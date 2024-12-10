use eframe::egui;
use std::sync::{Arc, Mutex};
use std::process::{Command as SystemCommandProcess, Stdio};
use std::thread;

#[derive(Debug, Clone)]
pub enum Task {
    DiskCleanup,
    PrefetchCleanup,
    WindowsUpdateCleanup,
    TemporaryFilesCleanup,
    FontCacheCleanup,
    OptimizeSystem,
    FixComponents,
    UpdateDrivers,
    EnableFullMemoryDumps,
    HardenSystem,
}

impl Task {
    pub fn task_description(&self) -> &str {
        match self {
            Task::DiskCleanup => "Perform Disk Cleanup",
            Task::PrefetchCleanup => "Clean Prefetch Files",
            Task::WindowsUpdateCleanup => "Clean Windows Update Cache",
            Task::TemporaryFilesCleanup => "Remove Temporary Files",
            Task::FontCacheCleanup => "Clean Font Cache",
            Task::OptimizeSystem => "Optimize System",
            Task::FixComponents => "Fix Components",
            Task::UpdateDrivers => "Update Drivers",
            Task::EnableFullMemoryDumps => "Enable Full Memory Dumps",
            Task::HardenSystem => "Harden System",
        }
    }
    pub fn execute_commands(
        &self,
        log: Arc<Mutex<String>>,
        running_flag: Arc<Mutex<bool>>,
    ) -> thread::JoinHandle<()> {
        let commands = match self {
            Task::DiskCleanup => vec![("cleanmgr", vec!["/sagerun:1"])],
            Task::PrefetchCleanup => vec![(
                "powershell",
                vec!["-command", "Remove-Item -Path 'C:\\Windows\\Prefetch\\*' -Recurse -Force"],
            )],
            Task::WindowsUpdateCleanup => vec![
                ("cmd", vec!["/c", "net stop wuauserv"]),
                ("cmd", vec!["/c", "net stop bits"]),
                ("cmd", vec!["/c", "rd /s /q C:\\Windows\\SoftwareDistribution"]),
                ("cmd", vec!["/c", "net start wuauserv"]),
                ("cmd", vec!["/c", "net start bits"]),
            ],
            Task::TemporaryFilesCleanup => vec![(
                "powershell",
                vec!["-command", "Remove-Item -Path 'C:\\Windows\\Temp\\*' -Recurse -Force"],
            )],
            Task::FontCacheCleanup => vec![(
                "powershell",
                vec!["-command", "Stop-Service -Name 'fontcache'; Remove-Item -Path 'C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*' -Recurse -Force; Start-Service -Name 'fontcache'"],
            )],
            Task::OptimizeSystem => vec![(
                "powershell",
                vec!["-command", "Optimize-Volume -DriveLetter C -Defrag -ReTrim"],
            )],
            Task::FixComponents => vec![
                ("dism", vec!["/online", "/cleanup-image", "/startcomponentcleanup"]),
                ("dism", vec!["/online", "/cleanup-image", "/startcomponentcleanup", "/resetbase"]),
                ("dism", vec!["/online", "/cleanup-image", "/spsuperseded"]),
                ("dism", vec!["/online", "/cleanup-image", "/restorehealth"]),
                ("sfc", vec!["/scannow"]),
            ],
            Task::UpdateDrivers => vec![(
                "powershell",
                vec!["-command", "Get-WmiObject Win32_PnPSignedDriver | foreach { $infPath = Get-ChildItem -Path C:\\Windows\\INF -Filter $_.InfName -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName; if ($infPath) { Invoke-Expression ('pnputil /add-driver ' + $infPath + ' /install') } }"],
            )],
            Task::EnableFullMemoryDumps => vec![(
                "powershell",
                vec!["-command", "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name 'CrashDumpEnabled' -Value 1"],
            )],
            Task::HardenSystem => vec![("netsh", vec!["advfirewall", "set", "allprofiles", "state", "on"])],
        };

        thread::spawn(move || {
            *running_flag.lock().unwrap() = true;

            for (program, args) in commands {
                let result = exec_command(program, &args);
                let mut log = log.lock().unwrap();
                match result {
                    Ok(output) => {
                        log.push_str(&format!("Command '{}' executed successfully.\n", program));
                        log.push_str(&format!("Output:\n{}\n", output));
                    }
                    Err(e) => log.push_str(&format!("Command '{}' failed: {}\n", program, e)),
                }
            }

            *running_flag.lock().unwrap() = false;
        })
    }
}


fn exec_command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = SystemCommandProcess::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|child| child.wait_with_output())
        .map_err(|e| format!("Failed to start '{}': {}", program, e))?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Command '{}' failed with error code {}: {}",
            program, code, stderr
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout)
}


pub struct SystemMaintenanceApp {
    tasks: Vec<Task>,
    log: Arc<Mutex<String>>,
    running_task: Arc<Mutex<bool>>,
}

impl SystemMaintenanceApp {
    pub fn new() -> Self {
        Self {
            tasks: vec![
                Task::DiskCleanup,
                Task::PrefetchCleanup,
                Task::WindowsUpdateCleanup,
                Task::TemporaryFilesCleanup,
                Task::FontCacheCleanup,
                Task::OptimizeSystem,
                Task::FixComponents,
                Task::UpdateDrivers,
                Task::EnableFullMemoryDumps,
                Task::HardenSystem,
            ],
            log: Arc::new(Mutex::new(String::new())),
            running_task: Arc::new(Mutex::new(false)),
        }
    }
}

impl eframe::App for SystemMaintenanceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("System Maintenance");

            for task in &self.tasks {
                if *self.running_task.lock().unwrap() {
                    ui.label(format!("Running: {}", task.task_description()));
                } else if ui.button(task.task_description()).clicked() {
                    task.execute_commands(self.log.clone(), self.running_task.clone());
                }
            }

            ui.separator();

            if *self.running_task.lock().unwrap() {
                ui.label("Task is currently running...");
                ui.add(egui::ProgressBar::new(0.5).animate(true));
            }

            ui.separator();

            // Logs
            ui.label("Logs:");
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    ui.label(&*self.log.lock().unwrap());
                });

            ctx.request_repaint();
        });
    }
}


fn main() -> eframe::Result<()> {
    let app = SystemMaintenanceApp::new();
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "System Maintenance",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    )
}
