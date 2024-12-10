use eframe::egui;
use std::sync::{Arc, Mutex};
use std::process::{Command as SystemCommandProcess, Stdio};
use tokio::runtime::Runtime;

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
    pub fn description(&self) -> &str {
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
        runtime: &Runtime,
    ) -> tokio::task::JoinHandle<()> {
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

        runtime.spawn(async move {
            for (program, args) in commands {
                let result = tokio::task::spawn_blocking(move || exec_command(program, &args)).await;

                let mut log = log.lock().unwrap();
                match result {
                    Ok(Ok(())) => log.push_str(&format!("Command '{}' executed successfully.\n", program)),
                    Ok(Err(e)) => log.push_str(&format!("Command '{}' failed: {}\n", program, e)),
                    Err(e) => log.push_str(&format!("Failed to execute '{}': {:?}\n", program, e)),
                }
            }
        })
    }
}

fn exec_command(program: &str, args: &[&str]) -> Result<(), String> {
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
    Ok(())
}

pub struct SystemMaintenanceApp {
    tasks: Vec<Task>,
    log: Arc<Mutex<String>>,
    runtime: Runtime,
}

impl SystemMaintenanceApp {
    pub fn new() -> Self {
        let runtime = Runtime::new().expect("Failed to create tokio runtime");
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
            runtime,
        }
    }
}

impl eframe::App for SystemMaintenanceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("System Maintenance");

            for task in &self.tasks {
                if ui.button(task.description()).clicked() {
                    task.execute_commands(self.log.clone(), &self.runtime);
                }
            }

            ui.separator();
            ui.label("Logs:");
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    ui.label(&*self.log.lock().unwrap());
                });

            ctx.request_repaint(); // Continuously repaint for updates
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
