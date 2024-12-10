use eframe::egui;
use std::sync::{Arc, Mutex};
use std::process::{Command as SystemCommandProcess, Stdio};

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

    pub fn execute(&self) -> Result<(), String> {
        match self {
            Task::DiskCleanup => exec_command("cleanmgr", &["/sagerun:1"]),
            Task::PrefetchCleanup => exec_command(
                "powershell",
                &["-command", "Remove-Item -Path 'C:\\Windows\\Prefetch\\*' -Recurse -Force"],
            ),
            Task::WindowsUpdateCleanup => {
                let commands = &[
                    ("cmd", &["/c", "net stop wuauserv"] as &[&str]),
                    ("cmd", &["/c", "net stop bits"]),
                    ("cmd", &["/c", "rd /s /q C:\\Windows\\SoftwareDistribution"]),
                    ("cmd", &["/c", "net start wuauserv"]),
                    ("cmd", &["/c", "net start bits"]),
                ];
                execute_commands(commands)
            }
            Task::TemporaryFilesCleanup => exec_command(
                "powershell",
                &["-command", "Remove-Item -Path 'C:\\Temp\\*' -Recurse -Force"],
            ),
            Task::FontCacheCleanup => exec_command(
                "powershell",
                &["-command", "Stop-Service -Name 'fontcache'; Remove-Item -Path 'C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*' -Recurse -Force; Start-Service -Name 'fontcache'"],
            ),
            Task::OptimizeSystem => exec_command(
                "powershell",
                &["-command", "Optimize-Volume -DriveLetter C -Defrag -ReTrim"],
            ),
            Task::FixComponents => {
                let commands = &[
                    ("dism", &["/online", "/cleanup-image", "/startcomponentcleanup"] as &[&str]),
                    ("dism", &["/online", "/cleanup-image", "/startcomponentcleanup", "/resetbase"]),
                    ("dism", &["/online", "/cleanup-image", "/spsuperseded"]),
                    ("dism", &["/online", "/cleanup-image", "/restorehealth"]),
                    ("sfc", &["/scannow"]),
                ];
                execute_commands(commands)
            }
            Task::UpdateDrivers => exec_command(
                "powershell",
                &[ "-command",
                   "Get-WmiObject Win32_PnPSignedDriver | foreach { $infPath = Get-ChildItem -Path C:\\Windows\\INF -Filter $_.InfName -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName; if ($infPath) { Invoke-Expression ('pnputil /add-driver ' + $infPath + ' /install') } }",
                ],
            ),
            Task::EnableFullMemoryDumps => exec_command(
                "powershell",
                &["-command", "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name 'CrashDumpEnabled' -Value 1"],
            ),
            Task::HardenSystem => exec_command(
                "netsh",
                &["advfirewall", "set", "allprofiles", "state", "on"],
            ),
        }
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
        return Err(format!(
            "Command '{}' failed: {}",
            program,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

fn execute_commands(commands: &[(&str, &[&str])]) -> Result<(), String> {
    for &(program, args) in commands {
        exec_command(program, args)?;
    }
    Ok(())
}

struct SystemMaintenanceApp {
    tasks: Vec<Task>,
    log: Arc<Mutex<String>>,
    input: String,
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
            input: String::new(),
        }
    }
}

impl eframe::App for SystemMaintenanceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("System Maintenance");

            for task in &self.tasks {
                if ui.button(task.description()).clicked() {
                    let result = task.execute();
                    let mut log = self.log.lock().unwrap();
                    match result {
                        Ok(_) => log.push_str(&format!("Task '{}' executed successfully.\n", task.description())),
                        Err(e) => log.push_str(&format!("Task '{}' failed: {}\n", task.description(), e)),
                    }
                }
            }

            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Input:");
                ui.text_edit_singleline(&mut self.input);
            });

            ui.separator();

            ui.label("Logs:");
            ui.label(&*self.log.lock().unwrap());
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
