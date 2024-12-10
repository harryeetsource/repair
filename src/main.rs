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

    pub fn execute(&self, log: &Arc<Mutex<String>>) -> Result<(), String> {
        match self {
            Task::DiskCleanup => {
                exec_command("cleanmgr", &["/sagerun:1"]).map_err(|e| {
                    let mut log = log.lock().unwrap();
                    log.push_str(&format!("Disk Cleanup failed: {}\n", e));
                    e
                })
            }
            Task::PrefetchCleanup => {
                exec_command(
                    "powershell",
                    &["-command", "Remove-Item -Path 'C:\\Windows\\Prefetch\\*' -Recurse -Force"],
                )
                .map_err(|e| {
                    let mut log = log.lock().unwrap();
                    log.push_str(&format!("Prefetch Cleanup failed: {}\n", e));
                    e
                })
            }
            Task::WindowsUpdateCleanup => {
                let commands: Vec<(&str, Vec<&str>)> = vec![
                    ("cmd", vec!["/c", "net stop wuauserv"]),
                    ("cmd", vec!["/c", "net stop bits"]),
                    ("cmd", vec!["/c", "rd /s /q C:\\Windows\\SoftwareDistribution"]),
                    ("cmd", vec!["/c", "net start wuauserv"]),
                    ("cmd", vec!["/c", "net start bits"]),
                ];
                execute_commands(&commands, log)
            }
            Task::TemporaryFilesCleanup => {
                exec_command(
                    "powershell",
                    &["-command", "Remove-Item -Path 'C:\\Windows\\Temp\\*' -Recurse -Force"],
                )
                .map_err(|e| {
                    let mut log = log.lock().unwrap();
                    log.push_str(&format!("Temporary Files Cleanup failed: {}\n", e));
                    e
                })
            }
            Task::FontCacheCleanup => {
                exec_command(
                    "powershell",
                    &["-command", "Stop-Service -Name 'fontcache'; Remove-Item -Path 'C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*' -Recurse -Force; Start-Service -Name 'fontcache'"],
                )
                .map_err(|e| {
                    let mut log = log.lock().unwrap();
                    log.push_str(&format!("Font Cache Cleanup failed: {}\n", e));
                    e
                })
            }
            Task::OptimizeSystem => {
                exec_command(
                    "powershell",
                    &["-command", "Optimize-Volume -DriveLetter C -Defrag -ReTrim"],
                )
                .map_err(|e| {
                    let mut log = log.lock().unwrap();
                    log.push_str(&format!("System Optimization failed: {}\n", e));
                    e
                })
            }
            Task::FixComponents => {
                let commands: Vec<(&str, Vec<&str>)> = vec![
                    ("dism", vec!["/online", "/cleanup-image", "/startcomponentcleanup"]),
                    ("dism", vec!["/online", "/cleanup-image", "/startcomponentcleanup", "/resetbase"]),
                    ("dism", vec!["/online", "/cleanup-image", "/spsuperseded"]),
                    ("dism", vec!["/online", "/cleanup-image", "/restorehealth"]),
                    ("sfc", vec!["/scannow"]),
                ];
                execute_commands(&commands, log)
            }
            Task::UpdateDrivers => {
                exec_command(
                    "powershell",
                    &[
                        "-command",
                        "Get-WmiObject Win32_PnPSignedDriver | foreach { $infPath = Get-ChildItem -Path C:\\Windows\\INF -Filter $_.InfName -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName; if ($infPath) { Invoke-Expression ('pnputil /add-driver ' + $infPath + ' /install') } }",
                    ],
                )
                .map_err(|e| {
                    let mut log = log.lock().unwrap();
                    log.push_str(&format!("Driver Update failed: {}\n", e));
                    e
                })
            }
            Task::EnableFullMemoryDumps => {
                exec_command(
                    "powershell",
                    &["-command", "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name 'CrashDumpEnabled' -Value 1"],
                )
                .map_err(|e| {
                    let mut log = log.lock().unwrap();
                    log.push_str(&format!("Enable Full Memory Dumps failed: {}\n", e));
                    e
                })
            }
            Task::HardenSystem => {
                exec_command(
                    "netsh",
                    &["advfirewall", "set", "allprofiles", "state", "on"],
                )
                .map_err(|e| {
                    let mut log = log.lock().unwrap();
                    log.push_str(&format!("System Hardening failed: {}\n", e));
                    e
                })
            }
        }
    }
}

fn execute_commands(commands: &[(&str, Vec<&str>)], log: &Arc<Mutex<String>>) -> Result<(), String> {
    for &(program, ref args) in commands {
        if let Err(e) = exec_command(program, args) {
            let mut log = log.lock().unwrap();
            log.push_str(&format!("Command `{}` with args {:?} failed: {}\n", program, args, e));
        }
    }
    Ok(())
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
        // Extract the error code
        let code = output.status.code().unwrap_or(-1); // Default to -1 if code is unavailable
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Command '{}' failed with error code {}: {}",
            program, code, stderr
        ));
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

            // Task buttons
            for task in &self.tasks {
                if ui.button(task.description()).clicked() {
                    let result = task.execute(&self.log);
                    let mut log = self.log.lock().unwrap();
                    match result {
                        Ok(_) => log.push_str(&format!("Task '{}' executed successfully.\n", task.description())),
                        Err(e) => log.push_str(&format!("Task '{}' failed: {}\n", task.description(), e)),
                    }
                }
            }

            ui.separator();

            // Input field
            ui.horizontal(|ui| {
                ui.label("Input:");
                ui.text_edit_singleline(&mut self.input);
            });

            ui.separator();

            // Scrollable area for logs
            ui.label("Logs:");
            egui::ScrollArea::vertical()
                .max_height(200.0) // Set max height for the scrollable area
                .show(ui, |ui| {
                    ui.label(&*self.log.lock().unwrap());
                });
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
