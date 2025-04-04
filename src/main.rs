use eframe::egui;
use std::process::{Command as SystemCommandProcess, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone)]
pub enum Task {
    DiskCleanup,
    PrefetchCleanup,
    WindowsUpdateCleanup,
    TemporaryFilesCleanup,
    FontCacheCleanup,
    DisableHibernation,
    FixComponents,
    UpdateDrivers,
    EnableFullMemoryDumps,
    HardenSystem,
    FlushDNSCache,
    ClearEventLogs,
    ClearARP,
    ResetNetworkSettings,
    SearchIndexingCleanup,
    BrowserCacheCleanup,
    CreateRestorePoint,
    RestartPrintSpooler,
    CheckWMIIntegrity,
    SalvageWMI,
}

impl Task {
    pub fn task_description(&self) -> &str {
        match self {
            Task::DiskCleanup => "Perform Disk Cleanup",
            Task::PrefetchCleanup => "Clean Prefetch Files",
            Task::WindowsUpdateCleanup => "Clean Windows Update Cache",
            Task::TemporaryFilesCleanup => "Remove Temporary Files",
            Task::FontCacheCleanup => "Clean Font Cache",
            Task::DisableHibernation => "Disable Hibernation",
            Task::FixComponents => "Fix Components",
            Task::UpdateDrivers => "Update Drivers",
            Task::EnableFullMemoryDumps => "Enable Full Memory Dumps",
            Task::HardenSystem => "Harden System",
            Task::FlushDNSCache => "Flush DNS Cache",
            Task::ClearEventLogs => "Clear Event Logs",
            Task::ClearARP => "Clear ARP Cache",
            Task::ResetNetworkSettings => "Reset Network Settings",
            Task::SearchIndexingCleanup => "Rebuild Search Index",
            Task::BrowserCacheCleanup => "Clean Browser Cache",
            Task::CreateRestorePoint => "Create a System Restore Point",
            Task::RestartPrintSpooler => "Restart the Spooler service",
            Task::CheckWMIIntegrity => "Check WMI repository integrity",
            Task::SalvageWMI => "Salvage WMI repository",
        }
    }

    pub fn execute_commands(
        &self,
        log: Arc<Mutex<String>>,
        running_flag: Arc<Mutex<bool>>,
    ) -> thread::JoinHandle<()> {
        let commands = match self {
            Task::DiskCleanup => vec![
                ("cleanmgr", vec!["/sagerun:1"]),
                ("powershell", vec![
                    "-command",
                    "Optimize-Volume -DriveLetter C -Defrag -ReTrim",
                ]),
            ],
            Task::PrefetchCleanup => vec![("powershell", vec![
                "-command",
                "Remove-Item -Path 'C:\\Windows\\Prefetch\\*' -Recurse -Force",
            ])],
            Task::WindowsUpdateCleanup => vec![
                ("cmd", vec!["/c", "net stop wuauserv"]),
                ("cmd", vec!["/c", "net stop bits"]),
                ("cmd", vec![
                    "/c",
                    "rd /s /q C:\\Windows\\SoftwareDistribution",
                ]),
                ("cmd", vec!["/c", "net start wuauserv"]),
                ("cmd", vec!["/c", "net start bits"]),
            ],
            Task::TemporaryFilesCleanup => vec![
                ("powershell", vec![
                    "-command",
                    "Remove-Item -Path 'C:\\Windows\\Temp\\*' -Recurse -Force -ErrorAction SilentlyContinue",
                ]),
                ("powershell", vec![
                    "-command",
                    "Remove-Item -Path 'C:\\Windows\\SystemTemp\\*' -Recurse -Force -ErrorAction SilentlyContinue",
                ]),
            ],
            Task::FontCacheCleanup => vec![
                ("powershell", vec![
                    "-command",
                    "Stop-Service -Name 'fontcache' -Force",
                ]),
                ("powershell", vec![
                    "-command",
                    "Remove-Item -Path 'C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*' -Recurse -Force -ErrorAction SilentlyContinue",
                ]),
                ("powershell", vec![
                    "-command",
                    "Remove-Item -Path 'C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache-System\\*' -Recurse -Force -ErrorAction SilentlyContinue",
                ]),
                ("powershell", vec![
                    "-command",
                    "Start-Service -Name 'fontcache'",
                ]),
            ],
            Task::DisableHibernation => vec![("powershell", vec!["-command", "powercfg -h off"])],

            Task::CreateRestorePoint => vec![("powershell", vec![
                "-command",
                r#"Checkpoint-Computer -Description 'System Maintenance Restore Point' -RestorePointType 'MODIFY_SETTINGS'"#,
            ])],
            Task::FixComponents => vec![
                ("dism", vec![
                    "/online",
                    "/cleanup-image",
                    "/startcomponentcleanup",
                ]),
                ("dism", vec![
                    "/online",
                    "/cleanup-image",
                    "/startcomponentcleanup",
                    "/resetbase",
                ]),
                ("dism", vec!["/online", "/cleanup-image", "/spsuperseded"]),
                ("dism", vec!["/online", "/cleanup-image", "/restorehealth"]),
                ("sfc", vec!["/scannow"]),
            ],
            Task::UpdateDrivers => vec![("powershell", vec![
                "-command",
                r#"
            # Build a cache of INF files to avoid repetitive recursive searches.
            $infCache = @{}
            Get-ChildItem -Path C:\Windows\INF -Filter *.inf -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $infCache[$_.Name] = $_.FullName
            }

            # Use Get-CimInstance to enumerate signed drivers.
            Get-CimInstance Win32_PnPSignedDriver | ForEach-Object {
                if ($_.InfName) {
                    $infName = $_.InfName
                    if ($infCache.ContainsKey($infName)) {
                        $infPath = $infCache[$infName]
                        Write-Output "Updating driver for device: $($_.DeviceName) using INF: $infPath"
                        try {
                            $pnputilResult = pnputil /add-driver $infPath /install /subdirs
                            Write-Output "Result for $($_.DeviceName): $pnputilResult"
                        }
                        catch {
                            Write-Output "Error updating driver for device: $($_.DeviceName): $_"
                        }
                    }
                    else {
                        Write-Output "INF file '$infName' not found in C:\Windows\INF for device: $($_.DeviceName)"
                    }
                }
                else {
                    Write-Output "No INF file specified for device: $($_.DeviceName)"
                }
            }
        "#,
            ])],
            Task::RestartPrintSpooler => vec![("powershell", vec![
                "-command",
                "Restart-Service -Name 'Spooler'",
            ])],
            Task::CheckWMIIntegrity => vec![("winmgmt", vec!["/verifyrepository"])],
            Task::SalvageWMI => vec![("winmgmt", vec!["/salvagerepository"])],
            Task::EnableFullMemoryDumps => vec![("powershell", vec![
                "-command",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name 'CrashDumpEnabled' -Value 1",
            ])],
            Task::HardenSystem => vec![("netsh", vec![
                "advfirewall",
                "set",
                "allprofiles",
                "state",
                "on",
            ])],
            Task::FlushDNSCache => vec![("cmd", vec!["/c", "ipconfig /flushdns"])],
            Task::ClearEventLogs => vec![
                ("wevtutil", vec!["cl", "Application"]),
                ("wevtutil", vec!["cl", "Security"]),
                ("wevtutil", vec!["cl", "System"]),
            ],
            Task::ClearARP => vec![("cmd", vec!["/c", "arp -d *"])],
            Task::ResetNetworkSettings => vec![
                ("cmd", vec!["/c", "netsh int ip reset"]),
                ("cmd", vec!["/c", "netsh winsock reset"]),
            ],
            Task::SearchIndexingCleanup => vec![
                ("powershell", vec!["-command", "Stop-Service WSearch"]),
                ("powershell", vec![
                    "-command",
                    "Remove-Item -Path 'C:\\ProgramData\\Microsoft\\Search\\Data' -Recurse -Force -ErrorAction SilentlyContinue",
                ]),
                ("powershell", vec!["-command", "Start-Service WSearch"]),
            ],
            Task::BrowserCacheCleanup => vec![
                ("cmd", vec![
                    "/c",
                    "for /d %i in (\"%localappdata%\\Google\\Chrome\\User Data\\Default\\Cache\\*\") do @rd /s /q \"%i\"",
                ]),
                ("cmd", vec![
                    "/c",
                    "for /d %i in (\"%localappdata%\\Microsoft\\Edge\\User Data\\Default\\Cache\\*\") do @rd /s /q \"%i\"",
                ]),
                ("cmd", vec![
                    "/c",
                    "for /d %i in (\"%localappdata%\\Mozilla\\Firefox\\Profiles\\*\\cache2\\*\") do @rd /s /q \"%i\"",
                ]),
            ],
        };

        thread::spawn(move || {
            *running_flag.lock().unwrap() = true;

            for (program, args) in commands {
                let result = exec_command(program, &args, log.clone());
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

fn exec_command(program: &str, args: &[&str], log: Arc<Mutex<String>>) -> Result<String, String> {
    // Log the command being executed in the scrollable log
    {
        let mut log_guard = log.lock().unwrap();
        log_guard.push_str(&format!(
            "Executing command: {} {}\n",
            program,
            args.join(" ")
        ));
    }

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
                Task::DisableHibernation,
                Task::FixComponents,
                Task::UpdateDrivers,
                Task::EnableFullMemoryDumps,
                Task::HardenSystem,
                Task::FlushDNSCache,
                Task::ClearEventLogs,
                Task::ClearARP,
                Task::ResetNetworkSettings,
                Task::SearchIndexingCleanup,
                Task::BrowserCacheCleanup,
                Task::RestartPrintSpooler,
                Task::CheckWMIIntegrity,
                Task::SalvageWMI,
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
