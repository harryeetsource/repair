use eframe::egui;
use std::process::{Command as SystemCommandProcess, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::io::{BufRead, BufReader};
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
        task_index: usize, // Added a task index to identify which task is running.
        log: Arc<Mutex<String>>,
        running_task: Arc<Mutex<Option<usize>>>,
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
                ("cmd", vec!["/c", "ipconfig /release"]),
                ("cmd", vec!["/c", "ipconfig /renew"]),
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
            // Mark this task as running by storing its index.
            *running_task.lock().unwrap() = Some(task_index);
    
            for (program, args) in commands {
                let result = exec_command(program, &args, log.clone());
                let mut log_lock = log.lock().unwrap();
                match result {
                    Ok(output) => {
                        log_lock.push_str(&format!("Command '{}' executed successfully.\n", program));
                        log_lock.push_str(&format!("Output:\n{}\n", output));
                    }
                    Err(e) => {
                        log_lock.push_str(&format!("Command '{}' failed: {}\n", program, e));
                    }
                }
            }
    
            // Reset the running task flag to indicate that no task is active.
            *running_task.lock().unwrap() = None;
        })
    }
}



fn exec_command(
    program: &str,
    args: &[&str],
    log: Arc<Mutex<String>>,
) -> Result<String, String> {
    {
        let mut log_guard = log.lock().unwrap();
        log_guard.push_str(&format!(
            "Executing command: {} {}\n",
            program,
            args.join(" ")
        ));
    }

    let mut child = SystemCommandProcess::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start '{}': {}", program, e))?;

    // Take ownership of stdout and stderr.
    let stdout_pipe = child.stdout.take().expect("Failed to capture stdout");
    let stderr_pipe = child.stderr.take().expect("Failed to capture stderr");

    let stdout_reader = BufReader::new(stdout_pipe);
    let stderr_reader = BufReader::new(stderr_pipe);
    let mut output_collector = String::new();

    // Read stdout line-by-line.
    for line in stdout_reader.lines() {
        match line {
            Ok(line_content) => {
                {
                    let mut log_guard = log.lock().unwrap();
                    log_guard.push_str(&format!("stdout: {}\n", line_content));
                }
                output_collector.push_str(&line_content);
                output_collector.push('\n');
            }
            Err(e) => {
                let err = format!("Error reading stdout: {}", e);
                {
                    let mut log_guard = log.lock().unwrap();
                    log_guard.push_str(&err);
                }
                return Err(err);
            }
        }
    }

    // Read stderr line-by-line.
    let mut error_collector = String::new();
    for line in stderr_reader.lines() {
        match line {
            Ok(line_content) => {
                let error_msg = format!("stderr: {}\n", line_content);
                {
                    let mut log_guard = log.lock().unwrap();
                    log_guard.push_str(&error_msg);
                }
                error_collector.push_str(&line_content);
                error_collector.push('\n');
            }
            Err(e) => {
                let err = format!("Error reading stderr: {}", e);
                {
                    let mut log_guard = log.lock().unwrap();
                    log_guard.push_str(&err);
                }
                return Err(err);
            }
        }
    }

    // Ensure the child process has finished.
    let exit_status = child.wait().map_err(|e| format!("Failed to wait for command: {}", e))?;
    if !exit_status.success() {
        let code = exit_status.code().unwrap_or(-1);
        let err_msg = format!("Command '{}' failed with code {}: {}", program, code, error_collector);
        {
            let mut log_guard = log.lock().unwrap();
            log_guard.push_str(&err_msg);
        }
        return Err(err_msg);
    }

    Ok(output_collector)
}

pub struct SystemMaintenanceApp {
    tasks: Vec<Task>,
    log: Arc<Mutex<String>>,
    // Change the running flag to an Option that holds the index of the running task.
    running_task: Arc<Mutex<Option<usize>>>,
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
            // Initially, no task is running.
            running_task: Arc::new(Mutex::new(None)),
        }
    }
}

impl eframe::App for SystemMaintenanceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("System Maintenance");
            
            // Lock once to get the current running task (if any).
            let current_running = *self.running_task.lock().unwrap();
            
            // Enumerate tasks so we know the index.
            for (idx, task) in self.tasks.iter().enumerate() {
                // If the current running task matches this index, show a label.
                if current_running == Some(idx) {
                    ui.label(format!("Running: {}", task.task_description()));
                } else if ui.button(task.task_description()).clicked() {
                    // When starting a task, record its index.
                    *self.running_task.lock().unwrap() = Some(idx);
                    // Here you call the task execution and pass the shared log and running_task.
                    // You should ensure that inside execute_commands, once the task completes,
                    // the running_task is reset to None.
                    task.execute_commands(idx, self.log.clone(), self.running_task.clone());

                }
            }
            
            ui.separator();
            
            if current_running.is_some() {
                ui.label("A task is currently running...");
                // You might consider tracking progress specifically per task.
                ui.add(egui::ProgressBar::new(0.5).animate(true));
            }
            
            ui.separator();
            
            // Display the log.
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
