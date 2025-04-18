use eframe::egui;
use std::io::{BufRead, BufReader};
use std::process::{Command as SystemCommandProcess, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::env;
use std::fs;
use std::ffi::c_void;
use std::ptr::null_mut;
use windows::Win32::Foundation::NTSTATUS;
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
    HardwareBenchmark,
    PowerEfficiencyReport,
    TriggerBSOD,
}
#[derive(PartialEq)]
enum AppSection {
    Repairs,
    Reports,
    Configuration,
    Crash,
    Logs,
}


impl Task {
    pub fn task_description(&self) -> &str {
        match self {
            Task::DiskCleanup => "Repair: Perform Disk Cleanup",
            Task::PrefetchCleanup => "Repair: Clean Prefetch Files",
            Task::WindowsUpdateCleanup => "Repair: Clean Windows Update Cache",
            Task::TemporaryFilesCleanup => "Repair: Remove Temporary Files",
            Task::FontCacheCleanup => "Repair: Clean Font Cache",
            Task::DisableHibernation => "Configuration: Disable Hibernation",
            Task::FixComponents => "Repair: Fix Components",
            Task::UpdateDrivers => "Repair: Update Drivers",
            Task::EnableFullMemoryDumps => "Repair: Enable Full Memory Dumps",
            Task::HardenSystem => "Configuration: Harden System",
            Task::FlushDNSCache => "Repair: Flush DNS Cache",
            Task::ClearEventLogs => "Repair: Clear Event Logs",
            Task::ClearARP => "Repair: Clear ARP Cache",
            Task::ResetNetworkSettings => "Repair: Reset Network Settings",
            Task::SearchIndexingCleanup => "Repair: Rebuild Search Index",
            Task::BrowserCacheCleanup => "Repair: Clean Browser Cache",
            Task::CreateRestorePoint => "Repair: Create a System Restore Point",
            Task::RestartPrintSpooler => "Repair: Restart the Spooler service",
            Task::CheckWMIIntegrity => "Repair: Check WMI repository integrity",
            Task::SalvageWMI => "Repair: Salvage WMI repository",
            Task::HardwareBenchmark => "Report: Generate system benchmark report",
            Task::PowerEfficiencyReport => "Report: Generate power efficiency report",
            Task::TriggerBSOD => "Crash: Trigger Blue Screen of Death",
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
                (
                    "powershell",
                    vec!["-command", "Optimize-Volume -DriveLetter C -Defrag -ReTrim"],
                ),
            ],
            Task::PrefetchCleanup => vec![(
                "powershell",
                vec![
                    "-command",
                    "Remove-Item -Path 'C:\\Windows\\Prefetch\\*' -Recurse -Force",
                ],
            )],
            Task::WindowsUpdateCleanup => vec![
                ("cmd", vec!["/c", "net stop wuauserv"]),
                ("cmd", vec!["/c", "net stop bits"]),
                (
                    "cmd",
                    vec!["/c", "rd /s /q C:\\Windows\\SoftwareDistribution"],
                ),
                ("cmd", vec!["/c", "net start wuauserv"]),
                ("cmd", vec!["/c", "net start bits"]),
            ],
            Task::TemporaryFilesCleanup => vec![
                (
                    "powershell",
                    vec![
                        "-command",
                        "Remove-Item -Path 'C:\\Windows\\Temp\\*' -Recurse -Force -ErrorAction SilentlyContinue",
                    ],
                ),
                (
                    "powershell",
                    vec![
                        "-command",
                        "Remove-Item -Path 'C:\\Windows\\SystemTemp\\*' -Recurse -Force -ErrorAction SilentlyContinue",
                    ],
                ),
            ],
            Task::FontCacheCleanup => vec![
                (
                    "powershell",
                    vec!["-command", "Stop-Service -Name 'fontcache' -Force"],
                ),
                (
                    "powershell",
                    vec![
                        "-command",
                        "Remove-Item -Path 'C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*' -Recurse -Force -ErrorAction SilentlyContinue",
                    ],
                ),
                (
                    "powershell",
                    vec![
                        "-command",
                        "Remove-Item -Path 'C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache-System\\*' -Recurse -Force -ErrorAction SilentlyContinue",
                    ],
                ),
                (
                    "powershell",
                    vec!["-command", "Start-Service -Name 'fontcache'"],
                ),
            ],
            Task::DisableHibernation => vec![("powershell", vec!["-command", "powercfg -h off"])],

            Task::CreateRestorePoint => vec![(
                "powershell",
                vec![
                    "-command",
                    r#"Checkpoint-Computer -Description 'System Maintenance Restore Point' -RestorePointType 'MODIFY_SETTINGS'"#,
                ],
            )],
            Task::FixComponents => vec![
                (
                    "dism",
                    vec!["/online", "/cleanup-image", "/startcomponentcleanup"],
                ),
                (
                    "dism",
                    vec![
                        "/online",
                        "/cleanup-image",
                        "/startcomponentcleanup",
                        "/resetbase",
                    ],
                ),
                ("dism", vec!["/online", "/cleanup-image", "/spsuperseded"]),
                ("dism", vec!["/online", "/cleanup-image", "/restorehealth"]),
                ("sfc", vec!["/scannow"]),
            ],
            Task::UpdateDrivers => vec![(
                "powershell",
                vec![
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
                ],
            )],
            Task::RestartPrintSpooler => vec![(
                "powershell",
                vec!["-command", "Restart-Service -Name 'Spooler'"],
            )],
            Task::CheckWMIIntegrity => vec![("winmgmt", vec!["/verifyrepository"])],
            Task::SalvageWMI => vec![("winmgmt", vec!["/salvagerepository"])],
            Task::EnableFullMemoryDumps => vec![(
                "powershell",
                vec![
                    "-command",
                    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name 'CrashDumpEnabled' -Value 1",
                ],
            )],
            Task::HardenSystem => vec![(
                "netsh",
                vec!["advfirewall", "set", "allprofiles", "state", "on"],
            )],
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
                (
                    "powershell",
                    vec![
                        "-command",
                        "Remove-Item -Path 'C:\\ProgramData\\Microsoft\\Search\\Data' -Recurse -Force -ErrorAction SilentlyContinue",
                    ],
                ),
                ("powershell", vec!["-command", "Start-Service WSearch"]),
            ],
            Task::BrowserCacheCleanup => vec![
                (
                    "cmd",
                    vec![
                        "/c",
                        "for /d %i in (\"%localappdata%\\Google\\Chrome\\User Data\\Default\\Cache\\*\") do @rd /s /q \"%i\"",
                    ],
                ),
                (
                    "cmd",
                    vec![
                        "/c",
                        "for /d %i in (\"%localappdata%\\Microsoft\\Edge\\User Data\\Default\\Cache\\*\") do @rd /s /q \"%i\"",
                    ],
                ),
                (
                    "cmd",
                    vec![
                        "/c",
                        "for /d %i in (\"%localappdata%\\Mozilla\\Firefox\\Profiles\\*\\cache2\\*\") do @rd /s /q \"%i\"",
                    ],
                ),
            ],
            Task::HardwareBenchmark => vec![(
                "cmd",
                vec!["/c", "winsat formal > HardwareBenchmarkReport.txt"],
            )],
            Task::PowerEfficiencyReport => {
    // Instead of embedding a cd command, we let the exec_command set the working directory.
    vec![
        (
            "powercfg",
            vec!["/energy", "/output", "energy_report.html", "/duration", "60"],
        ),
    ]
}

Task::TriggerBSOD => {
    // Call the unsafe crash logic in a blocking thread
    let result = exec_command("Triggering BSOD via NtRaiseHardError", &[], log.clone());
    {
        let mut log_lock = log.lock().unwrap();
        log_lock.push_str("Executing BSOD trigger via NtRaiseHardError...\n");
        match result {
            Ok(_) => log_lock.push_str("Attempted BSOD execution.\n"),
            Err(e) => log_lock.push_str(&format!("BSOD trigger failed: {}\n", e)),
        }
    }

    // NOTE: The actual crash is handled outside the exec_command logic
    // to prevent process-level cleanup interfering with crash state
    unsafe {
        let bsod_thread = thread::spawn(move || {

            #[link(name = "ntdll")]
            unsafe extern "system" {
                unsafe fn NtRaiseHardError(
                    ErrorStatus: NTSTATUS,
                    NumberOfParameters: u32,
                    UnicodeStringParameterMask: u32,
                    Parameters: *mut c_void,
                    ValidResponseOption: u32,
                    Response: *mut u32,
                ) -> NTSTATUS;

                unsafe fn RtlAdjustPrivilege(
                    Privilege: u32,
                    Enable: bool,
                    CurrentThread: bool,
                    Enabled: *mut bool,
                ) -> NTSTATUS;
            }

            const SE_SHUTDOWN_PRIVILEGE: u32 = 19;
            const STATUS_ASSERTION_FAILURE: i32 = 0xC0000420u32 as i32;

            let mut enabled = false;
            let _ = RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, true, false, &mut enabled);
            let mut response: u32 = 0;

            let _ = NtRaiseHardError(
                NTSTATUS(STATUS_ASSERTION_FAILURE),
                0,
                0,
                null_mut(),
                6,
                &mut response,
            );
        });

        bsod_thread.join().ok();
    }

    vec![]
}



        };

        thread::spawn(move || {
            // Mark this task as running by storing its index.
            *running_task.lock().unwrap() = Some(task_index);

            for (program, args) in commands {
                let result = exec_command(program, &args, log.clone());
                let mut log_lock = log.lock().unwrap();
                match result {
                    Ok(output) => {
                        log_lock
                            .push_str(&format!("Command '{}' executed successfully.\n", program));
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

fn exec_command(program: &str, args: &[&str], log: Arc<Mutex<String>>) -> Result<String, String> {
    {
        let mut log_guard = log.lock().unwrap();
        log_guard.push_str(&format!(
            "Executing command: {} {}\n",
            program,
            args.join(" ")
        ));
    }
    let cwd = env::current_dir().expect("Failed to get current directory");
    let mut child = SystemCommandProcess::new(program)
        .args(args)
        .current_dir(cwd)
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
    let exit_status = child
        .wait()
        .map_err(|e| format!("Failed to wait for command: {}", e))?;
    if !exit_status.success() {
        let code = exit_status.code().unwrap_or(-1);
        let err_msg = format!(
            "Command '{}' failed with code {}: {}",
            program, code, error_collector
        );
        {
            let mut log_guard = log.lock().unwrap();
            log_guard.push_str(&err_msg);
        }
        return Err(err_msg);
    }

    Ok(output_collector)
}

struct SystemMaintenanceApp {
    tasks: Vec<Task>, // Your task collection
    log: Arc<Mutex<String>>,
    running_task: Arc<Mutex<Option<usize>>>,
    current_section: AppSection,
    pub show_bsod_confirm: bool,
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
                Task::HardwareBenchmark,
                Task::PowerEfficiencyReport,
                Task::TriggerBSOD,
            ],
            log: Arc::new(Mutex::new(String::new())),
            // Initially, no task is running.
            running_task: Arc::new(Mutex::new(None)),
            current_section: AppSection::Repairs,
            show_bsod_confirm: false,
        }
    }
}

impl eframe::App for SystemMaintenanceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Create a top panel with selectable tabs.
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.selectable_label(self.current_section == AppSection::Repairs, "Repairs").clicked() {
                    self.current_section = AppSection::Repairs;
                }
                if ui.selectable_label(self.current_section == AppSection::Reports, "Reports").clicked() {
                    self.current_section = AppSection::Reports;
                }
                if ui.selectable_label(self.current_section == AppSection::Configuration, "Configuration").clicked() {
                    self.current_section = AppSection::Configuration;
                }
                if ui.selectable_label(self.current_section == AppSection::Crash, "Crash").clicked() {
                    self.current_section = AppSection::Crash;
                }
                if ui.selectable_label(self.current_section == AppSection::Logs, "Logs").clicked() {
                    self.current_section = AppSection::Logs;
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("System Maintenance");

            // Lock once to get the current running task (if any).
            let current_running = *self.running_task.lock().unwrap();

            match self.current_section {
                AppSection::Repairs => {
                    // Filter tasks: those with a description starting with "Repair:"
                    for (idx, task) in self.tasks.iter().enumerate() {
                        let desc = task.task_description();
                        if desc.starts_with("Repair:") {
                            if current_running == Some(idx) {
                                ui.label(format!("Running: {}", desc));
                            } else if ui.button(desc).clicked() {
                                *self.running_task.lock().unwrap() = Some(idx);
                                task.execute_commands(idx, self.log.clone(), self.running_task.clone());
                            }
                        }
                    }
                }
                AppSection::Reports => {
                    // Filter tasks: those with descriptions starting with "Report:"
                    for (idx, task) in self.tasks.iter().enumerate() {
                        let desc = task.task_description();
                        if desc.starts_with("Report:") {
                            if current_running == Some(idx) {
                                ui.label(format!("Running: {}", desc));
                            } else if ui.button(desc).clicked() {
                                *self.running_task.lock().unwrap() = Some(idx);
                                task.execute_commands(idx, self.log.clone(), self.running_task.clone());
                            }
                        }
                    }
                }
                AppSection::Configuration => {
                    // Filter tasks: those with descriptions starting with "Configuration:"
                    for (idx, task) in self.tasks.iter().enumerate() {
                        let desc = task.task_description();
                        if desc.starts_with("Configuration:") {
                            if current_running == Some(idx) {
                                ui.label(format!("Running: {}", desc));
                            } else if ui.button(desc).clicked() {
                                *self.running_task.lock().unwrap() = Some(idx);
                                task.execute_commands(idx, self.log.clone(), self.running_task.clone());
                            }
                        }
                    }
                }
                AppSection::Crash => {
                    for (idx, task) in self.tasks.iter().enumerate() {
                        let desc = task.task_description();
                        if desc.starts_with("Crash:") {
                            if current_running == Some(idx) {
                                ui.label(format!("Running: {}", desc));
                            } else if ui.button(desc).clicked() {
                                // Show confirmation modal *instead* of executing immediately
                                self.show_bsod_confirm = true;
                            }
                        }
                    }
                
                    // Show confirmation window (centered popup)
                    if self.show_bsod_confirm {
                        egui::Window::new("⚠️ Confirm System Crash")
                            .collapsible(false)
                            .resizable(false)
                            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                            .show(ctx, |ui| {
                                ui.label("⚠️ This action will forcefully crash your system to generate a memory dump.");
                                ui.label("Do you want to continue?");
                
                                ui.horizontal(|ui| {
                                    if ui.button("Yes, Crash the System").clicked() {
                                        self.show_bsod_confirm = false;
                
                                        // Execute the BSOD task (doesn't need a real index)
                                        Task::TriggerBSOD.execute_commands(
                                            usize::MAX,
                                            self.log.clone(),
                                            self.running_task.clone(),
                                        );
                                    }
                
                                    if ui.button("Cancel").clicked() {
                                        self.show_bsod_confirm = false;
                                    }
                                });
                            });
                    }
                }
                
                AppSection::Logs => {
                    use chrono::Local;
                
                    ui.heading("Logs");
                
                    if ui.button("Save Logs to File").clicked() {
                        let logs = self.log.lock().unwrap().clone();
                
                        // Create a timestamped filename
                        let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
                        let filename = format!("logs_{}.txt", timestamp);
                
                        match fs::write(&filename, logs) {
                            Ok(_) => {
                                println!("Logs have been successfully saved to {}.", filename);
                                ui.label(format!("Logs saved successfully to '{}'", filename));
                            }
                            Err(e) => {
                                println!("Error saving logs: {}", e);
                                ui.label(format!("Error saving logs: {}", e));
                            }
                        }
                    }
                
                    ui.allocate_ui(egui::Vec2::new(600.0, 300.0), |ui| {
                        egui::ScrollArea::both().show(ui, |ui| {
                            ui.label(&*self.log.lock().unwrap());
                        });
                    });
                }
                
                
                
            }

            // If a task is running and we're not in the Logs tab, add a progress indicator.
            if self.current_section != AppSection::Logs && current_running.is_some() {
                ui.separator();
                ui.label("A task is currently running...");
                ui.add(egui::ProgressBar::new(0.5).animate(true));
            }

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
