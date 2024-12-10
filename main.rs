use iced::{
    widget::{Button, Column, Row, Text, TextInput},
    Application, Element, Length, Settings, Font, application,
};
use log::{error, info};
use std::sync::{Arc, Mutex};
use std::process::{Command as SystemCommandProcess, Stdio};
use iced::Pixels;

#[derive(Debug, Clone)]
pub enum Message {
    ExecuteTask(Task),
    InputChanged(String),
}

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
                &[
                    "-command",
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

#[derive(Default)]
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

    pub fn update(&mut self, message: Message) {
        match message {
            Message::ExecuteTask(task) => {
                let mut log = self.log.lock().unwrap();
                log.push_str(&format!("Task '{}' executed.\n", task.description()));
            }
            Message::InputChanged(value) => {
                self.input = value;
            }
        }
    }

    pub fn view(&self) -> Element<Message> {
        let task_buttons = self
            .tasks
            .iter()
            .map(|task| {
                Button::new(Text::new(task.description()))
                    .on_press(Message::ExecuteTask(task.clone()))
                    .into()
            })
            .collect::<Column<_>>();

        let log_content = self.log.lock().unwrap().clone();

        Column::new()
            .push(Text::new("System Maintenance"))
            .push(task_buttons)
            .push(
                TextInput::new("Enter additional input...", &self.input)
                    .on_input(Message::InputChanged)
                    .padding(5),
            )
            .push(Text::new(log_content).width(Length::Fill))
            .into()
    }

    pub fn run() -> iced::Result {
        iced::Application::run_with(
            || {
                (
                    SystemMaintenanceApp::new(), // Initialize the application state
                    iced::Task::none(),          // No initial commands
                )
            },
            || {
                // Return application settings as a tuple to match the expected type
                (
                    (),                          // Placeholder state, as settings aren't part of `State`
                    iced::Task::none(),          // No commands at this stage
                )
            },
        )
    }
    
    
}

fn main() -> iced::Result {
    SystemMaintenanceApp::run()
}


