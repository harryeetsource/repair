package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

var myApp fyne.App
var myWindow fyne.Window

type DriverPackage struct {
	PublishedName  string
	DriverName     string
	DriverVersion  string
	PackageRanking string
	OEMInformation string
}

func enumerateDriverPackages() ([]DriverPackage, error) {
	driverPackages := make([]DriverPackage, 0)

	cmd := exec.Command("pnputil", "-e")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate driver packages: %v", err)
	}

	re := regexp.MustCompile(`Published Name: (.+)\r\nDriver package provider: .+\r\nClass GUID: .+\r\nDriver Version: .+\r\nDriver Date: .+\r\n.*\r\nDriver Name: (.+)\r\n`)
	matches := re.FindAllStringSubmatch(string(output), -1)

	for _, match := range matches {
		driverPackage := DriverPackage{
			DriverName:    match[2],
			PublishedName: match[1],
		}
		driverPackages = append(driverPackages, driverPackage)
	}

	return driverPackages, nil
}
func execCommand(cmd string, args ...string) (string, error) {
	var out bytes.Buffer
	command := exec.Command(cmd, args...)
	command.Stdout = &out
	err := command.Run()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

func (d DriverPackage) String() string {
	return fmt.Sprintf("Published name: %s, Driver name: %s", d.PublishedName, d.DriverName)
}

func getDriverPackages() ([]DriverPackage, []string, error) {
	var driverPackages []DriverPackage
	var driverPackageIds []string

	// Get list of driver packages and IDs
	command := "pnputil /e"
	out, err := exec.Command("cmd", "/C", command).Output()
	if err != nil {
		return nil, nil, err
	}

	// Parse output and extract driver package information
	re := regexp.MustCompile(`Published name\s+= (.+)\r\nDriver package provider\s+= (.+)\r\nClass name\s+= (.+)\r\nDriver date and version\s+= (.+)\r\nDriver package ranking\s+= (.+)\r\nOEM information\s+= (.+)\r\n`)
	matches := re.FindAllStringSubmatch(string(out), -1)
	for _, match := range matches {
		driverPackage := DriverPackage{
			DriverName:     match[3],
			PublishedName:  match[1],
			DriverVersion:  match[4],
			PackageRanking: match[5],
			OEMInformation: match[6],
		}
		driverPackages = append(driverPackages, driverPackage)
		driverPackageIds = append(driverPackageIds, match[1])
	}

	return driverPackages, driverPackageIds, nil
}

func getWMICApps() ([]string, error) {
	wmicApps := []string{}
	output, err := execCommand("wmic", "product", "get", "IdentifyingNumber,Name")
	if err != nil {
		return nil, err
	}
	input := strings.NewReader(output)
	scanner := bufio.NewScanner(input)
	scanner.Scan() // Skip the header line

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			delimiter := strings.Index(line, "  ")
			if delimiter != -1 {
				appId := line[:delimiter]
				appName := strings.TrimSpace(line[delimiter+2:])
				wmicApps = append(wmicApps, appId+","+appName)
			}
		}
	}

	return wmicApps, nil
}

func getWindowsStoreApps() ([]string, error) {
	storeApps := []string{}
	output, err := execCommand("powershell", "-command", "Get-AppxPackage -AllUsers | Format-Table Name,PackageFullName -AutoSize")
	if err != nil {
		return nil, err
	}
	input := strings.NewReader(output)
	scanner := bufio.NewScanner(input)
	scanner.Scan() // Skip the header line

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			delimiter := strings.Index(line, "  ")
			if delimiter != -1 {
				appName := line[:delimiter]
				appFullName := strings.TrimSpace(line[delimiter+2:])
				storeApps = append(storeApps, appName+","+appFullName)
			}
		}
	}

	return storeApps, nil
}
func performSystemCleanup() {
	fmt.Println("Performing full cleanup and system file check.")
	execCommand("dism", "/online", "/cleanup-image", "/startcomponentcleanup")
	execCommand("dism", "/online", "/cleanup-image", "/restorehealth")
	execCommand("sfc", "/scannow")

	fmt.Println("Deleting Prefetch files.")
	systemRoot := os.ExpandEnv("%systemroot%")
	execCommand("cmd", "/c", "del /s /q /f", systemRoot+"\\Prefetch\\*")

	fmt.Println("Cleaning up Windows Update cache.")
	execCommand("net", "stop", "wuauserv")
	execCommand("net", "stop", "bits")
	execCommand("cmd", "/c", "rd /s /q", systemRoot+"\\SoftwareDistribution")
	execCommand("net", "start", "wuauserv")
	execCommand("net", "start", "bits")
	fmt.Println("Performing disk cleanup.")
	execCommand("cleanmgr", "/sagerun:1")
	fmt.Println("Removing temporary files.")
	temp := os.ExpandEnv("%temp%")
	execCommand("del", "/s /q", temp+"\\*")
	execCommand("del", "/s /q", systemRoot+"\\temp\\*")
	fmt.Println("Cleaning up font cache.")
	execCommand("net", "stop", "fontcache")
	execCommand("del", "/f /s /q /a", systemRoot+"\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*")
	execCommand("del", "/f /s /q /a", systemRoot+"\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache-System\\*")
	execCommand("net", "start", "fontcache")
	//disable insecure windows features
	fmt.Println("Disabling insecure windows features.")
	execCommand("dism", "/online", "/disable-feature", "/featurename:WindowsMediaPlayer")
	fmt.Println("Disabling Windows Media Player")
	execCommand("dism", "/online", "/disable-feature", "/featurename:WindowsMediaPlayer")

	fmt.Println("Disabling SMBV1")
	execCommand("dism", "/online", "/disable-feature", "/featurename:SMB1Protocol")

	fmt.Println("Disabling RDP")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f")

	fmt.Println("Disabling Remote Assistance")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", "/v", "fAllowToGetHelp", "/t", "REG_DWORD", "/d", "0", "/f")

	fmt.Println("Disable Autorun for all drives")
	execCommand("reg", "add", "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "/v", "NoDriveTypeAutoRun", "/t", "REG_DWORD", "/d", "255", "/f")

	fmt.Println("Disabling LLMNR")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "/v", "EnableMulticast", "/t", "REG_DWORD", "/d", "0", "/f")

	fmt.Println("Deleting oldest shadowcopy")
	execCommand("vssadmin", "delete", "shadows", "/for=C:", "/oldest")

	fmt.Println("Enable UAC")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "1", "/f")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "ConsentPromptBehaviorAdmin", "/t", "REG_DWORD", "/d", "2", "/f")

	fmt.Println("Deleting log files older than 7 days")
	execCommand("forfiles", "/p", "C:\\Windows\\Logs", "/s", "/m", "*.log", "/d", "-7", "/c", "cmd /c del @path")
	fmt.Println("Enabling Windows Defender Credential Guard")
	fmt.Println("Enabling Credential Guard.")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA", "/v", "LsaCfgFlags", "/t", "REG_DWORD", "/d", "1", "/f")
	execCommand("bcdedit", "/set", "{0cb3b571-2f2e-4343-a879-d86a476d7215}", "loadoptions", "DISABLE-LSA-ISO,DISABLE-VSM")
	execCommand("bcdedit", "/set", "{0cb3b571-2f2e-4343-a879-d86a476d7215}", "device", "path", "\\EFI\\Microsoft\\Boot\\SecConfig.efi")

	fmt.Println("Enabling Exploit Protection settings")
	execCommand("powershell", "-command", "Set-ProcessMitigation -System -Enable DEP,SEHOP")
	fmt.Println("Enabling Data Execution Prevention (DEP)")
	execCommand("bcdedit", "/set", "nx", "AlwaysOn")
	fmt.Println("Enabling Secure Boot")
	execCommand("bcdedit", "/set", "{default}", "bootmenupolicy", "Standard")
	fmt.Println("Enabling secure boot-step 2.")
	execCommand("powershell", "-command", "Confirm-SecureBootUEFI")

	fmt.Println("Disabling Microsoft Office macros.")
	execCommand("reg", "add", "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security", "/v", "VBAWarnings", "/t", "REG_DWORD", "/d", "4", "/f")
	execCommand("reg", "add", "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security", "/v", "VBAWarnings", "/t", "REG_DWORD", "/d", "4", "/f")
	execCommand("reg", "add", "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security", "/v", "VBAWarnings", "/t", "REG_DWORD", "/d", "4", "/f")
	fmt.Println("Enabling Address Space Layout Randomization.")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "/v", "MoveImages", "/t", "REG_DWORD", "/d", "1", "/f")
	fmt.Println("Enabling Windows Defender Real-Time protection VIA registry.")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "0", "/f")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "/v", "DisableBehaviorMonitoring", "/t", "REG_DWORD", "/d", "0", "/f")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "/v", "DisableOnAccessProtection", "/t", "REG_DWORD", "/d", "0", "/f")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "/v", "DisableScanOnRealtimeEnable", "/t", "REG_DWORD", "/d", "0", "/f")
	fmt.Println("Enabling DNS-over-HTTPS (DoH) in Windows 11.")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", "/v", "EnableAutoDoh", "/t", "REG_DWORD", "/d", "2", "/f")
	fmt.Println("Checking for and installing Windows updates.")
	execCommand("powershell", "-ExecutionPolicy", "Bypass", "-command", "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force")
	execCommand("powershell", "-ExecutionPolicy", "Bypass", "-command", "Install-Module -Name PowerShellGet -Scope CurrentUser -Force -AllowClobber")
	execCommand("powershell", "-ExecutionPolicy", "Bypass", "-command", "Register-PackageSource -Trusted -ProviderName 'PowerShellGet' -Name 'PSGallery' -Location 'https://www.powershellgallery.com/api/v2'")
	execCommand("powershell", "-ExecutionPolicy", "Bypass", "-command", "Install-Package -Name PSWindowsUpdate -ProviderName PowerShellGet -Force")
	execCommand("powershell", "-ExecutionPolicy", "Bypass", "-command", "Import-Module PowerShellGet; Import-Module PSWindowsUpdate; Install-Module PSWindowsUpdate -Force; Get-WindowsUpdate -Install")
	fmt.Println("Restricting access to the Local System Authority.")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "/v", "RestrictAnonymous", "/t", "REG_DWORD", "/d", "1", "/f")

	// Disable Windows Delivery Optimization
	fmt.Println("Disabling Windows Delivery Optimization")
	execCommand("reg", "add", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization", "/v", "DODownloadMode", "/t", "REG_DWORD", "/d", "0", "/f")
	fmt.Println("Enabling Memory Integrity")
	execCommand("reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\", "/v", "Enabled", "/t", "REG_DWORD", "/d", "1", "/f")
	fmt.Println("Emptying Recycling Bin")
	bin := os.ExpandEnv("%systemdrive")
	execCommand("rd", "/s /q", bin+"\\$Recycle.Bin")
	fmt.Println("Enabling Kernel Mode Hardware Enforced Stack Protection.")
	execCommand("bcdedit", "/set", "kstackguardpolicy", "enable")
	fmt.Println("Enabling Windows Defender and Security Center.")

	// Enabling Windows Defender Real-time protection
	execCommand("powershell.exe", "Set-MpPreference", "-DisableRealtimeMonitoring", "0")

	// Enabling Windows Security Center
	fmt.Println("Enabling Windows Security Center service")
	execCommand("sc", "config", "wscsvc", "start=", "auto")
	execCommand("sc", "start", "wscsvc")

	// Updating Windows Defender signatures
	fmt.Println("Updating Windows Defender signatures.")
	execCommand("powershell.exe", "Update-MpSignature")
}

func main() {
	fmt.Println("Booting up the Patriot...")
	os.Setenv("FYNE_RENDER", "software")
	myApp := app.New()
	myWindow := myApp.NewWindow("The Patriot")
	progressBar := widget.NewProgressBar()
	numCommands := 18
	progressBar.Max = float64(numCommands)

	storeApps, _ := getWindowsStoreApps()
	driverPackages, _, _ := getDriverPackages()
	wmicApps, _ := getWMICApps()

	// List of Windows Store Apps
	storeAppList := widget.NewList(
		func() int {
			return len(storeApps)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Template")
		},
		func(index widget.ListItemID, item fyne.CanvasObject) {
			item.(*widget.Label).SetText(storeApps[index])
		},
	)
	storeAppList.OnSelected = func(id widget.ListItemID) {
		appFullName := storeApps[id]
		command := "powershell -command \"Get-AppxPackage -AllUsers -Name " + appFullName + " | Remove-AppxPackage\""
		fmt.Println("Uninstalling Windows Store app: " + appFullName)
		exec.Command("cmd", "/C", command).Run()
		storeApps, _ = getWindowsStoreApps()
		storeAppList.Refresh()
	}

	// List of Driver Packages
	driverPackageList := widget.NewList(
		func() int {
			return len(driverPackages)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Template")
		},
		func(index widget.ListItemID, item fyne.CanvasObject) {
			item.(*widget.Label).SetText(driverPackages[index].DriverName + " (" + driverPackages[index].PublishedName + ")")
		},
	)

	driverPackageList.OnSelected = func(id widget.ListItemID) {
		driverPackageName := driverPackages[id].PublishedName
		command := "pnputil /d \"" + driverPackageName + "\""
		fmt.Println("Deleting driver package: " + driverPackageName)
		exec.Command("cmd", "/C", command).Run()
		driverPackages, _, _ = getDriverPackages()
		driverPackageList.Refresh()
	}

	// List of WMIC Apps
	wmicAppList := widget.NewList(
		func() int {
			return len(wmicApps)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Template")
		},
		func(index widget.ListItemID, item fyne.CanvasObject) {
			item.(*widget.Label).SetText(wmicApps[index])
		},
	)
	wmicAppList.OnSelected = func(id widget.ListItemID) {
		appId := wmicApps[id]
		command := "wmic product where \"IdentifyingNumber='" + appId + "'\" call uninstall /nointeractive"
		fmt.Println("Uninstalling WMIC app: " + appId)
		exec.Command("cmd", "/C", command).Run()
		wmicApps, _ = getWMICApps()
		wmicAppList.Refresh()
	}

	// System cleanup button
	cleanupButton := widget.NewButton("Perform System Cleanup", func() {
		fmt.Println("Performing system cleanup...")
		progressBar.SetValue(0)
		progressBar.Show()
		// Add your cleanup commands here
		performSystemCleanup()
		progressBar.Hide()
	})

	progressBar.Hide()

	cleanupTab := container.NewVBox(
		cleanupButton,
		widget.NewLabel("Click the button to perform system cleanup."),
		progressBar,
	)

	tabs := container.NewAppTabs(
		container.NewTabItem("Windows Store Apps", storeAppList),

		container.NewTabItem("Driver Packages", driverPackageList),
		container.NewTabItem("WMIC Apps", wmicAppList),
		container.NewTabItem("System Cleanup", cleanupTab),
	)
	myWindow.SetContent(tabs)
	myWindow.Resize(fyne.NewSize(500, 400))
	myWindow.ShowAndRun()
	myWindow.SetContent(
		tabs,
	)

	myWindow.Resize(fyne.NewSize(800, 600))
	myWindow.ShowAndRun()
}
