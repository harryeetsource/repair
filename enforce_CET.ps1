# Ensure script is running as Administrator
$adminCheck = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $adminCheck) {
    Write-Host "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

Write-Host "Ensuring Full Kernel-Mode and User-Mode CET Enforcement..."

# Enable Control Flow Guard (CFG)
Write-Host "Enabling Control Flow Guard (CFG)..."
Set-ProcessMitigation -System -Enable CFG

# Enable User-Mode CET Shadow Stack
Write-Host "Enabling User-Mode CET Shadow Stack..."
Set-ProcessMitigation -System -Enable UserShadowStack

Set-ProcessMitigation -System -Enable BottomUp
Set-ProcessMitigation -System -Enable ForceRelocateImages
Set-ProcessMitigation -System -Enable HighEntropy
Set-ProcessMitigation -System -Enable StrictHandle
#Set-ProcessMitigation -System -Enable BlockDynamicCode
Set-ProcessMitigation -System -Enable SEHOP
Set-ProcessMitigation -System -Enable BlockRemoteImageLoads
Set-ProcessMitigation -System -Enable BlockLowLabelImageLoads
Set-ProcessMitigation -System -Enable SuppressExports
#Set-ProcessMitigation -System -Enable DisableWin32kSystemCalls

# Configure Kernel-Mode CET (Registry Change)
Write-Host "Ensuring Kernel-Mode Hardware-Enforced Stack Protection is enforced..."
$kernelKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
if (-not (Test-Path $kernelKey)) {
    New-Item -Path $kernelKey -Force | Out-Null
}
Set-ItemProperty -Path $kernelKey -Name "KernelModeHardwareEnforcedStackProtection" -Type DWord -Value 1

# Apply Exploit Protection Policies
Write-Host "Applying Exploit Protection Settings..."
$exploitGuardKey = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exploit Guard\System Mitigations"
if (-not (Test-Path $exploitGuardKey)) {
    New-Item -Path $exploitGuardKey -Force | Out-Null
}
Set-ItemProperty -Path $exploitGuardKey -Name "ControlFlowGuard" -Type DWord -Value 1
Set-ItemProperty -Path $exploitGuardKey -Name "ShadowStacks" -Type DWord -Value 1
Set-ItemProperty -Path $exploitGuardKey -Name "UserShadowStack" -Type DWord -Value 1
Set-ItemProperty -Path $exploitGuardKey -Name "UserShadowStackStrictMode" -Type DWord -Value 1

# Verify applied settings
Write-Host "Verifying applied settings..."
Get-ProcessMitigation -System

# Restart system to apply changes
Write-Host "Configuration completed. Restarting system in 10 seconds..."
Start-Sleep -Seconds 10
Restart-Computer -Force
