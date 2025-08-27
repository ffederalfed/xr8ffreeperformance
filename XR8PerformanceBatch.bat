:: ===================================================================
::  XR8 Performance Batch
::  License: MIT (see LICENSE). Functional behavior unchanged; visuals refreshed.
::  Discord: discord.gg/XR8
:: ===================================================================
@echo off

:: Version #
set "SCRIPT_VERSION=2.0"

:: Enable Delayed Expansion
setlocal enabledelayedexpansion

:: Log file location
set "LOG_FILE=XR8Perf.log"
echo XR8's Performance Batch Log > "%LOG_FILE%"

:: Enable ANSI Escape Sequences
reg add "HKCU\CONSOLE" /v "VirtualTerminalLevel" /t REG_DWORD /d "1" /f >> "%LOG_FILE%"

call :HandleRestorePoint
cls

:: Disable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >> %LOG_FILE%

:: Getting Admin Permissions https://stackoverflow.com/questions/1894967/how-to-request-administrator-access-inside-a-batch-file
echo Checking for Administrative Privelages...
timeout /t 3 /nobreak > NUL
IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

if '%errorlevel%' NEQ '0' (
    goto UACPrompt
) else ( goto GotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:GotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

:: Main Menu
:Menu
chcp 65001 >nul 2>&1
cls
call :SetColors
echo.
echo.
echo.
echo.
echo                %w%██╗░░██╗██████╗░░█████╗░  ████████╗░██╗░░░░░░░██╗███████╗░█████╗░██╗░░██╗███████╗██████╗░%t%
echo                %w%╚██╗██╔╝██╔══██╗██╔══██╗  ╚══██╔══╝░██║░░██╗░░██║██╔════╝██╔══██╗██║░██╔╝██╔════╝██╔══██╗%t%
echo                %w%░╚███╔╝░██████╔╝╚█████╔╝  ░░░██║░░░░╚██╗████╗██╔╝█████╗░░███████║█████═╝░█████╗░░██████╔╝%t%
echo                %w%░██╔██╗░██╔══██╗██╔══██╗  ░░░██║░░░░░████╔═████║░██╔══╝░░██╔══██║██╔═██╗░██╔══╝░░██╔══██╗%t%
echo                %w%██╔╝╚██╗██║░░██║╚█████╔╝  ░░░██║░░░░░╚██╔╝░╚██╔╝░███████╗██║░░██║██║░╚██╗███████╗██║░░██║%t%
echo                %w%╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░  ░░░╚═╝░░░░░░╚═╝░░░╚═╝░░╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝%t%
echo.
echo                                             %w%Created By: XR8%t%
echo                                                  %w%Version: %SCRIPT_VERSION%%t%
echo  %w%══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%t%


echo.
echo.
echo.
echo                           %c%[1]%t% %w%Performance Optimizations%t%                 %c%[2]%t% %w%KBM Optimizations%t%
echo. 
echo.
echo                           %c%[3]%t% %w%Disable Telemetry%t%                         %c%[4]%t% %w%Network%t%
echo.
echo.
echo                           %c%[5]%t% %w%Debloat Windows%t%                           %c%[6]%t% %w%Other%t%

set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto PerformanceOptimizations
if '%choice%'=='2' goto KBMOptimizations
if '%choice%'=='3' goto DisableTelemetry
if '%choice%'=='4' goto Network
if '%choice%'=='5' goto DebloatWindows
if '%choice%'=='6' goto Other

:PerformanceOptimizations
cls

:: Disable Mitigations
echo Disabling Mitigations
powershell "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}" >> %LOG_FILE%

powershell "Remove-Item -Path \"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\" -Recurse -ErrorAction SilentlyContinue" >> %LOG_FILE%

reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: BCD Tweaks
echo Applying BCD Tweaks
bcdedit /set useplatformclock No >> %LOG_FILE%
bcdedit /set useplatformtick No >> %LOG_FILE%
bcdedit /set disabledynamictick Yes >> %LOG_FILE%
bcdedit /set forcelegacyplatform No >> %LOG_FILE%
bcdedit /set tscsyncpolicy Enhanced >> %LOG_FILE%
bcdedit /set avoidlowmemory 0x8000000 >> %LOG_FILE%
bcdedit /set firstmegabytepolicy UseAll >> %LOG_FILE%
bcdedit /set nolowmem Yes >> %LOG_FILE%
bcdedit /set isolatedcontext No >> %LOG_FILE%
bcdedit /set x2apicpolicy Enable >> %LOG_FILE%
bcdedit /set usephysicaldestination No >> %LOG_FILE%
bcdedit /set linearaddress57 OptOut >> %LOG_FILE%
bcdedit /set noumex Yes >> %LOG_FILE%
bcdedit /set perfmem 0 >> %LOG_FILE%
bcdedit /set clustermodeaddressing 1 >> %LOG_FILE%
bcdedit /set configflags 0 >> %LOG_FILE%
bcdedit /set uselegacyapicmode No >> %LOG_FILE%
bcdedit /set disableelamdrivers Yes >> %LOG_FILE%
bcdedit /set vsmlaunchtype Off >> %LOG_FILE%
bcdedit /set ems No >> %LOG_FILE%
bcdedit /set extendedinput Yes >> %LOG_FILE%
bcdedit /set highestmode Yes >> %LOG_FILE%
bcdedit /set forcefipscrypto No >> %LOG_FILE%
bcdedit /set sos Yes >> %LOG_FILE%
bcdedit /set pae ForceEnable >> %LOG_FILE%
bcdedit /set debug No >> %LOG_FILE%
bcdedit /set hypervisorlaunchtype Off >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: NTFS Tweaks
echo Applying NTFS Tweaks
fsutil behavior set memoryusage 2 >> %LOG_FILE%
fsutil behavior set mftzone 4 >> %LOG_FILE%
fsutil behavior set disablelastaccess 1 >> %LOG_FILE%
fsutil behavior set disabledeletenotify 0 >> %LOG_FILE%
fsutil behavior set encryptpagingfile 0 >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Memory Compression
echo Disabling Memory Compression
PowerShell -Command "Disable-MMAgent -MemoryCompression" >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Page Combining
echo Disabling Page Combining
PowerShell -Command "Disable-MMAgent -PageCombining" >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Delete Microcode
echo Deleting Microcode
takeown /f "C:\Windows\System32\mcupdate_GenuineIntel.dll" /r /d y >> %LOG_FILE%
takeown /f "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /r /d y >> %LOG_FILE%
del "C:\Windows\System32\mcupdate_GenuineIntel.dll" /s /f /q >> %LOG_FILE%
del "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /s /f /q >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Win32Priority
echo Setting Win32Priority
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Large System Cache
echo Enabling Large System Cache
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Fast Startup
echo Disabling Fast Startup
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Hibernation
echo Disabling Hibernation
powercfg /h off
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Sleep Study
echo Disabling Sleep Study
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Preemption
echo Disabling Preemption
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "GPUPreemptionLevel" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableAsyncMidBufferPreemption" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidGfxPreemptionVGPU" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidBufferPreemptionForHighTdrTimeout" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableSCGMidBufferPreemption" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PerfAnalyzeMidBufferPreemption" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidGfxPreemption" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidBufferPreemption" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableCEPreemption" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisableCudaContextPreemption" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisablePreemptionOnS3S4" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "ComputePreemptionLevel" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisablePreemption" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable DEP
echo Disabling DEP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Automatic Maintenance
echo Disabling Automatic Maintenance
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Paging Executive
echo Disabling Paging Executive
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable FTH
echo Disabling Fault Tolerant Heap
reg add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable ASLR
echo Disabling Address Space Layout Randomization
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Power Throttling
echo Disabling Power Throttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PlatformAoAcOverride" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Enable HAGS
echo Enabling Hardware-Accelerated Gpu Scheduling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchedMode" /t REG_DWORD /d "2" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Enable Distribute Timers
echo Enabling Distribution of Timers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Enable GameMode
echo Enabling GameMode
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Gamebar
echo Disabling Gamebar
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: MenuShowDelay
echo Reducing Menu Delay
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable GpuEnergyDrv
echo Disabling GPU Energy Driver
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Energy Logging
echo Disabling Energy Logging
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Windows Insider Experiments
echo Disabling Windows Insider Experiments
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Game Priorities
echo Setting Game Priorities
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Timestamp
echo Setting Time Stamp
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "IoPriority" /t REG_DWORD /d "3" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: CSRSS
echo Setting CSRSS to Realtime
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: System Responsiveness
echo Setting System Responsiveness
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Microsoft Setting Synchronization
echo Disabling Setting Synchronization
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Windows Error Reporting
echo Disabling Windows Error Reporting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DoReport" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: IO Prioritization & Boost
echo Setting IO Priorities
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PassiveIntRealTimeWorkerPriority" /t REG_DWORD /d "18" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\KernelVelocity" /v "DisableFGBoostDecay" /t REG_DWORD /d "1" /f >> %LOG_FILE%

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Windows Defender
echo Disabling Windows Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericReports" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats" /v "Threats_ThreatSeverityDefaultAction" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "1" /t REG_SZ /d "6" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "2" /t REG_SZ /d "6" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "4" /t REG_SZ /d "6" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "5" /t REG_SZ /d "6" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEngCP.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Enable FSE
echo Enabling Full Screen Exclusive
reg delete "HKCU\SYSTEM\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /f >> %LOG_FILE%
reg delete "HKCU\SYSTEM\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /f >> %LOG_FILE%
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f >> %LOG_FILE%
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f >> %LOG_FILE%
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f >> %LOG_FILE%
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Latency Tolerance (Melody the Neko#9870)
echo Setting Latency Tolerance
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Resource Policy Tweaks
echo Setting Resource Policy Store Values
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "CapPercentage" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "SchedulingType" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "CapPercentage" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "SchedulingType" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "CapPercentage" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "SchedulingType" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "CapPercentage" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "SchedulingType" /t REG_DWORD /d "0" /f >> %LOG_FILE%

reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenPPLE" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Paused" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PausedDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Pausing" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\ThrottleGPUInterference" /v "IsLowPriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%

reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "82" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "82" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "BasePriority" /t REG_DWORD /d "82" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "BasePriority" /t REG_DWORD /d "82" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "BasePriority" /t REG_DWORD /d "82" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "BasePriority" /t REG_DWORD /d "82" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "BasePriority" /t REG_DWORD /d "82" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "BasePriority" /t REG_DWORD /d "82" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "BasePriority" /t REG_DWORD /d "82" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "BasePriority" /t REG_DWORD /d "82" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "BasePriority" /t REG_DWORD /d "82" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "OverTargetPriority" /t REG_DWORD /d "50" /f >> %LOG_FILE%

reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL


echo.
echo What GPU Do you Have?  NVIDIA = 1  AMD = 2  IGPU = 3 
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto NVIDIA
if '%choice%'=='2' goto AMD
if '%choice%'=='3' goto IGPU

:NVIDIA

:: NVIDIA Inspector Profile
echo Applying NVIDIA Inspector Profile
curl -g -k -L -# -o "%temp%\nvidiaProfileInspector.zip" "https://github.com/xr8/perf-suite >> %LOG_FILE%
powershell -NoProfile Expand-Archive '%temp%\nvidiaProfileInspector.zip' -DestinationPath 'C:\NvidiaProfileInspector\' >> %LOG_FILE%
curl -g -k -L -# -o "C:\NvidiaProfileInspector\ancel_nv_profile.nip" "https://cdn.discordapp.com/attachments/1003668036345143376/1067887367865778208/ancel_nv_profile.nip" >> %LOG_FILE%
start "" /wait "C:\NvidiaProfileInspector\nvidiaProfileInspector.exe" "C:\NvidiaProfileInspector\ancel_nv_profile.nip" >> %LOG_FILE%
timeout /t 3 /nobreak > NUL

:: Enable MSI Mode for GPU
echo Enabling MSI Mode
for /f %%g in ('wmic path win32_videocontroller get PNPDeviceID ^| findstr /L "VEN_"') do (
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
)
timeout /t 1 /nobreak > NUL

:: NVIDIA Latency Tolerance
echo Setting NVIDIA Latency Tolerance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /t REG_DWORD /d "20" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Force Contigous Memory Allocation
echo Forcing Contigous Memory Allocation
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable HDCP
echo Disabling High-bandwidth Digital Content Protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMHdcpKeyGlobZero" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable TCC
echo Disabling TCC
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TCCSupported" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Tiled Display
echo Disabling Tiled Display
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableTiledDisplay" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable NVIDIA Telemetry
echo Disabling NVIDIA Telemetry
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d "0" /f >> %LOG_FILE%
schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> %LOG_FILE%
schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> %LOG_FILE%
schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> %LOG_FILE%
schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> %LOG_FILE%
schtasks /change /disable /tn "NvDriverUpdateCheckDaily_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> %LOG_FILE%
schtasks /change /disable /tn "NVIDIA GeForce Experience SelfUpdate_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> %LOG_FILE%
schtasks /change /disable /tn "NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable NVIDIA Display Power Saving
echo Disabling NVIDIA Display Power Saving
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Write Combining
echo Disabling Write Combining
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Enable DPC'S for each Core
echo Enabling DPC'S for each Core
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Preemption
echo Disabling Preemption
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableCEPreemption" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemptionOnS3S4" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "ComputePreemption" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: BuffersInFlight
echo Setting BuffersInFlight
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "BuffersInFlight" /t REG_DWORD /d "20" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Video Redraw Acceleration
echo Setting Driver Acceleration
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Acceleration.Level" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable NVIDIA 3D Vision Shortcuts
echo Disabling NVIDIA Shortcuts
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DesktopStereoShortcuts" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "FeatureControl" /t REG_DWORD /d "4" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Filter
echo Disabling Filter
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "NVDeviceSupportKFilter" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Increased Dedicated Video Memory
echo Increasing Dedicated Video Memory
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmCacheLoc" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Set NVIDIA Driver Package Install Directory
echo Setting Driver Package Install Directory
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmDisableInst2Sys" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: ReAllocate DMA Buffers
echo ReAllocating DMA Buffers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmFbsrPagedDMA" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Change PCounter Permissions
echo Changing Performance Counter Permissions
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmProfilingAdminOnly" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable DX Event Tracking
echo Disabling DirectX Event Tracking
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TrackResetEngine" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Verifications in Block Transfer Operations
echo Disabling Verifications Block Transfer Operations
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ValidateBlitSubRects" /t REG_DWORD /d "0" /f
timeout /t 1 /nobreak > NUL

:: Disable NVIDIA WDDM TDR
echo Disabling NVIDIA TDR
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDdiDelay" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDebugMode" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLimitCount" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLimitTime" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrTestMode" /t REG_DWORD /d "0" /f
timeout /t 1 /nobreak > NUL

echo Finished NVIDIA GPU Optimizations
timeout /t 5 /nobreak > NUL
goto CompletedPerfOptimizations

:AMD

:: Enable MSI Mode for GPU
echo Enabling MSI Mode
for /f %%g in ('wmic path win32_videocontroller get PNPDeviceID ^| findstr /L "VEN_"') do (
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
)
timeout /t 1 /nobreak > NUL

:: Disable Override Referesh Rate
echo Disabling Display Refresh Rate Override
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "3D_Refresh_Rate_Override_DEF" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable SnapShot
echo Disabling SnapShot
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSnapshot" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Anti Aliasing
echo Disabling Anti Aliasing
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AAF_NA" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AntiAlias_NA" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ASTT_NA" /t REG_SZ /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable AllowSubscription
echo Disabling Subscriptions
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSubscription" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Anisotropic Filtering
echo Disabling Anisotropic Filtering
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AreaAniso_NA" /t REG_SZ /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable AllowRSOverlay
echo Disabling Radeon Overlay
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowRSOverlay" /t REG_SZ /d "false" /f >> %LOG_FILE% 
timeout /t 1 /nobreak > NUL

:: Enable Adaptive DeInterlacing
echo Enabling Adaptive DeInterlacing
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Adaptive De-interlacing" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable AllowSkins
echo Disabling Skins
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSkins" /t REG_SZ /d "false" /f >> %LOG_FILE% 
timeout /t 1 /nobreak > NUL

:: Disable AutoColorDepthReduction_NA
echo Disabling Automatic color 0Bpth Reduction
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AutoColorDepthReduction_NA" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Power Gating
echo Disabling Power Gating
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableSAMUPowerGating" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableUVDPowerGatingDynamic" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableVCEPowerGating" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisablePowerGating" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Clock Gating
echo Disabling Clock Gating
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableVceSwClockGating" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUvdClockGating" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable ASPM
echo Disabling Active State Power Management
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAspmL0s" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAspmL1" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable ULPS
echo Disabling Ultra Low Power States
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps_NA" /t REG_SZ /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Enable De-Lag
echo Enabling De-Lag
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_DeLagEnabled" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable FRT
echo Disabling Frame Rate Target
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_FRTEnabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable DMA
echo Disabling DMA
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Enable BlockWrite
echo Enable BlockWrite
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlockWrite" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable StutterMode
echo Disabling Stutter Mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable GPU Mem Clock Sleep State
echo Disabling GPU Memory Clock Sleep State
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Thermal Throttling
echo Disabling Thermal Throttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Preemption
echo Disabling Preemption
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableComputePreemption" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Setting Main3D
echo Setting Main3D
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_DEF" /t REG_SZ /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D" /t REG_BINARY /d "3100" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Setting FlipQueueSize
echo Setting FlipQueueSize
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "FlipQueueSize" /t REG_BINARY /d "3100" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Setting Shader Cache
echo Setting Shader Cache Size
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ShaderCache" /t REG_BINARY /d "3200" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Configuring TFQ
echo Configuring TFQ
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ" /t REG_BINARY /d "3200" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable HDCP
echo Disabling High-Bandwidth Digital Content Protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" /v "ProtectionControl" /t REG_BINARY /d "0100000001000000" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable GPU Power Down
echo Disabling GPU Power Down
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_GPUPowerDownEnabled" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable AMD Logging
echo Disabling AMD Logging
reg add "HKLM\SYSTEM\CurrentControlSet\Services\amdlog" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: AMD Tweaks (Melody The Neko#9870)
echo Applying Melody AMD Tweaks
for %%a in (LTRSnoopL1Latency LTRSnoopL0Latency LTRNoSnoopL1Latency LTRMaxNoSnoopLatency KMD_RpmComputeLatency
        DalUrgentLatencyNs memClockSwitchLatency PP_RTPMComputeF1Latency PP_DGBMMMaxTransitionLatencyUvd
        PP_DGBPMMaxTransitionLatencyGfx DalNBLatencyForUnderFlow DalDramClockChangeLatencyNs
        BGM_LTRSnoopL1Latency BGM_LTRSnoopL0Latency BGM_LTRNoSnoopL1Latency BGM_LTRNoSnoopL0Latency
        BGM_LTRMaxSnoopLatencyValue BGM_LTRMaxNoSnoopLatencyValue) do (reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "%%a" /t REG_DWORD /d "1" /f >> %LOG_FILE%
)

echo Finished AMD GPU Optimizations
timeout /t 5 /nobreak > NUL
goto CompletedPerfOptimizations

:IGPU
:: Dedicated Segment Size
echo Setting Dedicated Segment Size
reg add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "512" /f >> %LOG_FILE%
timeout /t 5 /nobreak > NUL

goto CompletedPerfOptimizations


:CompletedPerfOptimizations
cls
echo Completed Performance Optimizations
timeout /t 3 /nobreak > NUL
cls
call :SetColors
echo.
echo.
echo.
echo.
echo                          %w%██╗░░██╗██████╗░░█████╗░  ████████╗░██╗░░░░░░░██╗███████╗░█████╗░██╗░░██╗███████╗██████╗░%t%
echo                          %w%╚██╗██╔╝██╔══██╗██╔══██╗  ╚══██╔══╝░██║░░██╗░░██║██╔════╝██╔══██╗██║░██╔╝██╔════╝██╔══██╗%t%
echo                          %w%░╚███╔╝░██████╔╝╚█████╔╝  ░░░██║░░░░╚██╗████╗██╔╝█████╗░░███████║█████═╝░█████╗░░██████╔╝%t%
echo                          %w%░██╔██╗░██╔══██╗██╔══██╗  ░░░██║░░░░░████╔═████║░██╔══╝░░██╔══██║██╔═██╗░██╔══╝░░██╔══██╗%t%
echo                          %w%██╔╝╚██╗██║░░██║╚█████╔╝  ░░░██║░░░░░╚██╔╝░╚██╔╝░███████╗██║░░██║██║░╚██╗███████╗██║░░██║%t%
echo                          %w%╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░  ░░░╚═╝░░░░░░╚═╝░░░╚═╝░░╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝%t%
echo.
echo                                                 %w%Created By: XR8%t%
echo                                                      %w%Version: %SCRIPT_VERSION%%t%
echo.
echo %w%═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%t%

echo.
echo.
echo.
echo.
echo.
echo                                              %c%[1]%t% %w%Menu%t%               %c%[2]%t% %w%Exit%t%
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Menu
if '%choice%'=='2' goto Close


:KBMOptimizations
cls

:: Disable Sticky Keys
echo Disabling Sticky Keys
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Filter Keys
echo Disabling Filter Keys
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Toggle Keys
echo Disabling Toggle Keys
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: MSI Mode for USB Controller
echo Enabling MSI Mode for USB Controller
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable USB PowerSavings
echo Disabling USB PowerSavings
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f >> %LOG_FILE%
)
timeout /t 1 /nobreak > NUL

:: Disable Selective Suspend
echo Disabling USB Selective Suspend
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USB" /v "DisableSelectiveSuspend" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Mouse Acceleration
echo Disabling Mouse Acceleration
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Enable 1:1 Pixel Mouse Movements
echo Enabling 1:1 Pixel Mouse Movements
reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Mouse Smoothing
echo Disabling Mouse Smoothing
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "00000000000000000000000000000000000000000000000000000000000000000000000000000000" /f >> %LOG_FILE%
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "00000000000000000000000000000000000000000000000000000000000000000000000000000000" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Reduce Keyboard Repeat Delay
echo Reducing Keyboard Repeat Delay
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Reduce Keyboard Repeat Rate
echo Increasing Keyboard Repeat Rate
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Mouse Data Queue Size
echo Setting Mouse Data Queue Size
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "16" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Keyboard Data Queue Size
echo Setting Keyboard Data Queue Size
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "16" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: DebugPollInterval (BeersE#9366)
echo Setting Debug Poll Interval
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DebugPollInterval" /t REG_DWORD /d "1000" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Setting CSRSS to Realtime
echo Setting CSRSS to Realtime
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

goto CompletedKBMOptimizations

:CompletedKBMOptimizations
cls
echo Completed KBM Optimizations
timeout /t 3 /nobreak > NUL
cls
call :SetColors
echo.
echo.
echo.
echo.
echo                          %w%██╗░░██╗██████╗░░█████╗░  ████████╗░██╗░░░░░░░██╗███████╗░█████╗░██╗░░██╗███████╗██████╗░%t%
echo                          %w%╚██╗██╔╝██╔══██╗██╔══██╗  ╚══██╔══╝░██║░░██╗░░██║██╔════╝██╔══██╗██║░██╔╝██╔════╝██╔══██╗%t%
echo                          %w%░╚███╔╝░██████╔╝╚█████╔╝  ░░░██║░░░░╚██╗████╗██╔╝█████╗░░███████║█████═╝░█████╗░░██████╔╝%t%
echo                          %w%░██╔██╗░██╔══██╗██╔══██╗  ░░░██║░░░░░████╔═████║░██╔══╝░░██╔══██║██╔═██╗░██╔══╝░░██╔══██╗%t%
echo                          %w%██╔╝╚██╗██║░░██║╚█████╔╝  ░░░██║░░░░░╚██╔╝░╚██╔╝░███████╗██║░░██║██║░╚██╗███████╗██║░░██║%t%
echo                          %w%╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░  ░░░╚═╝░░░░░░╚═╝░░░╚═╝░░╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝%t%
echo.
echo                                                 %w%Created By: XR8%t%
echo                                                      %w%Version: %SCRIPT_VERSION%%t%
echo.
echo %w%═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%t%

echo.
echo.
echo.
echo.
echo.
echo                                              %c%[1]%t% %w%Menu%t%               %c%[2]%t% %w%Exit%t%

set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Menu
if '%choice%'=='2' goto Close


:DisableTelemetry
cls

:: Disable Telemetry Through Task Scheduler
echo Disabling Telemetry Through Task Scheduler
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Autochk\Proxy" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Maintenance\WinSAT" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Application Experience\AitAgent" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\PI\Sqm-Tasks" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" >> %LOG_FILE%
schtasks /change /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn" >> %LOG_FILE%
schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoftd\Office\OfficeTelemetryAgentFallBack" >> %LOG_FILE%
schtasks /change /TN "\Microsoftd\Office\OfficeTelemetryAgentFallBack" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Office\Office 15 Subscription Heartbeat" >> %LOG_FILE%
schtasks /change /TN "\Microsoft\Office\Office 15 Subscription Heartbeat" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" >> %LOG_FILE%
schtasks /change /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Time Synchronization\SynchronizeTime" >> %LOG_FILE%
schtasks /change /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\WindowsUpdate\Automatic App Update" >> %LOG_FILE%
schtasks /change /TN "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable >> %LOG_FILE%
schtasks /end /tn "\Microsoft\Windows\Device Information\Device" >> %LOG_FILE%
schtasks /change /TN "\Microsoft\Windows\Device Information\Device" /disable >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Telemetry Through Registry
echo Disabling Telemetry Through Registry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "DoSvc" /t REG_DWORD /d "3" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\DriverDatabase\Policies\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "CEIPEnable" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Reliability" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "DisableOptinExperience" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\IE" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\DriverDatabase\Policies\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable AutoLoggers
echo Disabling Auto Loggers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsClient" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsProxy" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Mellanox-Kernel" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f >> %LOG_FILE% 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Telemetry Services
echo Disabling Telemetry Services >> %LOG_FILE%
sc stop DiagTrack >> %LOG_FILE%
sc config DiagTrack start= disabled >> %LOG_FILE%
sc stop dmwappushservice >> %LOG_FILE%
sc config dmwappushservice start= disabled >> %LOG_FILE%
sc stop diagnosticshub.standardcollector.service >> %LOG_FILE%
sc config diagnosticshub.standardcollector.service start= disabled >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

goto CompletedTelemetryOptimizations

:CompletedTelemetryOptimizations
cls
echo Completed Telemetry Optimizations
timeout /t 3 /nobreak > NUL
cls
call :SetColors
echo.
echo.
echo.
echo.
echo                          %w%██╗░░██╗██████╗░░█████╗░  ████████╗░██╗░░░░░░░██╗███████╗░█████╗░██╗░░██╗███████╗██████╗░%t%
echo                          %w%╚██╗██╔╝██╔══██╗██╔══██╗  ╚══██╔══╝░██║░░██╗░░██║██╔════╝██╔══██╗██║░██╔╝██╔════╝██╔══██╗%t%
echo                          %w%░╚███╔╝░██████╔╝╚█████╔╝  ░░░██║░░░░╚██╗████╗██╔╝█████╗░░███████║█████═╝░█████╗░░██████╔╝%t%
echo                          %w%░██╔██╗░██╔══██╗██╔══██╗  ░░░██║░░░░░████╔═████║░██╔══╝░░██╔══██║██╔═██╗░██╔══╝░░██╔══██╗%t%
echo                          %w%██╔╝╚██╗██║░░██║╚█████╔╝  ░░░██║░░░░░╚██╔╝░╚██╔╝░███████╗██║░░██║██║░╚██╗███████╗██║░░██║%t%
echo                          %w%╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░  ░░░╚═╝░░░░░░╚═╝░░░╚═╝░░╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝%t%
echo.
echo                                                 %w%Created By: XR8%t%
echo                                                      %w%Version: %SCRIPT_VERSION%%t%
echo.
echo %w%═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%t%

echo.
echo.
echo.
echo.
echo.
echo                                              %c%[1]%t% %w%Menu%t%               %c%[2]%t% %w%Exit%t%

set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Menu
if '%choice%'=='2' goto Close


:Network
cls
echo Network Optimizations can cause better/worse results depending on the user, results may vary.
echo Would you like to Create a Restore Point before Optimizing your Network? Yes = 1 No = 2 Go back to Menu = 3
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto RP2
if '%choice%'=='2' goto NetworkTweaks
if '%choice%'=='3' goto Menu

:RP2
:: Creating Restore Point
echo Creating Restore Point
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d "0" /f >> %LOG_FILE%
powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'XR8 Performance Batch' -RestorePointType 'MODIFY_SETTINGS'" >> %LOG_FILE%

:NetworkTweaks
cls

:: Reset Internet
echo Resetting Internet
ipconfig /release
ipconfig /renew
ipconfig /flushdns
netsh int ip reset
netsh int ipv4 reset
netsh int ipv6 reset
netsh int tcp reset
netsh winsock reset
netsh advfirewall reset
netsh branchcache reset
netsh http flush logbuffer
timeout /t 3 /nobreak > NUL

:: Disable Network Power Savings
echo Disabling Network Power Savings
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "EnableDynamicPowerGating" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "EnableSavePowerNow" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "NicAutoPowerSaver" /t REG_DWORD /d "0" /f >> %LOG_FILE%

:: Set Network Autotuning to Normal
echo Setting Network AutoTuning to Normal
netsh int tcp set global autotuninglevel=normal
timeout /t 1 /nobreak > NUL

:: Disable ECN
echo Disabling Explicit Congestion Notification
netsh int tcp set global ecncapability=disabled
timeout /t 1 /nobreak > NUL

:: Enable DCA
echo Enabling Direct Cache Access
netsh int tcp set global dca=enabled
timeout /t 1 /nobreak > NUL

:: Enable NetDMA
echo Enabling Network Direct Memory Access
netsh int tcp set global netdma=enabled
timeout /t 1 /nobreak > NUL

:: Disable RSC
echo Disabling Recieve Side Coalescing
netsh int tcp set global rsc=disabled
timeout /t 1 /nobreak > NUL

:: Enable RSS
echo Enabling Recieve Side Scaling
netsh int tcp set global rss=enabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Ndis\Parameters" /v "RssBaseCpu" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable TCP Timestamps
echo Disabling TCP Timestamps
netsh int tcp set global timestamps=disabled
timeout /t 1 /nobreak > NUL

:: Set Initial RTO to 2ms
echo Setting Initial Retransmission Timer
netsh int tcp set global initialRto=2000
timeout /t 1 /nobreak > NUL

:: Set MTU Size to 1500
echo Setting MTU Size
netsh interface ipv4 set subinterface “Ethernet” mtu=1500 store=persistent
timeout /t 1 /nobreak > NUL

:: Disable NonSackRTTresiliency
echo Disabling Non Sack RTT Resiliency
netsh int tcp set global nonsackrttresiliency=disabled
timeout /t 1 /nobreak > NUL

:: Set Max Syn Retransmissions to 2
echo Setting Max Syn Retransmissions
netsh int tcp set global maxsynretransmissions=2
timeout /t 1 /nobreak > NUL

:: Disable MPP
echo Disabling Memory Pressure Protection
netsh int tcp set security mpp=disabled
timeout /t 1 /nobreak > NUL

:: Disable Security Profiles
echo Disabling Security Profiles
netsh int tcp set security profiles=disabled
timeout /t 1 /nobreak > NUL

:: Disable Heuristics
echo Disabling Windows Scaling Heuristics
netsh int tcp set heuristics disabled
timeout /t 1 /nobreak > NUL

:: Increase ARP Cache Size to 4096
echo Increasing ARP Cache Size
netsh int ip set global neighborcachelimit=4096
timeout /t 1 /nobreak > NUL

:: Enable CTCP
echo Enabling CTCP
netsh int tcp set supplemental Internet congestionprovider=ctcp
timeout /t 1 /nobreak > NUL

:: Disable Task Offloading
echo Disabling Task Offloading
netsh int ip set global taskoffload=disabled
timeout /t 1 /nobreak > NUL

:: Disable IPv6
echo Disabling IPv6
netsh int ipv6 set state disabled
timeout /t 1 /nobreak > NUL

:: Disable ISATAP
echo Disabling ISATAP
netsh int isatap set state disabled
timeout /t 1 /nobreak > NUL

:: Disable Teredo
echo Disabling Teredo
netsh int teredo set state disabled
timeout /t 1 /nobreak > NUL

:: Set TTL to 64
echo Configuring Time to Live
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Enable TCP Window Scaling
echo Enabling TCP Window Scaling
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Set TcpMaxDupAcks
echo Setting TcpMaxDupAcks to 2
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable SackOpts
echo Disabling TCP Selective ACKs
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Increase Maximum Port Number
echo Increasing Maximum Port Number
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Decrease Time to Wait in "TIME_WAIT" State
echo Decreasing Timed Wait Delay
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Set Network Priorities
echo Setting Network Priorities
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Adjust Sock Address Size
echo Configuring Sock Address Size
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Nagle's Algorithm
echo Disabling Nagle's Algorithm
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Delivery Optimization
echo Disabling Delivery Optimization
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Auto Disconnect for Idle Connections
echo Disabling Auto Disconnect
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Limit Number of SMB Sessions
echo Limiting SMB Sessions
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Oplocks
echo Disabling Oplocks
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Set IRP Stack Size
echo Setting IRP Stack Size
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "20" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Sharing Violations
echo Disabling Sharing Violations
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Get the Sub ID of the Network Adapter
for /f %%n in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /v "*SpeedDuplex" /s ^| findstr  "HKEY"') do (

:: Disable NIC Power Savings
echo Disabling NIC Power Savings
reg add "%%n" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "*EEE" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "EEE" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "EnablePME" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "EnablePowerManagement" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "EnableWakeOnLan" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "WakeOnLink" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Jumbo Frame
echo Disabling Jumbo Frame
reg add "%%n" /v "JumboPacket" /t REG_SZ /d "1514" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Configure Receive/Transmit Buffers
echo Configuring Buffer Sizes
reg add "%%n" /v "TransmitBuffers" /t REG_SZ /d "4096" /f >> %LOG_FILE%
reg add "%%n" /v "ReceiveBuffers" /t REG_SZ /d "512" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Configure Offloads
echo Configuring Offloads
reg add "%%n" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "LsoV1IPv4" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "LsoV2IPv4" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "LsoV2IPv6" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "PMARPOffload" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "PMNSOffload" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Enable RSS in NIC
echo Enabling RSS in NIC
reg add "%%n" /v "RSS" /t REG_SZ /d "1" /f >> %LOG_FILE%
reg add "%%n" /v "*NumRssQueues" /t REG_SZ /d "2" /f >> %LOG_FILE%
reg add "%%n" /v "RSSProfile" /t REG_SZ /d "3" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Disable Flow Control
echo Disabling Flow Control
reg add "%%n" /v "*FlowControl" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "FlowControlCap" /t REG_SZ /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Remove Interrupt Delays
echo Removing Interrupt Delays
reg add "%%n" /v "RxAbsIntDelay" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "TxIntDelay" /t REG_SZ /d "0" /f >> %LOG_FILE%
reg add "%%n" /v "TxAbsIntDelay" /t REG_SZ /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Remove Adapter Notification
echo Removing Adapter Notification Sending
reg add "%%n" /v "FatChannelIntolerant" /t REG_SZ /d "0" /f >> %LOG_FILE%
timeout /t 1 /nobreak > NUL

:: Enable Interrupt Moderation
echo Enabling Interrupt Moderation
reg add "%%n" /v "*InterruptModeration" /t REG_SZ /d "1" /f >> %LOG_FILE%
)

goto CompletedNetworkOptimizations

:CompletedNetworkOptimizations
cls
echo Completed Network Optimizations
timeout /t 3 /nobreak > NUL
cls
call :SetColors
echo.
echo.
echo.
echo.
echo                          %w%██╗░░██╗██████╗░░█████╗░  ████████╗░██╗░░░░░░░██╗███████╗░█████╗░██╗░░██╗███████╗██████╗░%t%
echo                          %w%╚██╗██╔╝██╔══██╗██╔══██╗  ╚══██╔══╝░██║░░██╗░░██║██╔════╝██╔══██╗██║░██╔╝██╔════╝██╔══██╗%t%
echo                          %w%░╚███╔╝░██████╔╝╚█████╔╝  ░░░██║░░░░╚██╗████╗██╔╝█████╗░░███████║█████═╝░█████╗░░██████╔╝%t%
echo                          %w%░██╔██╗░██╔══██╗██╔══██╗  ░░░██║░░░░░████╔═████║░██╔══╝░░██╔══██║██╔═██╗░██╔══╝░░██╔══██╗%t%
echo                          %w%██╔╝╚██╗██║░░██║╚█████╔╝  ░░░██║░░░░░╚██╔╝░╚██╔╝░███████╗██║░░██║██║░╚██╗███████╗██║░░██║%t%
echo                          %w%╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░  ░░░╚═╝░░░░░░╚═╝░░░╚═╝░░╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝%t%
echo.
echo                                                 %w%Created By: XR8%t%
echo                                                      %w%Version: %SCRIPT_VERSION%%t%
echo.
echo %w%═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%t%

echo.
echo.
echo.
echo.
echo.
echo                                              %c%[1]%t% %w%Menu%t%               %c%[2]%t% %w%Exit%t%
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto Menu
if '%choice%'=='2' goto Close


:DebloatWindows
cls

chcp 65001 >nul 2>&1
cls
call :SetColors
echo.
echo.
echo.
echo.
echo      %w%█████%y%%c%╗%t% %w%███%y%%c%╗%t%   %w%██%y%%c%╗%t% %w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%╗%t%     %w%███████%y%%c%╗%t%    %w%████████%y%%c%╗%t%%w%██%y%%c%╗%t%    %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t% %w%█████%y%%c%╗%t% %w%██%y%%c%╗%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██████%y%%c%╗%t% 
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%████%y%%c%╗%t%  %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔════╝    ╚══%t%%w%██%y%%c%╔══╝%t%%w%██%y%%c%║%t%    %w%██%y%%c%║%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t% %w%██%y%%c%╔╝%t%%w%██%y%%c%╔════╝%t%%w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%███████%y%%c%║%t%%w%██%y%%c%╔%t%%w%██%y%%c%╗%t% %w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%█████%y%%c%╗%t%  %w%██%y%%c%║%t%     %w%███████%y%%c%╗%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t% %w%█%y%%c%╗%t% %w%██%y%%c%║%t%%w%█████%y%%c%╗%t%  %w%███████%y%%c%║%t%%w%█████%y%%c%╔╝%t% %w%█████%y%%c%╗%t%  %w%██████%y%%c%╔╝%t%
echo     %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%║╚%t%%w%██%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%║%t%     %w%██%y%%c%╔══╝%t%  %w%██%y%%c%║     ╚════%t%%w%██%y%%c%║%t%       %w%██%y%%c%║%t%   %w%██%y%%c%║%t%%w%███%y%%c%╗%t%%w%██%y%%c%║%t%%w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%║%t%%w%██%y%%c%╔═%t%%w%██%y%%c%╗%t% %w%██%y%%c%╔══╝%t%  %w%██%y%%c%╔══%t%%w%██%y%%c%╗%t%
echo     %w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║ ╚%t%%w%████%y%%c%║╚%t%%w%██████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%███████%y%%c%║%t%       %w%██%y%%c%║   ╚%t%%w%███%y%%c%╔%t%%w%███%y%%c%╔╝%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%%w%██%y%%c%║%t%  %w%██%y%%c%╗%t%%w%███████%y%%c%╗%t%%w%██%y%%c%║%t%  %w%██%y%%c%║%t%
echo     %c%╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚══════╝╚══════╝       ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝%t%                                                                                                                                                        
echo                                                 %w%Created By: XR8%t%     
echo                                                      %w%Version: %SCRIPT_VERSION%%t%
echo.
echo %w%════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%t%
echo.
echo.
echo.
echo                          %c%[1]%t% %w%Remove Powershell Packages%t%                  %c%[2]%t% %w%Disable Cortana%t%
echo. 
echo.
echo                          %c%[3]%t% %w%Disable Unnecessary Services%t%                %c%[4]%t% %w%Disable OneDrive%t%
echo.
echo.
echo                          %c%[5]%t% %w%PC Cleaner%t%                                  %c%[6]%t% %w%Go Back to Menu%t%
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto PowerShellPackages
if '%choice%'=='2' goto DisableCortana
if '%choice%'=='3' goto UnnecessaryServicesDisable  
if '%choice%'=='4' goto DisableOneDrive
if '%choice%'=='5' goto PCCleaner
if '%choice%'=='6' goto Menu                  

:PowerShellPackages
cls
echo Removing Unnecessary Powershell Packages
PowerShell -Command "Get-AppxPackage -allusers *3DBuilder* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *bing* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *bingfinance* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *bingsports* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *BingWeather* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *Drawboard PDF* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *Facebook* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *Getstarted* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *Microsoft.Messaging* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *MicrosoftOfficeHub* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *Office.OneNote* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *OneNote* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *people* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *SkypeApp* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *solit* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *Sway* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *Twitter* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *WindowsAlarms* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *WindowsPhone* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *WindowsMaps* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *WindowsFeedbackHub* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *WindowsSoundRecorder* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *windowscommunicationsapps* | Remove-AppxPackage" >> %LOG_FILE%
PowerShell -Command "Get-AppxPackage -allusers *zune* | Remove-AppxPackage" >> %LOG_FILE%
timeout /t 5 /nobreak > NUL

goto DebloatWindows

:UnnecessaryServicesDisable
cls
echo Disabling Unnecessary Services
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\perceptionsimulation" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\StiSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\autotimesvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVE" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SensorService" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\svsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NfsClnt" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedRealitySvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TrkWks" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CryptSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServer" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\InstallService" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\OSRSS" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\sedsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SENS" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CaptureService" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "0" /f >> %LOG_FILE%

timeout /t 5 /nobreak > NUL

goto DebloatWindows

:DisableCortana
cls
echo Disabling Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "0" /f >> %LOG_FILE%
Powershell -Command "Get-appxpackage -allusers *Microsoft.549981C3F5F10* | Remove-AppxPackage" >> %LOG_FILE%
timeout /t 5 /nobreak > NUL

goto DebloatWindows

:DisableOneDrive
cls
echo Disabling OneDrive
start /wait "" "%SYSTEMROOT%\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
rd C:\OneDriveTemp /q /s >> %LOG_FILE%
rd "%USERPROFILE%\OneDrive" /q /s >> %LOG_FILE%
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /q /s >> %LOG_FILE%
rd "%PROGRAMDATA%\Microsoft OneDrive" /q /s >> %LOG_FILE%
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" >> %LOG_FILE%
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v "Attributes" /t REG_DWORD /d "0" >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 5 /nobreak > NUL

goto DebloatWindows

:PCCleaner
cls
echo Cleaning PC...
del /s /f /q c:\windows\temp. >> %LOG_FILE%
del /s /f /q C:\WINDOWS\Prefetch >> %LOG_FILE%
del /s /f /q %temp%. >> %LOG_FILE%
del /s /f /q %systemdrive%\*.tmp >> %LOG_FILE%
del /s /f /q %systemdrive%\*._mp >> %LOG_FILE%
del /s /f /q %systemdrive%\*.log >> %LOG_FILE%
del /s /f /q %systemdrive%\*.gid >> %LOG_FILE%
del /s /f /q %systemdrive%\*.chk >> %LOG_FILE%
del /s /f /q %systemdrive%\*.old >> %LOG_FILE%
del /s /f /q %systemdrive%\recycled\*.* >> %LOG_FILE%
del /s /f /q %systemdrive%\$Recycle.Bin\*.* >> %LOG_FILE%
del /s /f /q %windir%\*.bak >> %LOG_FILE%
del /s /f /q %windir%\prefetch\*.* >> %LOG_FILE%
del /s /f /q %LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db >> %LOG_FILE%
del /s /f /q %LocalAppData%\Microsoft\Windows\Explorer\*.db >> %LOG_FILE%
del /f /q %SystemRoot%\Logs\CBS\CBS.log >> %LOG_FILE%
del /f /q %SystemRoot%\Logs\DISM\DISM.log >> %LOG_FILE%
deltree /y c:\windows\tempor~1 >> %LOG_FILE%
deltree /y c:\windows\temp >> %LOG_FILE%
deltree /y c:\windows\tmp >> %LOG_FILE%
deltree /y c:\windows\ff*.tmp >> %LOG_FILE%
deltree /y c:\windows\history >> %LOG_FILE%
deltree /y c:\windows\cookies >> %LOG_FILE%
deltree /y c:\windows\recent >> %LOG_FILE%
deltree /y c:\windows\spool\printers >> %LOG_FILE%
cls
timeout /t 10 /nobreak > NUL

goto DebloatWindows

:Other

cls
call :SetColors
echo.
echo.
echo.
echo.
:: ================== HEADER (kept as-is; you can strip %w%/%t% later if you want) ==================
echo                          %w%██╗░░██╗██████╗░░█████╗░  ████████╗░██╗░░░░░░░██╗███████╗░█████╗░██╗░░██╗███████╗██████╗░%t%
echo                          %w%╚██╗██╔╝██╔══██╗██╔══██╗  ╚══██╔══╝░██║░░██╗░░██║██╔════╝██╔══██╗██║░██╔╝██╔════╝██╔══██╗%t%
echo                          %w%░╚███╔╝░██████╔╝╚█████╔╝  ░░░██║░░░░╚██╗████╗██╔╝█████╗░░███████║█████═╝░█████╗░░██████╔╝%t%
echo                          %w%░██╔██╗░██╔══██╗██╔══██╗  ░░░██║░░░░░████╔═████║░██╔══╝░░██╔══██║██╔═██╗░██╔══╝░░██╔══██╗%t%
echo                          %w%██╔╝╚██╗██║░░██║╚█████╔╝  ░░░██║░░░░░╚██╔╝░╚██╔╝░███████╗██║░░██║██║░╚██╗███████╗██║░░██║%t%
echo                          %w%╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░  ░░░╚═╝░░░░░░╚═╝░░░╚═╝░░╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝%t%
echo.
echo                                                 %w%Created By: XR8%t%
echo                                                      %w%Version: %SCRIPT_VERSION%%t%
echo.
echo %w%═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════%t%

echo.
echo.
echo.
:: ================== MENU (Power Plan removed; renumbered) ==================
echo                                         %c%[1]%t% %w%Disable Drivers%t%     %c%[2]%t% %w%KBoost%t%
echo.
echo.
echo                                         %c%[3]%t% %w%Menu%t%
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto DisableDrivers
if '%choice%'=='2' goto KBoost
if '%choice%'=='3' goto Menu

:DisableDrivers
cls
echo Disabling Drivers are very risky. This can break certain things within windows, do you wish to Continue?
echo Yes = 1 No = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto DisableDriversContinue
if '%choice%'=='2' goto Other

:DisableDriversContinue
cls
echo Disabling Drivers
reg add "HKLM\SYSTEM\CurrentControlSet\Services\acpipagr" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AcpiPmi" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CAD" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CLFS" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSC" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\luafv" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasAcd" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Rasl2tp" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasPppoe" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasSstp" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpipreg" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dam" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wanarpv6" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PEAUTH" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVEdrv" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cdrom" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\fileinfo" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FileCrypt" /v "Start" /t REG_DWORD /d "4" /f >> %LOG_FILE%
timeout /t 10 /nobreak > NUL
goto Other

:: ===== PowerPlan block REMOVED =====

:KBoost
cls
echo Would you like to Enable/Disable KBoost?
echo Enable = 1 Disable = 2
set choice=
set /p choice=
if not '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' goto EnableKBoost
if '%choice%'=='2' goto DisableKBoost

:EnableKBoost
cls
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PerfLevelSrc" /t REG_DWORD /d "2222" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerEnable" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevel" /t REG_DWORD /d "0" /f >> %LOG_FILE%
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevelAC" /t REG_DWORD /d "0" /f >> %LOG_FILE%
timeout /t 3 /nobreak > NUL
goto Other

:DisableKBoost
cls
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PerfLevelSrc" /f >> %LOG_FILE%
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerEnable" /f >> %LOG_FILE%
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevel" /f >> %LOG_FILE%
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevelAC" /f >> %LOG_FILE%
timeout /t 3 /nobreak > NUL
goto Other

:Close
cls
exit

:SetColors
for /f %%A in ('echo prompt $E^| cmd') do set "ESC=%%A"
set "w=%ESC%[97m"
set "c=%ESC%[96m"
set "y=%ESC%[93m"
set "u=%ESC%[95m"
set "q=%ESC%[92m"
set "t=%ESC%[0m"
exit /b

:HandleRestorePoint
echo Do you want to Create a Restore Point? Yes = 1 No = 2
set "restore_choice="
set /p "restore_choice="
if not "%restore_choice%"=="" set "restore_choice=%restore_choice:~0,1%"
if "%restore_choice%"=="1" (
    echo Creating Restore Point
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d "0" /f >> "%LOG_FILE%"
    powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'XR8 Performance Batch' -RestorePointType 'MODIFY_SETTINGS'" >> "%LOG_FILE%"
)
exit /b
