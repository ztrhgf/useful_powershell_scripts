<#PSScriptInfo

.VERSION 1.2

.GUID 0f142d4f-192e-4121-b3fd-010611e4c306

.AUTHOR Ondrej Sebela

.COMPANYNAME Microsoft

.COPYRIGHT

.TAGS Windows AutoPilot

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
Version 1.0:  enhanced & fixed version based on original 5.6 version of Get-AutopilotDiagnostics.ps1 from Michael Niehaus)
Version 1.1:  fixed path to log files
Version 1.2:  fixed Intune objects paging in GetIntuneObjects function (thanks JSiess)

#>


<#
.SYNOPSIS
Displays Windows Autopilot diagnostics information from the current PC or a captured set of logs.

.DESCRIPTION
This script displays diagnostics information from the current PC or a captured set of logs. This includes details about the Autopilot profile settings; policies, apps, certificate profiles, scripts, remediation scripts etc. being tracked via the Enrollment Status Page; and additional information.

This should work with Windows 10 1903 and later (earlier versions have not been validated). This script will not work on ARM64 systems due to registry redirection from the use of x86 PowerShell.exe.

This script is enhanced version of the great, but no longer maintained Get-AutopilotDiagnostics.ps1 so kudos to its author Michael Niehaus.

.PARAMETER Online
Look up the actual policy, app and script names via the Intune Graph API

.PARAMETER AllSessions
Show all ESP progress instead of just the final details.

.PARAMETER CABFile
Processes the information in the specified CAB file (captured by MDMDiagnosticsTool.exe -area Autopilot -cab filename.cab) instead of from the registry.

.PARAMETER ZIPFile
Processes the information in the specified ZIP file (captured by MDMDiagnosticsTool.exe -area Autopilot -zip filename.zip) instead of from the registry.

.PARAMETER ShowPolicies
Shows the policy details as recorded in the NodeCache registry keys, in the order that the policies were received by the client.

.EXAMPLE
.\Get-AutopilotDiagnostics.ps1

.EXAMPLE
.\Get-AutopilotDiagnostics.ps1 -Online

.EXAMPLE
.\Get-AutopilotESPStatus.ps1 -AllSessions

.EXAMPLE
.\Get-AutopilotDiagnostics.ps1 -CABFile C:\Autopilot.cab -Online -AllSessions

.EXAMPLE
.\Get-AutopilotDiagnostics.ps1 -ZIPFile C:\Autopilot.zip

.EXAMPLE
.\Get-AutopilotDiagnostics.ps1 -ShowPolicies

.NOTES
This script is enhanced & fixed version of the great, but no longer maintained Get-AutopilotDiagnostics.ps1 so kudos to its author Michael Niehaus.

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $False)] [String] $CABFile = $null,
    [Parameter(Mandatory = $False)] [String] $ZIPFile = $null,
    [Parameter(Mandatory = $False)] [Switch] $Online = $false,
    [Parameter(Mandatory = $False)] [Switch] $AllSessions = $false,
    [Parameter(Mandatory = $False)] [Switch] $ShowPolicies = $false
)

Begin {
    # Process log files if needed
    $script:useFile = $false
    if ($CABFile -or $ZIPFile) {

        if (-not (Test-Path "$($env:TEMP)\ESPStatus.tmp")) {
            New-Item -Path "$($env:TEMP)\ESPStatus.tmp" -ItemType "directory" | Out-Null
        }
        Remove-Item -Path "$($env:TEMP)\ESPStatus.tmp\*.*" -Force -Recurse
        $script:useFile = $true

        # If using a CAB file, extract the needed files from it
        if ($CABFile) {
            $fileList = @("MdmDiagReport_RegistryDump.reg", "microsoft-windows-devicemanagement-enterprise-diagnostics-provider-admin.evtx",
                "microsoft-windows-user device registration-admin.evtx", "AutopilotDDSZTDFile.json", "*.csv", "AppActionProcessor.log")

            $fileList | % {
                $null = & expand.exe "$CABFile" -F:$_ "$($env:TEMP)\ESPStatus.tmp\"
                if (-not (Test-Path "$($env:TEMP)\ESPStatus.tmp\$_")) {
                    Write-Error "Unable to extract $_ from $CABFile"
                }
            }
        } else {
            # If using a ZIP file, just extract the entire contents (not as easy to do selected files)
            Expand-Archive -Path $ZIPFile -DestinationPath "$($env:TEMP)\ESPStatus.tmp\"
        }

        # Get the hardware hash information
        $csvFile = (Get-ChildItem "$($env:TEMP)\ESPStatus.tmp\*.csv").FullName
        if ($csvFile) {
            $csv = Get-Content $csvFile | ConvertFrom-Csv
            $hash = $csv.'Hardware Hash'
        }

        # apps
        $appActionProcessorLogFile = "$($env:TEMP)\ESPStatus.tmp\AppActionProcessor.log"
        # remediation scripts
        $healthScriptsLogFile = "$($env:TEMP)\ESPStatus.tmp\HealthScripts.log"
        # scripts
        $agentExecutorLogFile = "$($env:TEMP)\ESPStatus.tmp\AgentExecutor.log"

        # Edit the path in the .reg file
        $content = Get-Content -Path "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_RegistryDump.reg"
        $content = $content -replace "\[HKEY_CURRENT_USER\\", "[HKEY_CURRENT_USER\ESPStatus.tmp\USER\"
        $content = $content -replace "\[HKEY_LOCAL_MACHINE\\", "[HKEY_CURRENT_USER\ESPStatus.tmp\MACHINE\"
        $content = $content -replace '^    "', '"'
        $content = $content -replace '^    @', '@'
        $content = $content -replace 'DWORD:', 'dword:'
        "Windows Registry Editor Version 5.00`n" | Set-Content -Path "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_Edited.reg"
        $content | Add-Content -Path "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_Edited.reg"

        # Remove the registry info if it exists
        if (Test-Path "HKCU:\ESPStatus.tmp") {
            Remove-Item -Path "HKCU:\ESPStatus.tmp" -Recurse -Force
        }

        # Import the .reg file
        $null = & reg.exe IMPORT "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_Edited.reg" 2>&1

        # Configure the (not live) constants
        $script:provisioningPath = "HKCU:\ESPStatus.tmp\MACHINE\software\microsoft\provisioning"
        $script:autopilotDiagPath = "HKCU:\ESPStatus.tmp\MACHINE\software\microsoft\provisioning\Diagnostics\Autopilot"
        $script:omadmPath = "HKCU:\ESPStatus.tmp\MACHINE\software\microsoft\provisioning\OMADM"
        $script:path = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics"
        $script:msiPath = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\EnterpriseDesktopAppManagement"
        $script:officePath = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\OfficeCSP"
        $script:sidecarPath = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\IntuneManagementExtension\Win32Apps"
        $script:enrollmentsPath = "HKCU:\ESPStatus.tmp\MACHINE\software\microsoft\enrollments"
    } else {
        # Configure live constants
        $script:provisioningPath = "HKLM:\software\microsoft\provisioning"
        $script:autopilotDiagPath = "HKLM:\software\microsoft\provisioning\Diagnostics\Autopilot"
        $script:omadmPath = "HKLM:\software\microsoft\provisioning\OMADM"
        $script:path = "HKLM:\Software\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics"
        $script:msiPath = "HKLM:\Software\Microsoft\EnterpriseDesktopAppManagement"
        $script:officePath = "HKLM:\Software\Microsoft\OfficeCSP"
        $script:sidecarPath = "HKLM:\Software\Microsoft\IntuneManagementExtension\Win32Apps"
        $script:enrollmentsPath = "HKLM:\Software\Microsoft\enrollments"

        $hash = (Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData

        # apps
        $appActionProcessorLogFile = "$($env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\AppActionProcessor.log"
        # remediation scripts
        $healthScriptsLogFile = "$($env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\HealthScripts.log"
        # scripts
        $agentExecutorLogFile = "$($env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\AgentExecutor.log"
    }

    # Configure other constants
    $script:officeStatus = @{"0" = "None"; "10" = "Initialized"; "20" = "Download In Progress"; "25" = "Pending Download Retry";
        "30" = "Download Failed"; "40" = "Download Completed"; "48" = "Pending User Session"; "50" = "Enforcement In Progress";
        "55" = "Pending Enforcement Retry"; "60" = "Enforcement Failed"; "70" = "Success / Enforcement Completed"
    }
    $script:espStatus = @{"1" = "Not Installed"; "2" = "Downloading / Installing"; "3" = "Success / Installed"; "4" = "Error / Failed" }
    $script:policyStatus = @{"0" = "Not Processed"; "1" = "Processed" }

    # Configure any other global variables
    $script:observedTimeline = @()
}

Process {
    #region Functions
    Function RecordStatus() {
        param
        (
            [Parameter(Mandatory = $true)] [String] $detail,
            [Parameter(Mandatory = $true)] [String] $status,
            [Parameter(Mandatory = $true)] [String] $color,
            [Parameter(Mandatory = $true)] [datetime] $date
        )

        # See if there is already an entry for this policy and status
        $found = $script:observedTimeline | ? { $_.Detail -eq $detail -and $_.Status -eq $status }
        if (-not $found) {
            $script:observedTimeline += New-Object PSObject -Property @{
                "Date"   = $date
                "Detail" = $detail
                "Status" = $status
                "Color"  = $color
            }
        }
    }

    Function AddDisplay() {
        param
        (
            [Parameter(Mandatory = $true)] [ref]$items
        )
        $items.Value | % {
            Add-Member -InputObject $_ -NotePropertyName display -NotePropertyValue $AllSessions
        }
        $items.Value[$items.Value.Count - 1].display = $true
    }

    Function ProcessScriptsLog {
        if (!(Test-Path $agentExecutorLogFile -ErrorAction SilentlyContinue)) {
            return "Log $agentExecutorLogFile doesn't yet exist"
        }

        Get-Content $agentExecutorLogFile | Select-String "cmd line for running powershell is.*\\Microsoft Intune Management Extension\\Policies\\Scripts\\" -Context 0, 20 | % {
            $match = $_ -split "`n"

            $sid = ([regex]"([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})_([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})").Matches($match[0]).captures.groups[1].value
            $guid = ([regex]"([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})_([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})").Matches($match[0]).captures.groups[2].value

            $errorCode = ([regex]"Powershell exit code is (\d+)").Matches($match).captures.groups[1].value
            # $errorText = ([regex]"error from script = (.*)").Matches($match).captures.groups[1].value

            if ($Online) {
                $script = $scripts | ? { $_.Id -eq $guid }
                $script = "$($script.DisplayName) ($guid)"
            } else {
                $script = $guid
            }

            if ($sid -eq "00000000-0000-0000-0000-000000000000") {
                $runAs = "SYSTEM"
            } else {
                $runAs = $sid
            }

            "$script : ErrorCode: $errorCode RunAs: $runAs"
        }
    }

    Function ProcessRemediationScriptsLog {
        if (!(Test-Path $healthScriptsLogFile -ErrorAction SilentlyContinue)) {
            return "Log $healthScriptsLogFile doesn't yet exist"
        }

        $healthScriptsLog = Get-Content $healthScriptsLogFile

        $healthScriptsLog | % {
            $matches = $null

            if ($_ -match "$([regex]::Escape("<![LOG[[HS] new result = "))(.+)$([regex]::Escape("]LOG]!>"))<time=`"([0-9:.]+)`" date=`"([-0-9]+)`"") {
                $json = ConvertFrom-Json $matches[1]
                $time = $matches[2]
                $date = $matches[3]
                # $json | select PolicyId, Result, ErrorCode, ResultType, RemediationStatus, PreRemediationDetectScriptOutput, PreRemediationDetectScriptError
                # $time
                # $date

                if ($Online) {
                    $remScript = $remediationScripts | ? { $_.Id -eq $json.PolicyId }
                    $remScript = "$($remScript.DisplayName) ($($json.PolicyId))"
                } else {
                    $remScript = $json.PolicyId
                }

                "$remScript : Result: $($json.Result) ErrorCode: $($json.ErrorCode) RemediationStatus: $($json.RemediationStatus)"
            }
        }
    }

    Function ProcessAppsLog {
        if (!(Test-Path $appActionProcessorLogFile -ErrorAction SilentlyContinue)) {
            return "Log $appActionProcessorLogFile doesn't yet exist"
        }

        $appActionProcessorLog = Get-Content $appActionProcessorLogFile
        # processed applications
        $processedGuid = @()
        # process apps that should be installed
        $appActionProcessorLog | % {
            $matches = $null

            if ($_ -match "$([regex]::Escape("<![LOG[[Win32App][ActionProcessor] App with id:")) ([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}) to install ([^]]+)") {

                $guid = $matches[1]
                $result = $matches[2]

                if ($result -eq "has previously been selected for enforcement. The app will not be enforced.") {
                    $result = "Should install"
                } else {
                    $result = "Shouldn't install ($result)" -replace ". The app will not be enforced."
                }

                if ($Online) {
                    $app = $apps | ? { $_.Id -eq $guid }
                    $app = "$($app.DisplayName) ($guid)"
                } else {
                    $app = $guid
                }

                if ($guid -notin $processedGuid) {
                    [PSCustomObject]@{
                        App    = $app
                        Result = $result
                    }

                    $processedGuid += $guid
                }
            } else {
                # not interested in this line
            }
        }

        $appActionProcessorLog | % {
            $matches = $null

            if (($_ -match "$([regex]::Escape("<![LOG[[Win32App][ActionProcessor]")) App with id: ([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}), targeted intent: (\w+), and enforceability: (\w+) has projected enforcement classification: (\w+) with desired state: (\w+)") -or ($_ -match "$([regex]::Escape("<![LOG[[Win32App][ActionProcessor]")) App with id: ([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}), effective intent: (\w+), and enforceability: (\w+) has projected enforcement classification: (\w+) with desired state: (\w+)")) {
                $guid = $matches[1]
                $targetedIntent = $matches[2]
                $enforceability = $matches[3]
                $enforcementClassification = $matches[4]
                $desiredState = $matches[5]

                if ($Online) {
                    $app = $apps | ? { $_.Id -eq $guid }
                    $app = "$($app.DisplayName) ($guid)"
                } else {
                    $app = $guid
                }

                if ($guid -notin $processedGuid) {
                    [PSCustomObject]@{
                        App    = $app
                        Result = "Shouldn't install (enfClassification: $enforcementClassification desiredState: $desiredState targetedIntent: $targetedIntent enforceability: $enforceability)"
                    }

                    $processedGuid += $guid
                }
            } else {
                # not interested in this line
            }
        }
    }

    Function ProcessApps() {
        param
        (
            [Parameter(Mandatory = $true, ValueFromPipeline = $True)] [Microsoft.Win32.RegistryKey] $currentKey,
            [Parameter(Mandatory = $true)] $currentUser,
            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True)] [bool] $display
        )

        Begin {
            if ($display) { Write-Host "Apps:" }
        }

        Process {
            if ($display) { Write-Host "  $(([datetime]$currentKey.PSChildName).ToString('u'))" }
            $currentKey.Property | % {
                if ($_.StartsWith("./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/")) {
                    $msiKey = [URI]::UnescapeDataString(($_.Split("/"))[6])
                    $fullPath = "$msiPath\$currentUser\MSI\$msiKey"
                    if (Test-Path $fullPath) {
                        $status = (Get-ItemProperty -Path $fullPath).Status
                        $msiFile = (Get-ItemProperty -Path $fullPath).CurrentDownloadUrl
                    }
                    if ($status -eq "" -or $status -eq $null) {
                        $status = 0
                    }
                    if ($msiFile -match "IntuneWindowsAgent.msi") {
                        $msiKey = "Intune Management Extensions ($($msiKey))"
                    } elseif ($Online) {
                        $found = $apps | ? { $_.ProductCode -contains $msiKey }
                        $msiKey = "$($found.DisplayName) ($($msiKey))"
                    }
                    if ($status -eq 70) {
                        if ($display) { Write-Host "    MSI $msiKey : $status ($($officeStatus[$status.ToString()]))" -ForegroundColor Green }
                        RecordStatus -detail "MSI $msiKey" -status $officeStatus[$status.ToString()] -color "Green" -date $currentKey.PSChildName
                    } elseif ($status -eq 60) {
                        if ($display) { Write-Host "    MSI $msiKey : $status ($($officeStatus[$status.ToString()]))" -ForegroundColor Red }
                        RecordStatus -detail "MSI $msiKey" -status $officeStatus[$status.ToString()] -color "Red" -date $currentKey.PSChildName
                    } else {
                        if ($display) { Write-Host "    MSI $msiKey : $status ($($officeStatus[$status.ToString()]))" -ForegroundColor Yellow }
                        RecordStatus -detail "MSI $msiKey" -status $officeStatus[$status.ToString()] -color "Yellow" -date $currentKey.PSChildName
                    }
                } elseif ($_.StartsWith("./Vendor/MSFT/Office/Installation/")) {
                    # Report the main status based on what ESP is tracking
                    $status = Get-ItemPropertyValue -Path $currentKey.PSPath -Name $_

                    # Then try to get the detailed Office status
                    $officeKey = [URI]::UnescapeDataString(($_.Split("/"))[5])
                    $fullPath = "$officepath\$officeKey"
                    if (Test-Path $fullPath) {
                        $oStatus = (Get-ItemProperty -Path $fullPath).FinalStatus

                        if ($oStatus -eq $null) {
                            $oStatus = (Get-ItemProperty -Path $fullPath).Status
                            if ($oStatus -eq $null) {
                                $oStatus = "None"
                            }
                        }
                    } else {
                        $oStatus = "None"
                    }
                    if ($officeStatus.Keys -contains $oStatus.ToString()) {
                        $officeStatusText = $officeStatus[$oStatus.ToString()]
                    } else {
                        $officeStatusText = $oStatus
                    }
                    if ($status -eq 1) {
                        if ($display) { Write-Host "    Office $officeKey : $status ($($policyStatus[$status.ToString()]) / $officeStatusText)" -ForegroundColor Green }
                        RecordStatus -detail "Office $officeKey" -status "$($policyStatus[$status.ToString()]) / $officeStatusText" -color "Green" -date $currentKey.PSChildName
                    } else {
                        if ($display) { Write-Host "    Office $officeKey : $status ($($policyStatus[$status.ToString()]) / $officeStatusText)" -ForegroundColor Yellow }
                        RecordStatus -detail "Office $officeKey" -status "$($policyStatus[$status.ToString()]) / $officeStatusText" -color "Yellow" -date $currentKey.PSChildName
                    }
                } else {
                    if ($display) { Write-Host "    $_ : Unknown app" }
                }
            }
        }

    }

    Function ProcessModernApps() {
        param
        (
            [Parameter(Mandatory = $true, ValueFromPipeline = $True)] [Microsoft.Win32.RegistryKey] $currentKey,
            [Parameter(Mandatory = $true)] $currentUser,
            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True)] [bool] $display
        )

        Begin {
            if ($display) { Write-Host "Modern Apps:" }
        }

        Process {
            if ($display) { Write-Host "  $(([datetime]$currentKey.PSChildName).ToString('u'))" }
            $currentKey.Property | % {
                $status = (Get-ItemPropertyValue -Path $currentKey.PSPath -Name $_).ToString()
                if ($_.StartsWith("./User/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/")) {
                    $appID = [URI]::UnescapeDataString(($_.Split("/"))[7])
                    $type = "User UWP"
                } elseif ($_.StartsWith("./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/")) {
                    $appID = [URI]::UnescapeDataString(($_.Split("/"))[7])
                    $type = "Device UWP"
                } else {
                    $appID = $_
                    $type = "Unknown UWP"
                }
                if ($status -eq "1") {
                    if ($display) { Write-Host "    $type $appID : $status ($($policyStatus[$status]))" -ForegroundColor Green }
                    RecordStatus -detail "UWP $appID" -status $policyStatus[$status] -color "Green" -date $currentKey.PSChildName
                } else {
                    if ($display) { Write-Host "    $type $appID : $status ($($policyStatus[$status]))" -ForegroundColor Yellow }
                }
            }
        }

    }

    Function ProcessSidecar() {
        param
        (
            [Parameter(Mandatory = $true, ValueFromPipeline = $True)] [Microsoft.Win32.RegistryKey] $currentKey,
            [Parameter(Mandatory = $true)] $currentUser,
            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True)] [bool] $display
        )

        Begin {
            if ($display) { Write-Host "Sidecar apps:" }
        }

        Process {
            if ($currentKey.PSChildName -eq "LastLoggedState") {
                return
            }

            if ($display) { Write-Host "  $(([datetime]$currentKey.PSChildName).ToString('u'))" }
            $currentKey.Property | % {
                $win32Key = [URI]::UnescapeDataString(($_.Split("/"))[9])
                $status = Get-ItemPropertyValue -Path $currentKey.PSPath -Name $_
                if ($Online) {
                    $found = $apps | ? { $win32Key -match $_.Id }
                    $win32Key = "$($found.DisplayName) ($($win32Key))"
                }
                $appGuid = $win32Key.Substring(9)
                $sidecarApp = "$sidecarPath\$currentUser\$appGuid"
                $exitCode = $null
                if (Test-Path $sidecarApp) {
                    $exitCode = (Get-ItemProperty -Path $sidecarApp).ExitCode
                }
                if ($status -eq "3") {
                    if ($exitCode -ne $null) {
                        if ($display) { Write-Host "    Win32 $win32Key : $status ($($espStatus[$status.ToString()]), rc = $exitCode)" -ForegroundColor Green }
                    } else {
                        if ($display) { Write-Host "    Win32 $win32Key : $status ($($espStatus[$status.ToString()]))" -ForegroundColor Green }
                    }
                    RecordStatus -detail "Win32 $win32Key" -status $espStatus[$status.ToString()] -color "Green" -date $currentKey.PSChildName
                } elseif ($status -eq "4") {
                    if ($exitCode -ne $null) {
                        if ($display) { Write-Host "    Win32 $win32Key : $status ($($espStatus[$status.ToString()]), rc = $exitCode)" -ForegroundColor Red }
                    } else {
                        if ($display) { Write-Host "    Win32 $win32Key : $status ($($espStatus[$status.ToString()]))" -ForegroundColor Red }
                    }
                    RecordStatus -detail "Win32 $win32Key" -status $espStatus[$status.ToString()] -color "Red" -date $currentKey.PSChildName
                } else {
                    if ($exitCode -ne $null) {
                        if ($display) { Write-Host "    Win32 $win32Key : $status ($($espStatus[$status.ToString()]), rc = $exitCode)" -ForegroundColor Yellow }
                    } else {
                        if ($display) { Write-Host "    Win32 $win32Key : $status ($($espStatus[$status.ToString()]))" -ForegroundColor Yellow }
                    }
                    if ($status -ne "1") {
                        RecordStatus -detail "Win32 $win32Key" -status $espStatus[$status.ToString()] -color "Yellow" -date $currentKey.PSChildName
                    }
                }
            }
        }

    }

    Function ProcessPolicies() {
        param
        (
            [Parameter(Mandatory = $true, ValueFromPipeline = $True)] [Microsoft.Win32.RegistryKey] $currentKey,
            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True)] [bool] $display
        )

        Begin {
            if ($display) { Write-Host "Policies:" }
        }

        Process {
            if ($display) { Write-Host "  $(([datetime]$currentKey.PSChildName).ToString('u'))" }
            $currentKey.Property | % {
                $status = Get-ItemPropertyValue -Path $currentKey.PSPath -Name $_
                if ($status -eq "1") {
                    if ($display) { Write-Host "    Policy $_ : $status ($($policyStatus[$status.ToString()]))" -ForegroundColor Green }
                    RecordStatus -detail "Policy $_" -status $policyStatus[$status.ToString()] -color "Green" -date $currentKey.PSChildName
                } else {
                    if ($display) { Write-Host "    Policy $_ : $status ($($policyStatus[$status.ToString()]))" -ForegroundColor Yellow }
                }
            }
        }

    }

    Function ProcessCerts() {
        param
        (
            [Parameter(Mandatory = $true, ValueFromPipeline = $True)] [Microsoft.Win32.RegistryKey] $currentKey,
            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True)] [bool] $display
        )

        Begin {
            if ($display) { Write-Host "Certificates:" }
        }

        Process {
            if ($display) { Write-Host "  $(([datetime]$currentKey.PSChildName).ToString('u'))" }
            $currentKey.Property | % {
                $certKey = [URI]::UnescapeDataString(($_.Split("/"))[6])
                $status = Get-ItemPropertyValue -Path $currentKey.PSPath -Name $_
                if ($Online) {
                    $found = $policies | ? { $certKey.Replace("_", "-") -match $_.Id }
                    $certKey = "$($found.DisplayName) ($($certKey))"
                }
                if ($status -eq "1") {
                    if ($display) { Write-Host "    Cert $certKey : $status ($($policyStatus[$status.ToString()]))" -ForegroundColor Green }
                    RecordStatus -detail "Cert $certKey" -status $policyStatus[$status.ToString()] -color "Green" -date $currentKey.PSChildName
                } else {
                    if ($display) { Write-Host "    Cert $certKey : $status ($($policyStatus[$status.ToString()]))" -ForegroundColor Yellow }
                }
            }
        }

    }

    Function ProcessNodeCache() {

        Process {
            $nodeCount = 0
            while ($true) {
                # Get the nodes in order.  This won't work after a while because the older numbers are deleted as new ones are added
                # but it will work out OK shortly after provisioning.  The alternative would be to get all the subkeys and then sort
                # them numerically instead of alphabetically, but that can be saved for later...
                $node = Get-ItemProperty "$provisioningPath\NodeCache\CSP\Device\MS DM Server\Nodes\$nodeCount" -ErrorAction SilentlyContinue
                if ($node -eq $null) {
                    break
                }
                $nodeCount += 1
                $node | select NodeUri, ExpectedValue
            }
        }

    }

    Function ProcessEvents() {

        Process {

            $productCode = 'IME-Not-Yet-Installed'
            if (Test-Path "$msiPath\S-0-0-00-0000000000-0000000000-000000000-000\MSI") {
                Get-ChildItem -Path "$msiPath\S-0-0-00-0000000000-0000000000-000000000-000\MSI" | % {
                    $file = (Get-ItemProperty -Path $_.PSPath).CurrentDownloadUrl
                    if ($file -match "IntuneWindowsAgent.msi") {
                        $productCode = Get-ItemPropertyValue -Path $_.PSPath -Name ProductCode
                    }
                }
            }

            # Process device management events
            if ($script:useFile) {
                $events = Get-WinEvent -Path "$($env:TEMP)\ESPStatus.tmp\microsoft-windows-devicemanagement-enterprise-diagnostics-provider-admin.evtx" -Oldest | ? { ($_.Message -match $productCode -and $_.Id -in 1905, 1906, 1920, 1922) -or $_.Id -in (72, 100, 107, 109, 110, 111) }
            } else {
                $events = Get-WinEvent -LogName Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin -Oldest | ? { ($_.Message -match $productCode -and $_.Id -in 1905, 1906, 1920, 1922) -or $_.Id -in (72, 100, 107, 109, 110, 111) }
            }
            $events | % {
                $message = $_.Message
                $detail = "Sidecar"
                $color = "Yellow"
                $event = $_
                switch ($_.id) {
                    { $_ -in (110, 109) } {
                        $detail = "Offline Domain Join"
                        switch ($event.Properties[0].Value) {
                            0 { $message = "Offline domain join not configured" }
                            1 { $message = "Waiting for ODJ blob" }
                            2 { $message = "Processed ODJ blob" }
                            3 { $message = "Timed out waiting for ODJ blob or connectivity" }
                        }
                    }
                    111 { $detail = "Offline Domain Join"; $message = "Starting wait for ODJ blob" }
                    107 { $detail = "Offline Domain Join"; $message = "Successfully applied ODJ blob" }
                    100 { $detail = "Offline Domain Join"; $message = "Could not establish connectivity"; $color = "Red" }
                    72 { $detail = "MDM Enrollment" }
                    1905 { $message = "Download started" }
                    1906 { $message = "Download finished" }
                    1920 { $message = "Installation started" }
                    1922 { $message = "Installation finished" }
                    { $_ -in (1922, 72) } { $color = "Green" }
                }
                RecordStatus -detail $detail -date $_.TimeCreated -status $message -color $color
            }

            # Process device registration events
            if ($script:useFile) {
                $events = Get-WinEvent -Path "$($env:TEMP)\ESPStatus.tmp\microsoft-windows-user device registration-admin.evtx" -Oldest | ? { $_.Id -in (306, 101) }
            } else {
                $events = Get-WinEvent -LogName 'Microsoft-Windows-User Device Registration/Admin' -Oldest | ? { $_.Id -in (306, 101) }
            }
            $events | % {
                $message = $_.Message
                $detail = "Device Registration"
                $color = "Yellow"
                $event = $_
                switch ($_.id) {
                    101 { $detail = "Device Registration"; $message = "SCP discovery successful." }
                    304 { $detail = "Device Registration"; $message = "Hybrid AADJ device registration failed." }
                    306 { $detail = "Device Registration"; $message = "Hybrid AADJ device registration succeeded."; $color = 'Green' }
                }
                RecordStatus -detail $detail -date $_.TimeCreated -status $message -color $color
            }

        }

    }

    Function GetIntuneObjects() {
        param
        (
            [Parameter(Mandatory = $true)] [String] $uri
        )

        Process {

            Write-Verbose "GET $uri"
            try {
                $response = Invoke-MSGraphRequest -Url $uri -HttpMethod Get

                $objects = $response.value
                $objectsNextLink = $response."@odata.nextLink"

                while ($objectsNextLink -ne $null) {
                    $response = (Invoke-MSGraphRequest -Url $objectsNextLink -HttpMethod Get)
                    $objectsNextLink = $response."@odata.nextLink"
                    $objects += $response.value
                }

                return $objects
            } catch {
                Write-Error $_.Exception
                return $null
                break
            }

        }
    }
    #endregion Functions

    #------------------------
    # Main code
    #------------------------

    # If online, make sure we are able to authenticate
    if ($Online) {

        # Make sure we can connect
        $module = Import-Module Microsoft.Graph.Intune -PassThru -ErrorAction Ignore
        if (-not $module) {
            Write-Host "Installing module Microsoft.Graph.Intune"
            Install-Module Microsoft.Graph.Intune -Force
        }
        Import-Module Microsoft.Graph.Intune
        $graph = Connect-MSGraph
        Write-Host "Connected to tenant $($graph.TenantId)"

        # Get a list of apps
        Write-Host "Getting list of apps"
        $script:apps = GetIntuneObjects("https://graph.microsoft.com/beta/deviceAppManagement/mobileApps")

        Write-Host "Getting list of scripts"
        $script:scripts = GetIntuneObjects("https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts")

        Write-Host "Getting list of remediation scripts"
        $script:remediationScripts = GetIntuneObjects("https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts")

        # Get a list of policies (for certs)
        Write-Host "Getting list of policies"
        $script:policies = GetIntuneObjects("https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations")
    }

    # Display Autopilot diag details
    Write-Host ""
    Write-Host "AUTOPILOT DIAGNOSTICS" -ForegroundColor Magenta
    Write-Host ""

    $values = Get-ItemProperty "$autopilotDiagPath"
    if (-not $values.CloudAssignedTenantId) {
        Write-Host "This is not an Autopilot device.`n"
        exit 0
    }

    if (-not $script:useFile) {
        $osVersion = (Get-WmiObject win32_operatingsystem).Version
        Write-Host "OS version:               $osVersion"
    }
    Write-Host "Profile:                  $($values.DeploymentProfileName)"
    Write-Host "TenantDomain:             $($values.CloudAssignedTenantDomain)"
    Write-Host "TenantID:                 $($values.CloudAssignedTenantId)"
    $correlations = Get-ItemProperty "$autopilotDiagPath\EstablishedCorrelations"
    Write-Host "ZTDID:                    $($correlations.ZTDRegistrationID)"
    Write-Host "EntDMID:                  $($correlations.EntDMID)"

    Write-Host "OobeConfig:               $($values.CloudAssignedOobeConfig)"

    if (($values.CloudAssignedOobeConfig -band 1024) -gt 0) {
        Write-Host " Skip keyboard:           Yes   1 - - - - - - - - - -"
    } else {
        Write-Host " Skip keyboard:           No    0 - - - - - - - - - -"
    }
    if (($values.CloudAssignedOobeConfig -band 512) -gt 0) {
        Write-Host " Enable patch download:   Yes   - 1 - - - - - - - - -"
    } else {
        Write-Host " Enable patch download:   No    - 0 - - - - - - - - -"
    }
    if (($values.CloudAssignedOobeConfig -band 256) -gt 0) {
        Write-Host " Skip Windows upgrade UX: Yes   - - 1 - - - - - - - -"
    } else {
        Write-Host " Skip Windows upgrade UX: No    - - 0 - - - - - - - -"
    }
    if (($values.CloudAssignedOobeConfig -band 128) -gt 0) {
        Write-Host " AAD TPM Required:        Yes   - - - 1 - - - - - - -"
    } else {
        Write-Host " AAD TPM Required:        No    - - - 0 - - - - - - -"
    }
    if (($values.CloudAssignedOobeConfig -band 64) -gt 0) {
        Write-Host " AAD device auth:         Yes   - - - - 1 - - - - - -"
    } else {
        Write-Host " AAD device auth:         No    - - - - 0 - - - - - -"
    }
    if (($values.CloudAssignedOobeConfig -band 32) -gt 0) {
        Write-Host " TPM attestation:         Yes   - - - - - 1 - - - - -"
    } else {
        Write-Host " TPM attestation:         No    - - - - - 0 - - - - -"
    }
    if (($values.CloudAssignedOobeConfig -band 16) -gt 0) {
        Write-Host " Skip EULA:               Yes   - - - - - - 1 - - - -"
    } else {
        Write-Host " Skip EULA:               No    - - - - - - 0 - - - -"
    }
    if (($values.CloudAssignedOobeConfig -band 8) -gt 0) {
        Write-Host " Skip OEM registration:   Yes   - - - - - - - 1 - - -"
    } else {
        Write-Host " Skip OEM registration:   No    - - - - - - - 0 - - -"
    }
    if (($values.CloudAssignedOobeConfig -band 4) -gt 0) {
        Write-Host " Skip express settings:   Yes   - - - - - - - - 1 - -"
    } else {
        Write-Host " Skip express settings:   No    - - - - - - - - 0 - -"
    }
    if (($values.CloudAssignedOobeConfig -band 2) -gt 0) {
        Write-Host " Disallow admin:          Yes   - - - - - - - - - 1 -"
    } else {
        Write-Host " Disallow admin:          No    - - - - - - - - - 0 -"
    }

    # In theory we could read these values from the profile cache registry key, but it's so bungled
    # up in the registry export that it doesn't import without some serious massaging for embedded
    # quotes.  So this is easier.
    if ($script:useFile) {
        $jsonFile = "$($env:TEMP)\ESPStatus.tmp\AutopilotDDSZTDFile.json"
    } else {
        $jsonFile = "$($env:WINDIR)\ServiceState\wmansvc\AutopilotDDSZTDFile.json"
    }
    if (Test-Path $jsonFile) {
        $json = Get-Content $jsonFile | ConvertFrom-Json
        $date = [datetime]$json.PolicyDownloadDate
        RecordStatus -date $date -detail "Autopilot profile" -status "Profile downloaded" -color "Yellow"
        if ($json.CloudAssignedDomainJoinMethod -eq 1) {
            Write-Host "Scenario:                 Hybrid Azure AD Join"
            if (Test-Path "$omadmPath\SyncML\ODJApplied") {
                Write-Host "ODJ applied:              Yes"
            } else {
                Write-Host "ODJ applied:              No"
            }
            if ($json.HybridJoinSkipDCConnectivityCheck -eq 1) {
                Write-Host "Skip connectivity check:  Yes"
            } else {
                Write-Host "Skip connectivity check:  No"
            }

        } else {
            Write-Host "Scenario:                 Azure AD Join"
        }
    } else {
        Write-Host "Scenario:                 Not available (JSON not found)"
    }

    # Get ESP properties
    Get-ChildItem $enrollmentsPath | ? { Test-Path "$($_.PSPath)\FirstSync" } | % {
        $properties = Get-ItemProperty "$($_.PSPath)\FirstSync"
        Write-Host "Enrollment status page:"
        Write-Host " Device ESP enabled:      $($properties.SkipDeviceStatusPage -eq 0)"
        Write-Host " User ESP enabled:        $($properties.SkipUserStatusPage -eq 0)"
        Write-Host " ESP timeout:             $($properties.SyncFailureTimeout)"
        if ($properties.BlockInStatusPage -eq 0) {
            Write-Host " ESP blocking:            No"
        } else {
            Write-Host " ESP blocking:            Yes"
            if ($properties.BlockInStatusPage -band 1) {
                Write-Host " ESP allow reset:         Yes"
            }
            if ($properties.BlockInStatusPage -band 2) {
                Write-Host " ESP allow try again:     Yes"
            }
            if ($properties.BlockInStatusPage -band 4) {
                Write-Host " ESP continue anyway:     Yes"
            }
        }
    }

    # Get Delivery Optimization statistics (when available)
    if (-not $script:useFile) {
        $stats = Get-DeliveryOptimizationPerfSnapThisMonth
        if ($stats.DownloadHttpBytes -ne 0) {
            $peerPct = [math]::Round( ($stats.DownloadLanBytes / $stats.DownloadHttpBytes) * 100 )
            $ccPct = [math]::Round( ($stats.DownloadCacheHostBytes / $stats.DownloadHttpBytes) * 100 )
        } else {
            $peerPct = 0
            $ccPct = 0
        }
        Write-Host "Delivery Optimization statistics:"
        Write-Host " Total bytes downloaded:  $($stats.DownloadHttpBytes)"
        Write-Host " From peers:              $($peerPct)% ($($stats.DownloadLanBytes))"
        Write-Host " From Connected Cache:    $($ccPct)% ($($stats.DownloadCacheHostBytes))"
    }

    # If the ADK is installed, get some key hardware hash info
    $adkPath = Get-ItemPropertyValue "HKLM:\Software\Microsoft\Windows Kits\Installed Roots" -Name KitsRoot10 -ErrorAction SilentlyContinue
    $oa3Tool = "$adkPath\Assessment and Deployment Kit\Deployment Tools\$($env:PROCESSOR_ARCHITECTURE)\Licensing\OA30\oa3tool.exe"
    if ($hash -and (Test-Path $oa3Tool)) {
        $commandLineArgs = "/decodehwhash:$hash"
        $output = & "$oa3Tool" $commandLineArgs
        [xml] $hashXML = $output | select -Skip 8 -First ($output.Count - 12)
        Write-Host "Hardware information:"
        Write-Host " Operating system build: " $hashXML.SelectSingleNode("//p[@n='OsBuild']").v
        Write-Host " Manufacturer:           " $hashXML.SelectSingleNode("//p[@n='SmbiosSystemManufacturer']").v
        Write-Host " Model:                  " $hashXML.SelectSingleNode("//p[@n='SmbiosSystemProductName']").v
        Write-Host " Serial number:          " $hashXML.SelectSingleNode("//p[@n='SmbiosSystemSerialNumber']").v
        Write-Host " TPM version:            " $hashXML.SelectSingleNode("//p[@n='TPMVersion']").v
    }

    # Process event log info
    ProcessEvents

    # Display the list of policies
    if ($ShowPolicies) {
        Write-Host " "
        Write-Host "POLICIES PROCESSED" -ForegroundColor Magenta
        ProcessNodeCache | Format-Table -Wrap
    }

    # Make sure the tracking path exists
    if (Test-Path $path) {

        # Process device ESP sessions
        Write-Host " "
        Write-Host "DEVICE ESP:" -ForegroundColor Magenta
        Write-Host " "

        if (Test-Path "$path\ExpectedPolicies") {
            [array]$items = Get-ChildItem "$path\ExpectedPolicies"
            AddDisplay ([ref]$items)
            $items | ProcessPolicies
        }
        if (Test-Path "$path\ExpectedMSIAppPackages") {
            [array]$items = Get-ChildItem "$path\ExpectedMSIAppPackages"
            AddDisplay ([ref]$items)
            $items | ProcessApps -currentUser "S-0-0-00-0000000000-0000000000-000000000-000"
        }
        if (Test-Path "$path\ExpectedModernAppPackages") {
            [array]$items = Get-ChildItem "$path\ExpectedModernAppPackages"
            AddDisplay ([ref]$items)
            $items | ProcessModernApps -currentUser "S-0-0-00-0000000000-0000000000-000000000-000"
        }
        if (Test-Path "$path\Sidecar") {
            [array]$items = Get-ChildItem "$path\Sidecar" | ? { $_.Property -match "./Device" }
            AddDisplay ([ref]$items)
            $items | ProcessSidecar -currentUser "00000000-0000-0000-0000-000000000000"
        }
        if (Test-Path "$path\ExpectedSCEPCerts") {
            [array]$items = Get-ChildItem "$path\ExpectedSCEPCerts"
            AddDisplay ([ref]$items)
            $items | ProcessCerts
        }

        # Process user ESP sessions
        Get-ChildItem "$path" | ? { $_.PSChildName.StartsWith("S-") } | % {
            $userPath = $_.PSPath
            $userSid = $_.PSChildName
            Write-Host " "
            Write-Host "USER ESP for $($userSid):" -ForegroundColor Magenta
            Write-Host " "
            if (Test-Path "$userPath\ExpectedPolicies") {
                [array]$items = Get-ChildItem "$userPath\ExpectedPolicies"
                AddDisplay ([ref]$items)
                $items | ProcessPolicies
            }
            if (Test-Path "$userPath\ExpectedMSIAppPackages") {
                [array]$items = Get-ChildItem "$userPath\ExpectedMSIAppPackages"
                AddDisplay ([ref]$items)
                $items | ProcessApps -currentUser $userSid
            }
            if (Test-Path "$userPath\ExpectedModernAppPackages") {
                [array]$items = Get-ChildItem "$userPath\ExpectedModernAppPackages"
                AddDisplay ([ref]$items)
                $items | ProcessModernApps -currentUser $userSid
            }
            if (Test-Path "$userPath\Sidecar") {
                [array]$items = Get-ChildItem "$path\Sidecar" | ? { $_.Property -match "./User" }
                AddDisplay ([ref]$items)
                $items | ProcessSidecar -currentUser $userSid
            }
            if (Test-Path "$userPath\ExpectedSCEPCerts") {
                [array]$items = Get-ChildItem "$userPath\ExpectedSCEPCerts"
                AddDisplay ([ref]$items)
                $items | ProcessCerts
            }
        }

        # Process Applications log
        Write-Host " "
        Write-Host "APPLICATION DEPLOYMENT DETAILS:" -ForegroundColor Magenta
        Write-Host " "
        ProcessAppsLog | Sort-Object -Property App | Out-String
        Write-Host ""

        # Process Scripts log
        Write-Host " "
        Write-Host "INVOKED PSH SCRIPT DETAILS:" -ForegroundColor Magenta
        Write-Host " "
        ProcessScriptsLog | Sort-Object | Out-String
        Write-Host ""

        # Process Remediation scripts log
        Write-Host " "
        Write-Host "INVOKED REMEDIATION SCRIPT DETAILS:" -ForegroundColor Magenta
        Write-Host " "
        ProcessRemediationScriptsLog | Sort-Object | Out-String
        Write-Host ""
    } else {
        Write-Host "ESP diagnostics info does not (yet) exist."
    }

    # Display timeline
    Write-Host ""
    Write-Host "OBSERVED TIMELINE:" -ForegroundColor Magenta
    Write-Host ""
    $observedTimeline | Sort-Object -Property Date |
        Format-Table @{
            Label      = "Date"
            Expression = { $_.Date.ToString("u") }
        },
        @{
            Label      = "Status"
            Expression =
            {
                switch ($_.Color) {
                    'Red' { $color = "91"; break }
                    'Yellow' { $color = '93'; break }
                    'Green' { $color = "92"; break }
                    default { $color = "0" }
                }
                $e = [char]27
                "$e[${color}m$($_.Status)$e[0m"
            }
        },
        Detail

    Write-Host ""
}

End {

    # Remove the registry info if it exists
    if (Test-Path "HKCU:\ESPStatus.tmp") {
        Remove-Item -Path "HKCU:\ESPStatus.tmp" -Recurse -Force
    }
}
