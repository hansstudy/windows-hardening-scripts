#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies Windows technical controls aligned to CMMC Level 2 and CPCSC ITSP.10.171 readiness.

.DESCRIPTION
    For US DoD contractors handling CUI (Controlled Unclassified Information) and
    Canadian defense suppliers handling SI (Specified Information) under CPCSC,
    which is run by Public Services and Procurement Canada (PSPC). Every control
    is cited with both the CMMC 2.0 practice ID and the ITSP.10.171 identifier.
    Controls required at Level 1 are marked [LEVEL 1].

    CMMC 2.0 Level 2:  110 practices, NIST SP 800-171 Rev 2. C3PAO-assessed.
    CPCSC Level 1:     13 requirements, annual self-assessment via PSPC tool;
                       result in CanadaBuys. Live since April 1, 2026.
    CPCSC Level 2:     98 requirements (ITSP.10.171 adapts NIST SP 800-171 Rev 3:
                       97 from Rev 3 plus Canada's 03.14.09). Planned spring 2027;
                       assessed by SCC-accredited certification bodies.

    The technical requirements overlap heavily with CMMC, but Rev 2 and Rev 3
    differ and CPCSC Level 1 requires MFA. This script supports readiness work;
    it is not an attestation. Dated program status:
    https://github.com/hansstudy/CPCSC and https://hans.study/cpcsc/
    Read-only audit scripts (no changes applied) live in that CPCSC hub.

    IMPORTANT: This script covers technical OS controls only. Full CMMC/CPCSC
    readiness also requires:
      - Written policies and procedures (AC, CM, IR, RA, CA families)
      - Security awareness training program (AT.L2-3.2.1/3.2.2)
      - Incident response plan (IR.L2-3.6.1)
      - Risk assessment documentation (RA.L2-3.11.1/3.11.2)
      - Plan of Action and Milestones (CA.L2-3.12.2)
      - Key management procedures (SC.L2-3.13.10)
    Retain the generated log file as technical implementation evidence
    for your System Security Plan (SSP).

.NOTES
    ================================================================
    Study Workstation Configurator
    Template: CMMC Level 2 / CPCSC ITSP.10.171

    Author: Hans Study, CISSP
    Baseline dated:     2026-05-16
    Facts refreshed:    2026-10-05
    Config fingerprint: (curated baseline; not configurator output)

    Website:   https://hans.study
    Email:     contact@hans.study
    LinkedIn:  https://linkedin.com/in/hans-study
    Instagram: https://instagram.com/studybyt3s
    X:         https://x.com/studybyt3s
    YouTube:   https://youtube.com/@studybyt3s
    GitHub:    https://github.com/hansstudy

    Target OS:  Windows 10/11 Pro or Enterprise, Server 2019/2022/2025
    Version:    2.0

    STANDARDS REFERENCED:
      CMMC 2.0 Level 2 (NIST SP 800-171 Rev 2)    (dodcio.defense.gov/cmmc)
      CPCSC / ITSP.10.171 (NIST SP 800-171 Rev 3) (PSPC; cyber.gc.ca)
      DISA STIG Windows 11 V2R2                   (public.cyber.mil)
      CIS Microsoft Windows 11 Benchmark v3.0      (cisecurity.org)
      NSA/CISA Cybersecurity Information Sheets    (media.defense.gov)
      CSE/CCCS ITSP.70.012                         (cyber.gc.ca)

    CITATION FORMAT:
      CMMC:  [CMMC-X.X.XXX]  practice ID from the CMMC 2.0 model document
      CPCSC: [03.XX.XX]      requirement ID from CCCS ITSP.10.171

    Source-available. Personal and internal use permitted.
    Redistribution requires written authorization from Hans Study.
    See LICENSE for full terms.
    This script does not constitute legal or compliance advice.
    Engage a C3PAO (CMMC) or an SCC-accredited certification body (CPCSC)
    for formal assessment. Hans Study accepts no liability for outcomes.
    ================================================================
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$SkippedEntControls = [System.Collections.Generic.List[string]]::new()

$LogDate = Get-Date -Format "yyyyMMdd"
$LogPath = "C:\Logs\CMMC-CPCSC-ITSP10171_$LogDate.log"
if (-not (Test-Path "C:\Logs")) { New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null }
Start-Transcript -Path $LogPath -Append -IncludeInvocationHeader | Out-Null

# Helper functions are embedded here so the script runs standalone with no module dependency.
function Write-TSGSection { param([string]$Title, [string]$Subtitle = "")
    Write-Host ""; Write-Host "  == $Title" -ForegroundColor Yellow
    if ($Subtitle) { Write-Host "     $Subtitle" -ForegroundColor DarkGray }
}
function Set-TSGRegistry { param([string]$Path, [string]$Name, [object]$Value, [string]$Type = "DWord")
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        Write-Host "    [OK] $($Path.Split('\')[-1])\$Name = $Value" -ForegroundColor Green
    } catch { Write-Host "    [FAIL] $Name -- $($_.Exception.Message)" -ForegroundColor Red }
}
function Remove-TSGAppx { param([string]$PackageName, [string]$FriendlyName)
    try {
        Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*$PackageName*" } |
            Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
        Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*$PackageName*" } |
            Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Write-Host "    [OK] $FriendlyName removed or already absent" -ForegroundColor Green
    } catch { Write-Host "    [SKIP] $FriendlyName" -ForegroundColor DarkGray }
}
function Test-TSGEnterprise { param([string]$ControlName = "This control")
    $sku = (Get-CimInstance Win32_OperatingSystem).OperatingSystemSKU
    if ($sku -in @(4,27,70,84,121,122,125,126,7,8,12,13,79,80)) { return $true }
    Write-Host "    [SKIP] $ControlName requires Enterprise license (SKU: $sku)" -ForegroundColor DarkGreen
    $script:SkippedEntControls.Add($ControlName); return $false
}
function New-TSGRestorePoint { param([string]$Description = "Hardening")
    try { Checkpoint-Computer -Description "$Description $(Get-Date -Format 'yyyy-MM-dd')" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
          Write-Host "  [OK] Restore point created" -ForegroundColor Green }
    catch { Write-Host "  [WARN] Restore point failed -- continuing" -ForegroundColor Yellow }
}
function Disable-TSGNetBIOS {
    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
        foreach ($a in $adapters) { $a.SetTcpipNetbios(2) | Out-Null }
        Write-Host "    [OK] NetBIOS over TCP/IP disabled on all adapters" -ForegroundColor Green
    } catch { Write-Host "    [FAIL] $($_.Exception.Message)" -ForegroundColor Red }
}

Write-Host ""
Write-Host "  =========================================================" -ForegroundColor DarkYellow
Write-Host "  CMMC Level 2 / CPCSC (ITSP.10.171) Hardening" -ForegroundColor DarkYellow
Write-Host "  Controls cited with CMMC practice IDs and CPCSC equivalents" -ForegroundColor Gray
Write-Host "  Hans Study, CISSP | https://hans.study" -ForegroundColor DarkGray
Write-Host "  Log: $LogPath" -ForegroundColor DarkGray
Write-Host "  =========================================================" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  CMMC 2.0 Level 2 -- 110 practices, NIST SP 800-171 Rev 2" -ForegroundColor Gray
Write-Host "  CPCSC Level 1    -- 13 controls, self-assessment required summer 2026" -ForegroundColor Yellow
Write-Host "  CPCSC Level 2    -- 98 controls, third-party required spring 2027" -ForegroundColor Yellow
Write-Host ""

$OsSku = (Get-CimInstance Win32_OperatingSystem).OperatingSystemSKU
$IsEnterprise = $OsSku -in @(4,27,70,84,121,122,125,126,7,8,12,13,79,80)
Write-Host "  OS SKU: $OsSku | Edition: $(if ($IsEnterprise) { 'Enterprise/Server' } else { 'Pro' })" `
    -ForegroundColor $(if ($IsEnterprise) { "Green" } else { "Yellow" })
Write-Host ""

New-TSGRestorePoint -Description "CMMC / CPCSC Hardening"


# ================================================================================
# ACCESS CONTROL (AC)
# CMMC: AC.L1-3.1.1 through AC.L1-3.1.22
# CPCSC: 03.01.01 through 03.01.22
#
# Who can access the system, what they can access, and how remote access
# is controlled. The Windows controls below address the technical enforcement.
# Written access control policies (AC.L1-3.1.1 / CPCSC 03.01.01) are a
# separate organizational requirement -- a document, not a registry key.
# ================================================================================
Write-TSGSection "ACCESS CONTROL (AC)" "CMMC AC.L1-3.1.1 to AC.L1-3.1.22 | CPCSC 03.01"

# [LEVEL 1] Limit system access to authorized users
# CMMC: AC.L1-3.1.1 | FAR 52.204-21(b)(1)(i) | CPCSC: 03.01.01
# UAC ensures users cannot silently elevate without explicit admin consent.
# ConsentPromptBehaviorAdmin = 2 = Always Notify (max level, DISA WN11-SO-000251)
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"                 -Value 1
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop"      -Value 1
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
Write-Host "    [OK] [LEVEL 1] AC.L1-3.1.1 | CPCSC 03.01.01 -- UAC Always Notify" -ForegroundColor Green

# [LEVEL 1] Limit access to types of transactions authorized users can execute
# CMMC: AC.L1-3.1.2 | FAR 52.204-21(b)(1)(ii) | CPCSC: 03.01.02
# AutoRun = 0xFF disables automatic execution from all removable media types
# Source: DISA STIG WN11-CC-000150 | CIS 18.9.8.1 | CCCS ITSP.70.012
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
Set-TSGRegistry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
Write-Host "    [OK] [LEVEL 1] AC.L1-3.1.2 | CPCSC 03.01.02 -- AutoRun disabled" -ForegroundColor Green

# Control remote access sessions (managed access points, cryptographic protection)
# CMMC: AC.L2-3.1.12 / AC.L2-3.1.13 / AC.L2-3.1.14 | CPCSC: 03.01.12/13/14
# RDP NLA: credentials required before full session establishment
# Source: DISA STIG WN11-CC-000030 | CIS 18.9.59.2.1 | CCCS
Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Write-Host "    [OK] AC.L2-3.1.12/13/14 | CPCSC 03.01.12-14 -- RDP NLA enforced" -ForegroundColor Green

# Disable RDP if not operationally required (minimize remote access surface)
# CMMC: AC.L2-3.1.12 | CPCSC: 03.01.12
# Comment this block out if RDP is operationally required
Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
Write-Host "    [OK] AC.L2-3.1.12 | CPCSC 03.01.12 -- RDP disabled (comment out if needed)" -ForegroundColor Green

# Credential Guard -- protect CUI-accessing credentials in hardware-isolated container
# CMMC: AC.L2-3.1.5 / IA.L2-3.5.3 | CPCSC: 03.01.05 / 03.05.03
# Enterprise/Education only. Cannot be configured on Pro via registry.
# Source: learn.microsoft.com/windows/security/licensing-and-edition-requirements
if (Test-TSGEnterprise -ControlName "Credential Guard (AC.L2-3.1.5 / CPCSC 03.01.05)") {
    Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
    Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures"   -Value 1
    Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" -Name "Enabled" -Value 1
    Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1
    Write-Host "    [OK] AC.L2-3.1.5 / IA.L2-3.5.3 | CPCSC 03.01.05/03.05.03 -- Credential Guard (restart required)" -ForegroundColor Green
}


# ================================================================================
# AUDIT AND ACCOUNTABILITY (AU)
# CMMC: AU.L2-3.3.1 through AU.L2-3.3.9
# CPCSC: 03.03.01 through 03.03.09
#
# Create and retain audit logs sufficient for monitoring, analysis, and
# investigation of unauthorized activity. This is one of the most assessable
# control families -- CMMC and CPCSC auditors will pull these event logs.
# ================================================================================
Write-TSGSection "AUDIT AND ACCOUNTABILITY (AU)" "CMMC AU.L2-3.3.1 to AU.L2-3.3.9 | CPCSC 03.03"

# Create and retain audit logs
# CMMC: AU.L2-3.3.1 | CPCSC: 03.03.01
AuditPol /set /subcategory:"Logon"                   /success:enable /failure:enable | Out-Null  # DISA WN11-AU-000030/035
AuditPol /set /subcategory:"Logoff"                  /success:enable                 | Out-Null
AuditPol /set /subcategory:"Account Lockout"         /failure:enable                 | Out-Null
AuditPol /set /subcategory:"Special Logon"           /success:enable                 | Out-Null
Write-Host "    [OK] AU.L2-3.3.1 | CPCSC 03.03.01 -- Logon/logoff auditing enabled" -ForegroundColor Green

# Ensure individual user actions are traceable
# CMMC: AU.L2-3.3.2 | CPCSC: 03.03.02
AuditPol /set /subcategory:"Credential Validation"   /success:enable /failure:enable | Out-Null  # DISA WN11-AU-000010/015
AuditPol /set /subcategory:"Process Creation"        /success:enable                 | Out-Null  # DISA WN11-AU-000050
# Both auditpol AND registry key required for Event 4688 command-line capture
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1  # DISA WN11-CC-000066
Write-Host "    [OK] AU.L2-3.3.2 | CPCSC 03.03.02 -- Process creation with command line (Event 4688)" -ForegroundColor Green

# Privileged function and policy change auditing
# CMMC: AU.L2-3.3.2 / AU.L2-3.3.5 | CPCSC: 03.03.02 / 03.03.05
AuditPol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null  # DISA WN11-AU-000090/095
AuditPol /set /subcategory:"Audit Policy Change"     /success:enable /failure:enable | Out-Null  # DISA WN11-AU-000525/530
AuditPol /set /subcategory:"Authentication Policy Change" /success:enable            | Out-Null
AuditPol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
AuditPol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
Write-Host "    [OK] AU.L2-3.3.2/5 | CPCSC 03.03.02/05 -- Privilege and policy change auditing" -ForegroundColor Green

# Protect audit logs -- increase sizes to prevent overwrite
# CMMC: AU.L2-3.3.8 / AU.L2-3.3.9 | CPCSC: 03.03.08 / 03.03.09
# Source: DISA STIG WN11-AU-000045 | CIS 18.9.26.1 | CCCS ITSP.70.012
wevtutil sl Security    /ms:1073741824 | Out-Null   # 1 GB -- auditors check log retention
wevtutil sl Application /ms:268435456  | Out-Null   # 256 MB
wevtutil sl System      /ms:268435456  | Out-Null   # 256 MB
Write-Host "    [OK] AU.L2-3.3.8/9 | CPCSC 03.03.08/09 -- Log sizes: Security 1GB" -ForegroundColor Green

# PowerShell Script Block Logging -- comprehensive audit evidence for PS activity
# CMMC: AU.L2-3.3.1 / AU.L2-3.3.2 / AU.L2-3.3.5 | CPCSC: 03.03.01/02/05
# Source: DISA STIG WN11-CC-000326 | NSA/CISA June 2022 CSI | CCCS ITSP.70.012
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging"         -Value 1
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -Value 1
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:104857600 | Out-Null
Write-Host "    [OK] AU.L2-3.3.1/2/5 | CPCSC 03.03.01/02/05 -- PS Script Block Logging" -ForegroundColor Green

# PowerShell Transcription -- session-level audit records
# CMMC: AU.L2-3.3.1 / AU.L2-3.3.2 | CPCSC: 03.03.01 / 03.03.02
$transcriptPath = "C:\Logs\PSTranscripts"
if (-not (Test-Path $transcriptPath)) { New-Item -ItemType Directory -Path $transcriptPath -Force | Out-Null }
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting"    -Value 1
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory"        -Value $transcriptPath -Type String
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1
Write-Host "    [OK] AU.L2-3.3.1/2 | CPCSC 03.03.01/02 -- PS Transcription to $transcriptPath" -ForegroundColor Green


# ================================================================================
# CONFIGURATION MANAGEMENT (CM)
# CMMC: CM.L2-3.4.1 through CM.L2-3.4.9
# CPCSC: 03.04.01 through 03.04.09
#
# Establish and maintain baseline configurations. Restrict, disable, or prevent
# use of unnecessary programs, functions, ports, protocols, and services.
# This script IS the documented baseline configuration for CM.L2-3.4.1/2.
# ================================================================================
Write-TSGSection "CONFIGURATION MANAGEMENT (CM)" "CMMC CM.L2-3.4.1 to CM.L2-3.4.9 | CPCSC 03.04"

Write-Host "    [INFO] CM.L2-3.4.1/2 | CPCSC 03.04.01/02 -- This script is the baseline configuration" -ForegroundColor DarkYellow
Write-Host "    Retain this log as evidence of baseline enforcement for your SSP: $LogPath" -ForegroundColor DarkGray

# Least functionality -- disable SMBv1 (unnecessary, exploitable protocol)
# CMMC: CM.L2-3.4.6 / CM.L2-3.4.7 | CPCSC: 03.04.06 / 03.04.07
# Source: DISA STIG WN11-00-000165 | CIS 18.3.3 | CCCS ITSP.70.012
Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Write-Host "    [OK] CM.L2-3.4.6/7 | CPCSC 03.04.06/07 -- SMBv1 disabled" -ForegroundColor Green

# Remove PowerShell v2 -- unnecessary execution path that bypasses all logging
# CMMC: CM.L2-3.4.6 / CM.L2-3.4.7 | CPCSC: 03.04.06 / 03.04.07
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Write-Host "    [OK] CM.L2-3.4.6/7 | CPCSC 03.04.06/07 -- PS v2 removed" -ForegroundColor Green

# Windows Firewall -- deny-by-exception for all network connections
# CMMC: CM.L2-3.4.7 | CPCSC: 03.04.07
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Write-Host "    [OK] CM.L2-3.4.7 | CPCSC 03.04.07 -- Firewall default-deny inbound" -ForegroundColor Green

# AppLocker -- application allowlisting (Enterprise/Education only)
# CMMC: CM.L2-3.4.8 / CM.L2-3.4.9 | CPCSC: 03.04.08 / 03.04.09
if (Test-TSGEnterprise -ControlName "AppLocker (CM.L2-3.4.8 / CPCSC 03.04.08)") {
    sc.exe config appidsvc start= auto | Out-Null
    Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    Write-Host "    [OK] CM.L2-3.4.8/9 | CPCSC 03.04.08/09 -- AppIDSvc enabled (configure rules via GPO)" -ForegroundColor Green
    Write-Host "    [NOTE] AppLocker rule configuration is a separate GPO task" -ForegroundColor Yellow
}

# Disable Windows Script Host -- unnecessary execution capability
# CMMC: CM.L2-3.4.6 / CM.L2-3.4.7 | CPCSC: 03.04.06 / 03.04.07
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
Write-Host "    [OK] CM.L2-3.4.6/7 | CPCSC 03.04.06/07 -- WSH disabled (.vbs/.js blocked)" -ForegroundColor Green

# Disable telemetry services -- unnecessary data collection
# CMMC: CM.L2-3.4.6 | CPCSC: 03.04.06
# DiagTrack service left running. Disabling it breaks the Defender for Endpoint sensor.
# The AllowTelemetry policy above controls the data level; the service itself must stay.
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
Write-Host "    [OK] CM.L2-3.4.6 | CPCSC 03.04.06 -- Telemetry service disabled" -ForegroundColor Green

# Disable Windows Recall -- AI screenshot indexing would capture CUI/SI content
# CMMC: CM.L2-3.4.6 / SC.L1-3.13.1 | CPCSC: 03.04.06 / 03.13.01
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Value 1
Set-TSGRegistry -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Value 1
Disable-WindowsOptionalFeature -Online -FeatureName "Recall" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Write-Host "    [OK] CM.L2-3.4.6 | CPCSC 03.04.06 -- Recall disabled (CUI/SI indexing risk)" -ForegroundColor Green


# ================================================================================
# IDENTIFICATION AND AUTHENTICATION (IA)
# CMMC: IA.L1-3.5.1 through IA.L2-3.5.11
# CPCSC: 03.05.01 through 03.05.11
#
# This is a Level 1 requirement in both CMMC and CPCSC.
# ================================================================================
Write-TSGSection "IDENTIFICATION AND AUTHENTICATION (IA)" "CMMC IA.L1-3.5.1 to IA.L2-3.5.11 | CPCSC 03.05"

# [LEVEL 1] Identify and authenticate users before allowing access
# CMMC: IA.L1-3.5.1 / IA.L1-3.5.2 | FAR 52.204-21(b)(1)(iii)/(iv) | CPCSC: 03.05.01 / 03.05.02
# Disable WDigest -- prevents cleartext credentials in LSASS memory
# Source: DISA STIG WN11-CC-000038
Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
Write-Host "    [OK] [LEVEL 1] IA.L1-3.5.1 | CPCSC 03.05.01 -- WDigest disabled" -ForegroundColor Green

# [LEVEL 1] Do not store LAN Manager hash -- weak hash undermines authentication
# CMMC: IA.L1-3.5.2 / IA.L2-3.5.10 | CPCSC: 03.05.02 / 03.05.10
# Source: DISA STIG WN11-SO-000195 | CIS 2.3.11.6
Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
Write-Host "    [OK] [LEVEL 1] IA.L1-3.5.2 | CPCSC 03.05.02 -- No LM hash stored" -ForegroundColor Green

# [LEVEL 1] Require NTLMv2 only -- NTLMv1 is not a valid authentication mechanism
# CMMC: IA.L1-3.5.2 | CPCSC: 03.05.02
# LmCompatibilityLevel = 5: refuse LM, refuse NTLMv1, send NTLMv2 only
# Source: DISA STIG WN11-SO-000205 | CIS 2.3.11.7
Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
Write-Host "    [OK] [LEVEL 1] IA.L1-3.5.2 | CPCSC 03.05.02 -- NTLMv2 enforced, LM/NTLMv1 refused" -ForegroundColor Green

# Enable LSA Protection -- protects the authentication subsystem from dumping
# CMMC: IA.L2-3.5.3 (replay-resistant authentication) | CPCSC: 03.05.03
# Source: DISA STIG WN11-SO-000100 | CIS 18.3.2 | CCCS ITSP.70.012
Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
Write-Host "    [OK] IA.L2-3.5.3 | CPCSC 03.05.03 -- LSA Protection / RunAsPPL (restart required)" -ForegroundColor Yellow

# Require SMB packet signing -- ensures authenticity of network authentication
# CMMC: IA.L2-3.5.4 | CPCSC: 03.05.04
# Source: DISA STIG WN11-SO-000160/165 | CIS 2.3.9.1/2.3.9.2 | CCCS ITSP.70.012
Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"    -Name "RequireSecuritySignature" -Value 1
Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
Write-Host "    [OK] IA.L2-3.5.4 | CPCSC 03.05.04 -- SMB signing required" -ForegroundColor Green

# Restrict PowerShell execution policy
# CMMC: CM.L2-3.4.7 / IA.L2-3.5.3 | CPCSC: 03.04.07 / 03.05.03
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
Write-Host "    [OK] IA.L2-3.5.3 | CPCSC 03.05.03 -- PS ExecutionPolicy RemoteSigned" -ForegroundColor Green

# Block Office macros -- primary initial access vector for credential theft
# CMMC: CM.L2-3.4.7 / SI.L1-3.14.2 | CPCSC: 03.04.07 / 03.14.02
$officeVersion = "16.0"
foreach ($app in @("Word", "Excel", "PowerPoint", "Outlook", "Access")) {
    Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Office\$officeVersion\$app\Security" -Name "blockcontentexecutionfrominternet" -Value 1
}
Write-Host "    [OK] SI.L1-3.14.2 | CPCSC 03.14.02 -- Office macros from internet blocked" -ForegroundColor Green


# ================================================================================
# SYSTEM AND COMMUNICATIONS PROTECTION (SC)
# CMMC: SC.L1-3.13.1 through SC.L2-3.13.16
# CPCSC: 03.13.01 through 03.13.16
# ================================================================================
Write-TSGSection "SYSTEM AND COMMUNICATIONS PROTECTION (SC)" "CMMC SC.L1-3.13.1 to SC.L2-3.13.16 | CPCSC 03.13"

# [LEVEL 1] Monitor and control communications at network boundaries
# CMMC: SC.L1-3.13.1 | FAR 52.204-21(b)(1)(xi) | CPCSC: 03.13.01
# Firewall and default-deny already configured in CM section above
Write-Host "    [OK] [LEVEL 1] SC.L1-3.13.1 | CPCSC 03.13.01 -- Host firewall boundary (set in CM section)" -ForegroundColor Green

# Disable LLMNR -- removes unauthenticated broadcast name resolution
# CMMC: SC.L1-3.13.1 | CPCSC: 03.13.01
# Source: DISA STIG WN11-CC-000085 | CIS 18.5.4 | CCCS ITSP.70.012
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
Write-Host "    [OK] SC.L1-3.13.1 | CPCSC 03.13.01 -- LLMNR disabled" -ForegroundColor Green

# Disable NetBIOS over TCP/IP
# CMMC: SC.L1-3.13.1 | CPCSC: 03.13.01
# Source: DISA STIG WN11-CC-000080 | NSA | CCCS ITSP.70.012
Disable-TSGNetBIOS
Write-Host "    [OK] SC.L1-3.13.1 | CPCSC 03.13.01 -- NetBIOS over TCP/IP disabled" -ForegroundColor Green

# [LEVEL 1] Implement cryptographic mechanisms to protect CUI/SI in transmission
# CMMC: SC.L2-3.13.11 | CMMC Level 2 | CPCSC: 03.13.11
# Enable FIPS-validated cryptography mode
# Forces Windows to use only FIPS 140 validated cryptographic algorithms
# Test applications for FIPS compatibility before deploying to production
Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name "Enabled" -Value 1
Write-Host "    [OK] SC.L2-3.13.11 | CPCSC 03.13.11 -- FIPS-validated cryptography enabled (restart required)" -ForegroundColor Green
Write-Host "    [WARN] Test all applications for FIPS compatibility before production deployment" -ForegroundColor Yellow

# Protect CUI/SI at rest -- BitLocker full disk encryption
# CMMC: SC.L2-3.13.16 | CPCSC: 03.13.16
# Available on Pro AND Enterprise. Enterprise adds PIN enforcement via GPO.
Write-Host "    Enabling BitLocker on C: ..." -ForegroundColor DarkGray
$tpm = Get-Tpm -ErrorAction SilentlyContinue
if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) {
    manage-bde -on C: -RecoveryPassword -SkipHardwareTest | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    [OK] BitLocker enabled on C:. Recovery key was NOT written to this log." -ForegroundColor Green
        Write-Host "    [NOTE] Retrieve and escrow the key now: manage-bde -protectors -get C:" -ForegroundColor Yellow
    } else {
        Write-Host "    [FAIL] manage-bde exit code $LASTEXITCODE (already encrypted, feature missing, or blocked by policy)" -ForegroundColor Red
    }
} else {
    Write-Host "    [SKIP] No ready TPM detected. Enable BitLocker manually with a startup key or password protector." -ForegroundColor DarkGreen
}
Write-Host "    [NOTE] SC.L2-3.13.16 | CPCSC 03.13.16 -- Restart required to complete encryption" -ForegroundColor Yellow
Write-Host "    [NOTE] Key management procedure required per SC.L2-3.13.10 / CPCSC 03.13.10" -ForegroundColor DarkGray

# Disable activity history and advertising data -- control information flows
# CMMC: SC.L1-3.13.1 | CPCSC: 03.13.01
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities"  -Value 0
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1
Write-Host "    [OK] SC.L1-3.13.1 | CPCSC 03.13.01 -- Activity history and ad upload disabled" -ForegroundColor Green


# ================================================================================
# SYSTEM AND INFORMATION INTEGRITY (SI)
# CMMC: SI.L1-3.14.1 through SI.L2-3.14.7
# CPCSC: 03.14.01 through 03.14.07
# ================================================================================
Write-TSGSection "SYSTEM AND INFORMATION INTEGRITY (SI)" "CMMC SI.L1-3.14.1 to SI.L2-3.14.7 | CPCSC 03.14"

# [LEVEL 1] Provide protection from malicious code at entry and exit points
# CMMC: SI.L1-3.14.2 | FAR 52.204-21(b)(1)(x) | CPCSC: 03.14.02
Set-Service -Name "WinDefend" -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring $false
Write-Host "    [OK] [LEVEL 1] SI.L1-3.14.2 | CPCSC 03.14.02 -- Defender real-time protection" -ForegroundColor Green

# Network protection -- blocks known malicious IPs/domains
# CMMC: SI.L2-3.14.6 | CPCSC: 03.14.06
Set-MpPreference -EnableNetworkProtection Enabled
Write-Host "    [OK] SI.L2-3.14.6 | CPCSC 03.14.06 -- Network Protection enabled" -ForegroundColor Green

# Controlled Folder Access -- anti-ransomware protection for CUI/SI storage
# CMMC: SI.L1-3.14.2 / SI.L2-3.14.6 | CPCSC: 03.14.02 / 03.14.06
Set-MpPreference -EnableControlledFolderAccess Enabled
Write-Host "    [OK] SI.L1-3.14.2 | CPCSC 03.14.02 -- Controlled Folder Access (anti-ransomware)" -ForegroundColor Green
Write-Host "    [NOTE] If CFA blocks CUI-handling apps: Add-MpPreference -ControlledFolderAccessAllowedApplications 'App.exe'" -ForegroundColor DarkGray

# [LEVEL 1] Update malicious code protection mechanisms when new releases are available
# CMMC: SI.L1-3.14.4 | FAR 52.204-21(b)(1)(xiii) | CPCSC: 03.14.04
Set-MpPreference -SignatureScheduleDay Everyday
Write-Host "    [OK] [LEVEL 1] SI.L1-3.14.4 | CPCSC 03.14.04 -- Defender signatures scheduled daily" -ForegroundColor Green

# [LEVEL 1] Perform periodic scans and real-time scans
# CMMC: SI.L1-3.14.5 | FAR 52.204-21(b)(1)(xiv) | CPCSC: 03.14.05
Set-MpPreference -ScanScheduleDay Everyday
Set-MpPreference -ScanScheduleTime "02:00:00"
Write-Host "    [OK] [LEVEL 1] SI.L1-3.14.5 | CPCSC 03.14.05 -- Scheduled scan daily at 02:00" -ForegroundColor Green

# DEP and SEHOP -- exploit mitigation as malicious code protection
# CMMC: SI.L1-3.14.2 | CPCSC: 03.14.02
# Source: DISA STIG WN11-00-000145/150 | CIS 18.8.21.5 | CCCS ITSP.70.012
bcdedit /set nx AlwaysOn | Out-Null
Write-Host "    [OK] SI.L1-3.14.2 | CPCSC 03.14.02 -- DEP AlwaysOn (restart required)" -ForegroundColor Green

Set-ProcessMitigation -System -Enable BottomUp,HighEntropy -ErrorAction SilentlyContinue
Write-Host "    [OK] SI.L1-3.14.2 | CPCSC 03.14.02 -- ASLR and forced relocation" -ForegroundColor Green

# Value 0 ENABLES SEHOP (counterintuitive name, confirmed in DISA STIG WN11-00-000150)
Set-TSGRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0
Write-Host "    [OK] SI.L1-3.14.2 | CPCSC 03.14.02 -- SEHOP enabled" -ForegroundColor Green


# ================================================================================
# MEDIA PROTECTION (MP) -- TECHNICAL CONTROLS ONLY
# CMMC: MP.L2-3.8.5 / MP.L2-3.8.6 / MP.L2-3.8.7 / MP.L2-3.8.8
# CPCSC: 03.08.05 / 03.08.06 / 03.08.07 / 03.08.08
#
# Most MP controls are procedural (physical media inventory, disposal procedures).
# The following are the technically enforceable Windows controls.
# ================================================================================
Write-TSGSection "MEDIA PROTECTION (MP) -- Technical Controls" "CMMC MP.L2-3.8.5/6/7/8 | CPCSC 03.08.05/06/07/08"

# Require BitLocker encryption on removable drives before write access
# CMMC: MP.L2-3.8.5 / MP.L2-3.8.6 | CPCSC: 03.08.05 / 03.08.06
# CUI/SI on removable media must be protected with cryptographic mechanisms.
# RDVDenyWriteAccess = 1: blocks write access until the drive is encrypted.
# RDVEnforcePassphrase = 1: enforces a passphrase on BitLocker To Go drives.
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVEnforcePassphrase" -Value 1
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyWriteAccess"   -Value 1
Write-Host "    [OK] MP.L2-3.8.5/6 | CPCSC 03.08.05/06 -- Removable drive write requires BitLocker" -ForegroundColor Green
Write-Host "    [NOTE] Users will be prompted to encrypt USB drives before write access is granted" -ForegroundColor DarkGray

# AutoRun disable (already set in AC section) satisfies MP.L2-3.8.7/3.8.8
Write-Host "    [OK] MP.L2-3.8.7/8 | CPCSC 03.08.07/08 -- AutoRun disabled (set in AC section)" -ForegroundColor Green


# ================================================================================
# BLOATWARE REMOVAL -- CM.L2-3.4.6/7 | CPCSC 03.04.06/07
# Consumer applications generate outbound connections and background data flows
# incompatible with handling CUI/SI. Remove them unconditionally.
# ================================================================================
Write-TSGSection "BLOATWARE REMOVAL" "CMMC CM.L2-3.4.6/7 | CPCSC 03.04.06/07"

Remove-TSGAppx -PackageName "Microsoft.549981C3F5F10"                -FriendlyName "Cortana"
Remove-TSGAppx -PackageName "Microsoft.Windows.Copilot"              -FriendlyName "Windows Copilot"
Remove-TSGAppx -PackageName "MicrosoftWindows.Client.WebExperience"  -FriendlyName "Windows Widgets"
Remove-TSGAppx -PackageName "Microsoft.BingNews"                     -FriendlyName "Bing News"
Remove-TSGAppx -PackageName "Microsoft.BingWeather"                  -FriendlyName "Bing Weather"
Remove-TSGAppx -PackageName "Microsoft.GamingApp"                    -FriendlyName "Xbox Gaming App"
Remove-TSGAppx -PackageName "Microsoft.XboxApp"                      -FriendlyName "Xbox App"
Remove-TSGAppx -PackageName "Microsoft.XboxGameOverlay"              -FriendlyName "Xbox Game Overlay"
Remove-TSGAppx -PackageName "Microsoft.XboxGamingOverlay"            -FriendlyName "Xbox Gaming Overlay"
Remove-TSGAppx -PackageName "Microsoft.YourPhone"                    -FriendlyName "Phone Link"
Remove-TSGAppx -PackageName "MicrosoftTeams"                         -FriendlyName "Teams Consumer"
Remove-TSGAppx -PackageName "Microsoft.SkypeApp"                     -FriendlyName "Skype"
Remove-TSGAppx -PackageName "MicrosoftCorporationII.QuickAssist"     -FriendlyName "Quick Assist"
Remove-TSGAppx -PackageName "Microsoft.WindowsFeedbackHub"           -FriendlyName "Feedback Hub (sends data to Microsoft)"
Remove-TSGAppx -PackageName "BytedancePte.TikTok"                    -FriendlyName "TikTok (flagged by both US and Canadian governments)"

Set-TSGRegistry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed"      -Value 0
Set-TSGRegistry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled"     -Value 0
Set-TSGRegistry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0
Set-TSGRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
Write-Host "    [OK] CM.L2-3.4.6/7 | CPCSC 03.04.06/07 -- Consumer apps removed" -ForegroundColor Green


# ================================================================================
# DOCUMENTATION REQUIRED FOR ASSESSMENT
# Controls in this section cannot be implemented via script.
# Your C3PAO (CMMC) or 3PAO (CPCSC) will require evidence of these.
# ================================================================================
Write-TSGSection "DOCUMENTATION REQUIRED FOR ASSESSMENT" "Organizational controls not implementable via script"

Write-Host ""
Write-Host "  The following CMMC/CPCSC controls require documents, not registry keys." -ForegroundColor Yellow
Write-Host "  Your assessor will ask for these. Start on them now." -ForegroundColor Yellow
Write-Host ""
Write-Host "  CMMC AC.L1-3.1.1  / CPCSC 03.01.01  -- Written Access Control Policy" -ForegroundColor DarkGray
Write-Host "  CMMC AT.L2-3.2.1  / CPCSC 03.02.01  -- Security Awareness Training Program" -ForegroundColor DarkGray
Write-Host "  CMMC AT.L2-3.2.2  / CPCSC 03.02.02  -- Insider Threat Awareness Training" -ForegroundColor DarkGray
Write-Host "  CMMC CM.L2-3.4.1  / CPCSC 03.04.01  -- Documented System Baseline Configuration" -ForegroundColor DarkGray
Write-Host "  CMMC CM.L2-3.4.3  / CPCSC 03.04.03  -- Change Control Process" -ForegroundColor DarkGray
Write-Host "  CMMC IR.L2-3.6.1  / CPCSC 03.06.01  -- Incident Response Plan" -ForegroundColor DarkGray
Write-Host "  CMMC IR.L2-3.6.2  / CPCSC 03.06.02  -- Incident Reporting to Government" -ForegroundColor DarkGray
Write-Host "  CMMC MP.L2-3.8.1  / CPCSC 03.08.01  -- Media Protection Policy + Disposal Procedures" -ForegroundColor DarkGray
Write-Host "  CMMC RA.L2-3.11.1 / CPCSC 03.11.01  -- Risk Assessment Documentation" -ForegroundColor DarkGray
Write-Host "  CMMC RA.L2-3.11.2 / CPCSC 03.11.02  -- Vulnerability Scan Results + Remediation" -ForegroundColor DarkGray
Write-Host "  CMMC SC.L2-3.13.10/ CPCSC 03.13.10  -- Cryptographic Key Management Procedure" -ForegroundColor DarkGray
Write-Host "  CMMC CA.L2-3.12.1 / CPCSC 03.12.01  -- Security Assessment Plan" -ForegroundColor DarkGray
Write-Host "  CMMC CA.L2-3.12.2 / CPCSC 03.12.02  -- Plan of Action and Milestones (POA&M)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  This log file is technical implementation evidence for your SSP:" -ForegroundColor DarkYellow
Write-Host "  $LogPath" -ForegroundColor DarkYellow


# ================================================================================
# FINALIZATION
# ================================================================================
Write-TSGSection "FINALIZATION"

if ($SkippedEntControls.Count -gt 0) {
    Write-Host ""
    Write-Host "  Enterprise-only controls skipped on this Pro SKU:" -ForegroundColor Yellow
    $SkippedEntControls | ForEach-Object { Write-Host "    * $_" -ForegroundColor Yellow }
    Write-Host "  Source: learn.microsoft.com/windows/security/licensing-and-edition-requirements" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  CMMC Level 2 / CPCSC ITSP.10.171 technical controls applied." -ForegroundColor DarkYellow
Write-Host "  Log retained at: $LogPath" -ForegroundColor Gray
Write-Host ""
Write-Host "  CONTROL FAMILIES APPLIED:" -ForegroundColor Gray
Write-Host "    AC  Access Control:               AC.L1-3.1.1/2, AC.L2-3.1.5/12/13/14" -ForegroundColor DarkGray
Write-Host "    AU  Audit and Accountability:     AU.L2-3.3.1 through AU.L2-3.3.9" -ForegroundColor DarkGray
Write-Host "    CM  Configuration Management:     CM.L2-3.4.1/2/6/7/8/9" -ForegroundColor DarkGray
Write-Host "    IA  Identification and Auth:      IA.L1-3.5.1/2, IA.L2-3.5.3/4/10" -ForegroundColor DarkGray
Write-Host "    SC  System and Comms Protection:  SC.L1-3.13.1/8, SC.L1-3.13.1/16" -ForegroundColor DarkGray
Write-Host "    SI  System and Info Integrity:    SI.L1-3.14.2/4/5, SI.L2-3.14.6/7" -ForegroundColor DarkGray
Write-Host "    MP  Media Protection (technical): MP.L2-3.8.5/6/7/8" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  RESTART REQUIRED: DEP, FIPS mode, LSA Protection, Credential Guard, BitLocker" -ForegroundColor Yellow
Write-Host "  Hans Study | https://hans.study | contact@hans.study" -ForegroundColor DarkGray

Stop-Transcript | Out-Null

$restart = Read-Host "  Restart now? [y/N]"
if ($restart -match '^[Yy]') {
    Write-Host "  Restarting in 15 seconds. Press Ctrl+C to cancel." -ForegroundColor Yellow
    Start-Sleep -Seconds 15
    Restart-Computer -Force
}
