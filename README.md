# Windows Hardening PowerShell Scripts: DISA STIG, CIS, CCCS, NSA/CISA, CMMC, CPCSC, Genetec, and Kiosk Baselines

Standalone PowerShell scripts that apply published security hardening baselines to Windows 10, Windows 11, Windows Server 2019, Windows Server 2022, and Windows Server 2025. Each script is a single `.ps1` file. No modules, no shared dependencies, no installer.

By **Hans Study, CISSP**. Independent network and security consultant and advisor based in Ontario, Canada. Government, law enforcement, defense, airports, healthcare, and enterprise clients across Canada and the United States.

[hans.study](https://hans.study) | [contact@hans.study](mailto:contact@hans.study)
LinkedIn: [hans-study](https://linkedin.com/in/hans-study) | Instagram: [@StudyByt3s](https://instagram.com/studybyt3s) | X: [@StudyByt3s](https://x.com/studybyt3s) | YouTube: [@StudyByt3s](https://youtube.com/@studybyt3s) | GitHub: [hansstudy](https://github.com/hansstudy)

Last updated: 2026-10-05

---

## Table of Contents

- [Quick Picker](#quick-picker)
- [What This Repository Contains](#what-this-repository-contains)
- [Standards Referenced](#standards-referenced)
- [Scripts](#scripts)
  - [Genetec-SecurityCenter-Workstation.ps1](#genetec-securitycenter-workstationps1)
  - [CCCS-NSA-CISA-Baseline.ps1](#cccs-nsa-cisa-baselineps1)
  - [DISA-STIG-Baseline.ps1](#disa-stig-baselineps1)
  - [CIS-Benchmark-L1.ps1](#cis-benchmark-l1ps1)
  - [Minimum-Viable-Security.ps1](#minimum-viable-securityps1)
  - [Security-Analyst-Workstation.ps1](#security-analyst-workstationps1)
  - [Kiosk-ThinClient-Lockdown.ps1](#kiosk-thinclient-lockdownps1)
  - [CMMC-CPCSC-ITSP10171.ps1](#cmmc-cpcsc-itsp10171ps1)
- [How to Run](#how-to-run)
- [Verification After Running](#verification-after-running)
- [Edition Requirements](#edition-requirements)
- [Accuracy Notes](#accuracy-notes)
- [Helper Functions Reference](#helper-functions-reference)
- [FAQ](#faq)
- [About the Author](#about-the-author)
- [License](#license)

---

## Quick Picker

Pick the script that matches your use case. Each row links to the detailed section below.

| Use case | Script | Standard implemented |
|---|---|---|
| Genetec Security Center workstation, Archiver, or Directory server | [Genetec-SecurityCenter-Workstation.ps1](#genetec-securitycenter-workstationps1) | Genetec Hardening Guide plus CCCS/NSA/CISA |
| Canadian government contractor, healthcare, or general Canadian enterprise | [CCCS-NSA-CISA-Baseline.ps1](#cccs-nsa-cisa-baselineps1) | CSE/CCCS ITSP.70.012 plus NSA/CISA |
| US DoD contractor, federal agency, or insurance/contract requirement for DISA STIG | [DISA-STIG-Baseline.ps1](#disa-stig-baselineps1) | DISA STIG Windows 11 V2R2 and Windows 10 V2R7 |
| Compliance audit or vendor assessment that accepts an industry-standard baseline | [CIS-Benchmark-L1.ps1](#cis-benchmark-l1ps1) | CIS Microsoft Windows 11/10 Benchmark v3.0 Level 1 |
| Legacy environment, compatibility-sensitive deployment, or a tested low-risk first pass | [Minimum-Viable-Security.ps1](#minimum-viable-securityps1) | Curated subset of CCCS, NSA/CISA, DISA, and CIS |
| SOC analyst, threat hunter, DFIR practitioner, or incident responder workstation | [Security-Analyst-Workstation.ps1](#security-analyst-workstationps1) | DISA STIG with analyst-specific carve-outs |
| Guard terminal, reception kiosk, lobby access control console, or any single-purpose machine | [Kiosk-ThinClient-Lockdown.ps1](#kiosk-thinclient-lockdownps1) | DISA STIG plus CIS Level 2 lockdown |
| US DoD CMMC Level 2 (CUI) or Canadian CPCSC ITSP.10.171 (SI) readiness | [CMMC-CPCSC-ITSP10171.ps1](#cmmc-cpcsc-itsp10171ps1) | NIST SP 800-171 Rev 2 (CMMC) and Rev 3 (CPCSC) |

---

## What This Repository Contains

Eight standalone PowerShell hardening scripts. Each script:

- Targets Windows 10, Windows 11, Windows Server 2019, Windows Server 2022, and Windows Server 2025.
- Applies one published security hardening baseline.
- Documents every control inline with the citation (DISA STIG rule ID, CIS section number, NSA/CISA publication, CCCS ITSP section, or CMMC/CPCSC practice ID).
- Requires administrator privileges.
- Creates a Windows System Restore point before any change.
- Logs every action to `C:\Logs\<ScriptName>_YYYYMMDD.log`.
- Detects the OS edition at runtime and skips Enterprise-only controls on Windows Pro with a logged warning.
- Prompts for restart when controls require one.
- Runs without modules, shared files, or external dependencies. One `.ps1` per use case.

Prefer a wizard? The [Study Windows Configuration Utility](https://hans.study/tools/workstation-config/) on hans.study builds a hardening script for a single workstation or a domain GPO from the same baselines.

Commands and registry keys are drawn from the cited official sources. Re-check the current STIG, CIS, or ITSP text before you treat a run as assessment evidence.

---

## Standards Referenced

| Standard | Publisher | Source |
|---|---|---|
| DISA STIG Windows 11 V2R2 / Windows 10 V2R7 | Defense Information Systems Agency (US DoD) | [public.cyber.mil](https://public.cyber.mil) |
| CIS Microsoft Windows 11/10 Benchmark v3.0 (Level 1 and Level 2) | Center for Internet Security | [cisecurity.org](https://cisecurity.org) |
| NSA/CISA Cybersecurity Information Sheets | US National Security Agency and Cybersecurity and Infrastructure Security Agency | [media.defense.gov](https://media.defense.gov) |
| NSA/CISA Keeping PowerShell Security Measures (June 2022) | NSA / CISA | [media.defense.gov](https://media.defense.gov) |
| ITSP.70.012 Hardening Microsoft Windows 10 Enterprise | Communications Security Establishment / Canadian Centre for Cyber Security | [cyber.gc.ca](https://cyber.gc.ca) |
| CPCSC / ITSP.10.171 Protecting Specified Information | PSPC (program); Cyber Centre (ITSP.10.171 standard) | [canada.ca CPCSC](https://www.canada.ca/en/public-services-procurement/services/industrial-security/security-requirements-contracting/cyber-security-certification-defence-suppliers-canada/program-overview.html) · [cyber.gc.ca](https://cyber.gc.ca) |
| CMMC 2.0 (NIST SP 800-171 Rev 2) | US Department of Defense | [dodcio.defense.gov/cmmc](https://dodcio.defense.gov/cmmc) |
| Genetec Security Center Hardening Guide | Genetec | [publications.genetec.com](https://publications.genetec.com) |

---

## Scripts

### Helper Functions

Each script embeds the helper functions it needs, drawn from a common set of six: `Write-TSGSection`, `Set-TSGRegistry`, `Remove-TSGAppx`, `Test-TSGEnterprise`, `New-TSGRestorePoint`, and `Disable-TSGNetBIOS`. The function names are kept for backward compatibility with the original implementation. No external module is required.

---

### Genetec-SecurityCenter-Workstation.ps1

**Use when:** Deploying a Genetec Security Center workstation, Archiver, or Directory server.

Applies CCCS/NSA/CISA-level hardening with specific tuning for Genetec Security Center 6.x. Every decision that deviates from a standard baseline is documented inline with the reason.

Key Genetec-specific decisions:

**Controlled Folder Access is not enabled.** Genetec writes continuously to AppData and archive paths. CFA blocks these writes until whitelisted. Use AuditMode first to build the exclusion list before enabling.

**Windows Search Indexing is disabled.** Genetec has its own media index. WSearch generates competing I/O on archive volumes with no benefit.

**SysMain (Superfetch) is disabled.** RAM should go to the Archiver buffer and SQL cache, not to application pre-loading.

**Cloud-delivered Defender protection is disabled.** Most VMS networks are isolated. Outbound sample submission is not appropriate and can cause latency on restricted networks. Windows Tamper Protection blocks this setting by default. The script reads the value back and warns if it did not apply, in which case turn Tamper Protection off in Windows Security and re-run.

**RDP is left enabled with NLA enforced.** SC administrators need remote Config Tool access. Disable RDP if your environment does not require remote administration.

**High Performance power plan is on.** CPU throttling causes frame drops and recording gaps on Archiver servers.

**Hibernation is disabled.** Recording servers must never hibernate. Hibernation causes recording gaps that cannot be recovered.

Defender exclusions are added for G64, G64x, MDF, LDF, and NDF file extensions and Genetec installation paths. Inbound firewall rules are added for TCP 5500 (SDK), 443 (HTTPS), 554 (RTSP), 555 (stream), and 8888 (Unit Assistant).

**Why Genetec needs its own hardening script:**

Generic Windows hardening baselines break Genetec deployments in predictable ways. Controlled Folder Access blocks video archive writes and causes recording gaps. Aggressive Defender scanning of G64 files on the Archiver volume creates I/O contention that shows up as dropped frames and buffering delays in Security Desk. Hibernation on a server running the Genetec Directory causes all connected clients to lose their session. Applying generic guidance without understanding what Genetec does at the OS level produces an integrator who spends hours troubleshooting symptoms that trace directly to the hardening script.

This script is built from direct deployment experience across government, law enforcement, airports, and critical infrastructure sites. The goal is a workstation that passes a security audit and keeps cameras recording. The server side of the same problem is covered in [VMS server hardening](https://hans.study/vms-server-hardening/) on hans.study.

**Genetec Security Center default communication ports added to the firewall:**

| Port | Protocol | Purpose |
|---|---|---|
| 5500 | TCP | Genetec Directory SDK. Client connections from Security Desk and Config Tool |
| 443 | TCP | Genetec Web Client and REST API (HTTPS) |
| 554 | TCP | Genetec Archiver RTSP. Live stream and playback |
| 555 | TCP | Genetec Archiver proprietary stream protocol |
| 8888 | TCP | Genetec Unit Assistant. Camera unit management and firmware updates |

If your deployment uses custom port assignments configured in Config Tool, edit the `$genetecRules` array in the script before running. To prove the paths are open from a client or a remote site after a firewall change, [PortProof](https://hans.study/tools/portproof/) checks a declared list of ports and returns a pass/fail matrix. A [firewall review](https://hans.study/firewall-review/) covers the rule base itself.

**Windows Defender exclusions added by the script:**

- `C:\Program Files (x86)\Genetec Security Center*`. SC installation directory. The trailing wildcard matches the versioned folder (for example `Genetec Security Center 6.0`).
- `C:\Program Files\Genetec Security Center*`. SC installation directory, 64-bit path.
- `C:\ProgramData\Genetec Security Center*`. SC configuration and cache.
- `.g64`. Genetec proprietary video container format.
- `.g64x`. Genetec extended video container format.
- `.mdf`, `.ldf`, `.ndf`. SQL Server database files used by the Genetec Directory.

If your Genetec archive is stored on a non-default path, add an exclusion for it after running the script:

```powershell
Add-MpPreference -ExclusionPath "D:\GenetecArchive"
```

**Tested against:** Genetec Security Center 6.x on Windows Server 2019, Windows Server 2022, Windows 10 Enterprise, and Windows 11 Enterprise. Validate in a lab before applying to a production Archiver or Directory.

---

### CCCS-NSA-CISA-Baseline.ps1

**Use when:** Hardening a Canadian government contractor, healthcare provider, or enterprise workstation. Recommended starting point for any Canadian deployment that does not require DISA STIG.

Aligns with CSE/CCCS ITSP.70.012, the NSA/CISA June 2022 PowerShell security guidance, and CPCSC endpoint requirements. Covers WDigest removal, NTLMv2 enforcement, LLMNR and NetBIOS disable, SMBv1 removal, PS v2 removal, Script Block Logging, and PS Transcription. Less disruptive than DISA STIG: no mandatory Always Notify UAC, no forced AppLocker.

---

### DISA-STIG-Baseline.ps1

**Use when:** You need US DoD-level hardening, or your contract, insurance, or compliance program requires DISA STIG compliance.

Addresses the CAT I (critical) registry- and policy-based findings and most CAT II (medium) DISA STIG findings for standalone, non-domain-joined Windows 10 and Windows 11 systems. User-rights assignments (`WN11-UR-*`) require `secedit` and are not included. Every registry key and command cites its DISA STIG rule ID (for example, `WN11-CC-000038`, `WN11-SO-000205`) for direct traceability against the official STIG checklist.

Be aware before deploying:

- UAC is set to Always Notify (required by WN11-SO-000250).
- RDP is disabled by default.
- WSH is disabled, which will break `.vbs` and `.js` automation in use on the host.
- AppLocker service is started on Enterprise, but rule configuration via Group Policy is required separately.

Comment out any block that conflicts with your operational requirements before running.

---

### CIS-Benchmark-L1.ps1

**Use when:** You want an industry-standard baseline accepted for compliance audits and vendor security assessments.

CIS Microsoft Windows 11/10 Benchmark Level 1. Designed to deploy without significant operational impact. Level 2 controls (AppLocker, mandatory BitLocker PIN, Credential Guard enforcement) are not included. Use the DISA STIG script if Level 2 coverage is required. Every registry key and command cites its CIS section number.

---

### Minimum-Viable-Security.ps1

**Use when:** Hardening a legacy environment where compatibility is a concern, or you want a verified low-risk starting point before going further.

Curated minimum baseline. Every control works on Windows 10/11 Pro without additional licensing and is unlikely to break existing applications. Apply [CCCS-NSA-CISA-Baseline.ps1](#cccs-nsa-cisa-baselineps1) or [DISA-STIG-Baseline.ps1](#disa-stig-baselineps1) after this for full coverage.

---

### Security-Analyst-Workstation.ps1

**Use when:** Setting up a workstation for a SOC analyst, threat hunter, DFIR practitioner, or incident responder.

DISA STIG-level hardening with analyst-specific carve-outs:

- IPv6 and RDP are left enabled.
- Cloud-delivered Defender protection is disabled for air-gapped analysis and sandbox work. Tamper Protection blocks this by default. The script warns if the setting did not apply.
- Controlled Folder Access is not enabled, because forensic tools write to too many locations to whitelist reliably.
- Security event log is set to 2 GB, PS Operational log to 200 MB.

---

### Kiosk-ThinClient-Lockdown.ps1

**Use when:** Setting up a guard terminal, reception kiosk, lobby access control console, or any other single-purpose machine.

Maximum restriction. RDP, NetBIOS, and LLMNR are disabled. IPv6 is set to prefer IPv4 rather than disabled outright, since a full disable breaks loopback and adds a five-second boot delay. UAC is set to Always Notify and standard user elevation is auto-denied. WSH is disabled. BitLocker is enabled. AppLocker service is started on Enterprise (rules require Group Policy). High Performance power plan is on, hibernation is off, SysMain and WSearch are disabled, and all consumer apps are removed.

Pass the kiosk application and the local account it runs as to get a true single-app kiosk. The app is allow-listed in Controlled Folder Access and becomes that account's shell in place of Explorer. Task Manager, lock, log off, Run, and Control Panel are disabled for that account. Removable storage is denied machine-wide whether or not the parameters are supplied.

```powershell
.\Kiosk-ThinClient-Lockdown.ps1 -KioskApp "C:\Kiosk\App.exe" -KioskUser "kiosk"
```

Without the two parameters the script hardens the machine but leaves Explorer as the shell. The account must be a standard user; the script refuses an administrator. For unattended boot use Sysinternals Autologon, which stores the password in LSA secrets rather than plaintext registry. On Enterprise, Shell Launcher v2 is Microsoft's supported alternative to the per-user shell.

---

### CMMC-CPCSC-ITSP10171.ps1

**Use when:** Your organization handles US DoD Controlled Unclassified Information (CUI) under CMMC, or Canadian Specified Information (SI) under the Canadian Program for Cyber Security Certification (CPCSC).

Controls are cited with both the CMMC 2.0 practice ID (for example, `AC.L1-3.1.1`) and the ITSP.10.171 identifier (for example, `03.01.01`). Controls required at Level 1 are marked `[LEVEL 1]`. One script covers much of both programs' technical OS surface.

**Program status (verify against the living hub before you attest):**

| Program | Level | Requirement | Status |
|---|---|---|---|
| CPCSC | Level 1 | 13 requirements, annual self-assessment through PSPC's tool; result in CanadaBuys | Live (opened April 1, 2026; in select contracts since summer 2026) |
| CPCSC | Level 2 | 98 requirements, assessed by SCC-accredited certification bodies | Planned for spring 2027 |
| CMMC | Level 2 | 110 practices, C3PAO-assessed | Active now for US DoD contracts with CUI |

CMMC Level 2 uses NIST SP 800-171 Rev 2 (110 controls). CPCSC uses ITSP.10.171, which adapts NIST SP 800-171 Rev 3: 98 requirements (97 from Rev 3 plus Canada's `03.14.09`). The technical requirements overlap heavily, so one hardened build covers much of both, but Rev 2 and Rev 3 differ and CPCSC Level 1 requires MFA where CMMC Level 1 does not. Check each requirement. CPCSC is run by Public Services and Procurement Canada (PSPC).

Dated program facts live in [hansstudy/CPCSC](https://github.com/hansstudy/CPCSC) and [hans.study/cpcsc](https://hans.study/cpcsc/). For a read-only Windows audit against ITSP.10.171 (no changes applied), use the scripts in that hub. This script **applies** baselines; the hub **audits**.

This script covers technical OS controls: UAC, firewall, audit logging, encryption, malware protection, credential protection, FIPS mode, BitLocker, and BitLocker To Go for removable drives. It does not cover written policies, incident response plans, risk assessments, or key management procedures. Those are organizational controls. The script prints a full checklist of required documentation at the end. Running it supports readiness work; it is not a CPCSC or CMMC attestation.

The log file is technical implementation evidence for your System Security Plan (SSP). For formal assessment, engage a C3PAO (CMMC) or a certification body accredited by the Standards Council of Canada (CPCSC Level 2).

---

## How to Run

Download the script for your use case. Open PowerShell as Administrator.

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\CCCS-NSA-CISA-Baseline.ps1
```

Or right-click the `.ps1` and choose **Run with PowerShell** (as Administrator).

The script creates a System Restore point, applies all controls, logs everything to `C:\Logs\`, reports any skipped Enterprise-only controls, and prompts for restart. Review the log for `[FAIL]` entries before restarting.

---

## Verification After Running

After the script completes, confirm the result before restarting:

1. Open the log file at `C:\Logs\<ScriptName>_YYYYMMDD.log`.
2. Search for `[FAIL]`. Each `[FAIL]` line names the control that did not apply and the reason. Most failures are environment-specific (Group Policy precedence, missing service, unsupported edition).
3. Search for `[SKIP]`. Skipped controls are Enterprise-only items detected on a Pro edition, plus any controls that need a separate step (for example, AppLocker policy configuration via Group Policy).
4. Restart the machine if the script reported `RESTART REQUIRED`. Some controls (LSA Protection, DEP, Credential Guard) require a reboot to take effect.

To re-run a script idempotently, simply execute it again. Every registry write checks the key path first and overwrites without side effects.

---

## Edition Requirements

Credential Guard and AppLocker enforcement require Windows Enterprise or Education licensing. Both are detected at runtime and auto-skipped on Pro with a logged warning. Source: [learn.microsoft.com/windows/security/licensing-and-edition-requirements](https://learn.microsoft.com/en-us/windows/security/licensing-and-edition-requirements).

Everything else (BitLocker, DEP, ASLR, SEHOP, LSA Protection, all audit controls, and all Defender controls) works on Pro and Enterprise.

---

## Accuracy Notes

A few behaviors that look wrong but are correct:

**SEHOP.** `DisableExceptionChainValidation = 0` enables SEHOP. Setting it to 0 turns protection on. The registry name is counterintuitive. Confirmed correct in DISA STIG WN11-00-000150.

**Firewall profile list.** `Set-NetFirewallProfile -Profile Domain,Public,Private` (no spaces in the profile list). `Domain, Public, Private` with spaces is a common error in other scripts and can cause unexpected behavior.

**NetBIOS disable.** Uses `Win32_NetworkAdapterConfiguration.SetTcpipNetbios(2)` via WMI. Value 2 = disable. There is no native PowerShell cmdlet for this.

**FIPS mode (CMMC/CPCSC script).** Required by CMMC SC.L2-3.13.11 and ITSP.10.171 `03.13.11`. Some applications using non-FIPS cryptographic APIs will fail after this is enabled. Test before production deployment.

**BitLocker To Go (CMMC/CPCSC script).** `RDVDenyWriteAccess = 1` blocks write access to removable drives until they are encrypted. Users see a prompt to encrypt the USB drive before they can write to it.

---

## Helper Functions Reference

These functions are embedded in every script. Copy the definitions into your own scripts if needed.

```powershell
# Idempotent registry write. Creates key path if missing, logs OK or FAIL
Set-TSGRegistry -Path "HKLM:\Software\..." -Name "ValueName" -Value 1

# Section header with optional source reference subtitle
Write-TSGSection "SECTION TITLE" "DISA WN11-XX-000000 | CIS 18.x.x"

# AppX removal. Provisioned (new users) and per-user (existing accounts)
Remove-TSGAppx -PackageName "Microsoft.BingNews" -FriendlyName "Bing News"

# Enterprise license check. Returns $true or $false, logs warning on Pro
if (Test-TSGEnterprise -ControlName "Credential Guard") { ... }

# System restore point before any changes
New-TSGRestorePoint -Description "Pre-hardening snapshot"

# Disable NetBIOS over TCP/IP on all IPv4 adapters via WMI
Disable-TSGNetBIOS
```

---

## FAQ

**Are these scripts safe to run on a production workstation?**
Each script creates a Windows System Restore point before making any change. Test in a non-production environment first. The `Minimum-Viable-Security.ps1` baseline is the lowest-risk starting point. DISA STIG and Kiosk Lockdown make changes that may break existing applications.

**Do I need Windows Enterprise to use these scripts?**
No. Every control that requires Enterprise (Credential Guard, AppLocker enforcement) is auto-detected and skipped on Pro with a logged warning. The rest of the baseline (BitLocker, Defender, audit logging, network hardening, registry-based STIG settings) works on Pro and Enterprise.

**Where do the logs go?**
`C:\Logs\<ScriptName>_YYYYMMDD.log`. The log is the audit trail. Keep it for compliance evidence.

**Will these scripts break my applications?**
DISA STIG and Kiosk Lockdown disable WSH, force NTLMv2-only, and apply Always Notify UAC. Any application that depends on `.vbs` or `.js` automation, legacy SMB, or silent elevation will be affected. The Genetec, Security Analyst, and Minimum Viable Security scripts are designed to avoid these breakages. Read the relevant script section above for the trade-offs.

**Can I run more than one script on the same machine?**
Yes. The scripts are idempotent. A common pattern: apply `Minimum-Viable-Security.ps1` first, then run a stricter script on top (`CCCS-NSA-CISA-Baseline.ps1` or `DISA-STIG-Baseline.ps1`). The second script will overwrite any conflicting setting from the first.

**Do these scripts work on domain-joined machines?**
The settings apply to the local machine. Group Policy will override anything the local Group Policy editor cannot change. If your domain pushes its own settings, those will take precedence after the next Group Policy refresh. Use these scripts on standalone machines, or coordinate with your AD team if pushing the same baseline via GPO.

**What is the difference between DISA STIG and CIS Benchmark Level 1?**
DISA STIG is the US Department of Defense hardening standard, mandatory for systems handling DoD information. It is stricter and intentionally breaks legacy compatibility. CIS Benchmark Level 1 is the consensus industry baseline accepted by most compliance frameworks. It is designed to deploy without significant operational impact. Use DISA STIG when contract or insurance terms require it. Use CIS L1 when you need a defensible baseline that does not break common workflows.

**What is CMMC and who needs it?**
Cybersecurity Maturity Model Certification. A US Department of Defense compliance program for any organization in the Defense Industrial Base that handles Controlled Unclassified Information (CUI). Level 2 (110 practices, NIST SP 800-171 Rev 2) is the level most contractors need.

**What is CPCSC and who needs it?**
Canadian Program for Cyber Security Certification. Run by Public Services and Procurement Canada (PSPC). Required on Government of Canada defense contracts that name a CPCSC level for suppliers handling Specified Information (SI). Level 1 (13 requirements, annual self-assessment through PSPC's tool, result in CanadaBuys) is live: opened April 1, 2026 and in select contracts since summer 2026. Level 2 (98 requirements, assessed by SCC-accredited certification bodies) is planned for spring 2027. Full, dated program status: [hansstudy/CPCSC](https://github.com/hansstudy/CPCSC) and [hans.study/cpcsc](https://hans.study/cpcsc/).

**Does the Genetec script support Security Center version 5.x?**
The script is tested against Genetec Security Center 6.x. Version 5.x deployments share most of the same hardening principles but may use different default ports and service names. Read the inline comments before running on 5.x.

**Can I redistribute these scripts?**
No, not without written authorization from Hans Study. The license permits personal use, internal organizational use, and internal commercial use. Redistribution, republishing, hosting, sublicensing, and distribution of derivative works require permission. See [LICENSE](LICENSE) for full terms.

**Who maintains this repository?**
Hans Study, CISSP. See [About the Author](#about-the-author) below.

---

## About the Author

**Hans Study, CISSP** is an independent network and security consultant and advisor based in Ontario, Canada. He holds the Certified Information Systems Security Professional (CISSP) credential from (ISC)².

Clients include government, law enforcement, defense, airports, healthcare, and enterprise organizations across Canada and the United States.

Focus areas:

- Physical security system integration (Genetec, Milestone, C-CURE, Avigilon, Axis, Bosch).
- Windows endpoint hardening and security architecture.
- OT/IT convergence for physical security environments.
- Compliance against DISA STIG, CIS, NSA/CISA, CCCS ITSP.70.012, CMMC, and CPCSC.
- Incident response and forensic readiness for SOC and DFIR teams.

Contact: [contact@hans.study](mailto:contact@hans.study)
Website: [hans.study](https://hans.study)

---

## License

Source-available. See [LICENSE](LICENSE) for the full terms.

**Permitted without prior authorization:**
- Personal use.
- Internal organizational use, including internal commercial use (running the scripts on systems your organization owns, leases, or is authorized to administer).
- Local modifications for your own internal use.

**Requires written authorization from Hans Study:**
- Redistribution, republishing, mirroring, hosting, or sublicensing.
- Selling, leasing, renting, or providing the scripts as a paid product or hosted service.
- Including the scripts in another product, repository, or distribution channel.
- Distributing derivative works.

Authorization requests: [contact@hans.study](mailto:contact@hans.study).

**Attribution required in every authorized use:**
- Keep the [LICENSE](LICENSE) file intact.
- Keep the POWER_HEADER `.NOTES` block at the top of each `.ps1` file.
- Keep the console banner that prints during script execution (`Hans Study, CISSP | https://hans.study`).
- Visibly credit Hans Study (hans.study) in any derivative work, screenshot, blog post, video, presentation, or other public communication that incorporates or demonstrates the scripts.

No warranty. Test before production deployment. Hans Study accepts no liability for unintended consequences.
