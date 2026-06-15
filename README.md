<div align="center">

# 🛡️ SOC Home Lab — Detection Engineering with Wazuh & Sysmon

**A self-built SOC environment: deploy → instrument → attack → detect → triage → tune**

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh%204.9.2-1A73E8?style=flat-square)
![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-0078D6?style=flat-square&logo=windows)
![MITRE](https://img.shields.io/badge/Mapped%20to-MITRE%20ATT%26CK-CC0000?style=flat-square)
![Atomic Red Team](https://img.shields.io/badge/Simulation-Atomic%20Red%20Team-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)

</div>

---

## 📌 Overview

This lab simulates a small enterprise environment to practice the full SOC analyst workflow — not just running tools, but building the infrastructure, instrumenting an endpoint, emulating real adversary behavior, and then **investigating the alerts as a Tier 1/2 analyst would**, including identifying detection gaps and writing tuning recommendations.

> 💡 **Why this matters:** Most "SOC labs" stop at installing a SIEM. This one goes further — every alert below is mapped to MITRE ATT&CK, analyzed for *why* it fired (or didn't), and paired with a concrete remediation/tuning step.

---

## 🏗️ Architecture

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│   Ubuntu Desktop 24.04 (VM)  │         │   Windows 10 Enterprise (VM)   │
│   ───────────────────────    │         │   ──────────────────────────  │
│   • Wazuh Manager             │ ◄─────► │   • Wazuh Agent v4.9.2         │
│   • Wazuh Indexer             │  soclab │   • Sysmon (SwiftOnSecurity)   │
│   • Wazuh Dashboard           │ network │   • Atomic Red Team            │
│   6 GB RAM · 2 vCPU            │ 192.168.1.0/24 │  4 GB RAM · 2 vCPU       │
└─────────────────────────────┘         └──────────────────────────────┘
        Host: VirtualBox on Linux (16 GB RAM)
```

| Layer | Tool | Purpose |
|:--|:--|:--|
| 🖥️ Hypervisor | **VirtualBox** | Hosts both VMs on an isolated internal network |
| 🧠 SIEM / XDR | **Wazuh 4.9.2** | Log ingestion, correlation, alerting, dashboard |
| 🔍 Telemetry | **Sysmon** (SwiftOnSecurity config) | High-fidelity process, file & network events |
| ⚔️ Adversary Emulation | **Atomic Red Team** + manual TTPs | Realistic attack simulation |
| 🗺️ Framework | **MITRE ATT&CK** | Mapping every detection to a known technique |

---

## ⚙️ Setup Walkthrough

<details>
<summary><b>1. Hypervisor & Networking</b></summary>

- Installed VirtualBox on the Linux host.
- Created an **Internal Network** (`soclab`) so the Wazuh server and Windows endpoint communicate privately on `192.168.1.0/24`.
- Each VM also given a NAT adapter for internet access during initial setup/updates.
</details>

<details>
<summary><b>2. Wazuh Server Deployment</b></summary>

- Installed Ubuntu Desktop 24.04 (6 GB RAM, 2 vCPU).
- Deployed Wazuh **all-in-one** via the official installer:

  ```bash
  curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
  sudo bash wazuh-install.sh -a -i
  ```

- This provisions the **indexer, manager, and dashboard** together, auto-generates TLS certs, and prints admin credentials on completion.
</details>

<details>
<summary><b>3. Windows Endpoint & Agent</b></summary>

- Installed Windows 10 Enterprise (Evaluation), static IP on `soclab`.
- Installed the Wazuh Agent (version-matched to the server, **4.9.2**) via MSI:

  ```powershell
  msiexec.exe /i wazuh-agent-4.9.2-1.msi /q WAZUH_MANAGER="192.168.1.14"
  ```

- Confirmed registration as **Active** in the Wazuh dashboard's Endpoints view.
</details>

<details>
<summary><b>4. Enhanced Logging with Sysmon</b></summary>

- Installed **Sysmon** with the community-standard **SwiftOnSecurity** config for high-signal process/file/network telemetry.
- Added a `<localfile>` block to the agent's `ossec.conf` to forward `Microsoft-Windows-Sysmon/Operational` events:

  ```xml
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  ```

- Validated end-to-end log flow via Wazuh's **Threat Hunting** module before moving to attack simulation.
</details>

<details>
<summary><b>5. Attack Simulation</b></summary>

- Used **Atomic Red Team** for framework-driven technique execution.
- Supplemented with **manual command-line TTPs** (process masquerading, abnormal shell spawning) for realism and to test detection coverage beyond canned tests.
</details>

---

## 🔎 Detection Writeups

### 🟥 1 · Credential Dumping Simulation → Suspicious File Drop
**MITRE:** `T1105` Ingress Tool Transfer · `T1003.001` LSASS Memory *(Command & Control / Credential Access)*

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 10
```
Runs Mimikatz **reflectively inside PowerShell** (`sekurlsa::logonpasswords`) to dump in-memory credentials — no new `mimikatz.exe` process is spawned.

| | |
|---|---|
| **Alert** | `Rule 92213` — *"Executable file dropped in folder commonly used by malware"* |
| **Severity** | 🔴 **Level 15** (near-maximum) |
| **Trigger** | `powershell.exe` writing a script to `%TEMP%` |

📸 *Attack output:*
![Mimikatz execution](screenshots/01-t1003-mimikatz-output.png)

📸 *Wazuh alert detail:*
![Level 15 alert T1105](screenshots/02-alert-level15-T1105.png)

> **🕳️ Detection Gap Found:** Because Mimikatz ran in-process, the *actual* credential theft (LSASS memory access) would appear as Sysmon **Event ID 10 (ProcessAccess)** — but a search for `data.win.system.eventID: 10` returned **zero results**. The SwiftOnSecurity config excludes this event by default.
>
> **🔧 Tuning Recommendation:** Enable Sysmon EID 10 with a targeted filter — alert when a non-security process opens a handle to `lsass.exe` — to catch credential dumping directly rather than via side effects.

---

### 🟧 2 · Process Masquerading — `cmd.exe` Disguised as `svchost.exe`
**MITRE:** `T1036` Masquerading · `T1055` Process Injection *(Defense Evasion / Privilege Escalation)*

```powershell
copy C:\Windows\System32\cmd.exe C:\Users\Public\svchost.exe
C:\Users\Public\svchost.exe /c "whoami"
```
A copy of `cmd.exe` renamed to mimic a trusted system process and run from a world-writable path — a textbook malware tactic.

| | |
|---|---|
| **Alert** | `Rule 61618` — *"Sysmon - Suspicious Process - svchost.exe"* |
| **Severity** | 🟠 **Level 12** |
| **Key Indicator** | `originalFileName: Cmd.Exe` ≠ `image: C:\Users\Public\svchost.exe` |

📸 *Attack output:*
![svchost masquerade output](screenshots/04-svchost-masquerade-cmd-output.png)

📸 *Process metadata mismatch:*
![svchost field details](screenshots/05-alert-svchost-fields.png)

📸 *Wazuh alert detail:*
![Level 12 alert T1055](screenshots/06-alert-level12-T1055.png)

> **🧩 Analysis:** Sysmon captured the parent process (`powershell.exe`, **High** integrity), full file hashes (MD5/SHA256), and the PE-internal `originalFileName` — which doesn't match the on-disk filename. This mismatch is one of the most reliable masquerading signatures available.
>
> **✅ Response:** Treat any `originalFileName` ≠ filename mismatch as high priority — isolate host, check the captured hash against threat intel, and pivot to the parent PowerShell process for further compromise.

---

### 🟨 3 · Abnormal Process Spawning a Command Shell
**MITRE:** `T1059.003` Windows Command Shell *(Execution)*

```powershell
copy C:\Windows\System32\cmd.exe C:\Users\Public\Downloads\update.exe
C:\Users\Public\Downloads\update.exe /c "whoami & hostname"
```
Same masquerading pattern as #2, but renamed as `update.exe` and run from `Downloads` — used here to simulate post-compromise recon (`whoami`, `hostname`).

| | |
|---|---|
| **Alert** | `Rule 92052` — *"Windows command prompt started by an abnormal process"* |
| **Severity** | 🟡 **Level 4** |
| **Trigger** | Command shell (renamed `cmd.exe`) spawned by `powershell.exe` from a user download directory |

📸 *Attack output:*
![update.exe output](screenshots/07-update-exe-cmd-output.png)

📸 *Field details:*
![update.exe fields](screenshots/08-alert-update-exe-fields.png)

📸 *Wazuh alert detail:*
![Level 4 alert T1059](screenshots/09-alert-level4-T1059.png)

> **🔗 Correlation:** On its own this is low severity — but combined with alert #2 (same masquerading technique, same parent), it forms a **strong composite indicator**: repeated renamed-`cmd.exe` executions from user-writable paths, spawned by PowerShell. This pattern alone should justify escalation and host isolation.

---

## 📊 Lab-Wide Stats (24h snapshot)

| Metric | Value |
|:--|:--:|
| Total alerts ingested | **827** |
| Alerts at Level ≥ 12 | **34** |
| Authentication successes | **38** |
| Authentication failures | **1** |

**Top MITRE techniques observed:** Ingress Tool Transfer · Account Discovery · Lateral Tool Transfer · PowerShell · Windows Command Shell · Disable/Modify Tools

📸 *Endpoint status — agent active and reporting:*
![Agent active](screenshots/10-agent-active-overview.png)

---

## 🧠 Skills Demonstrated

- ✅ SIEM deployment & administration (Wazuh indexer / manager / dashboard)
- ✅ Endpoint instrumentation with Sysmon (custom config + log forwarding via `ossec.conf`)
- ✅ Threat hunting & log analysis (Wazuh Discover / Threat Hunting)
- ✅ Adversary emulation (Atomic Red Team + manual TTPs)
- ✅ MITRE ATT&CK mapping and alert triage
- ✅ **Detection gap analysis** and tuning recommendations
- ✅ Incident documentation written for handoff/escalation

---

## 🗂️ Repository Structure

```
soc-home-lab/
├── README.md
└── screenshots/
    ├── 01-t1003-mimikatz-output.png
    ├── 02-alert-level15-T1105.png
    ├── 03-dashboard-overview.png
    ├── 04-svchost-masquerade-cmd-output.png
    ├── 05-alert-svchost-fields.png
    ├── 06-alert-level12-T1055.png
    ├── 07-update-exe-cmd-output.png
    ├── 08-alert-update-exe-fields.png
    ├── 09-alert-level4-T1059.png
    └── 10-agent-active-overview.png
```

---

<div align="center">

*Built as a hands-on SOC analyst portfolio project — infrastructure, detection, and analysis end to end.*

</div>
