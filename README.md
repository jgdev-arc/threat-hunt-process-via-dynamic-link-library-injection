<img src="https://github.com/user-attachments/assets/1f32eddf-ef47-4df5-b4a6-2c0c43d1286f" width="400"/>

# Threat Hunt Report: Process Injection via DLL Injection (T1055.001)

This threat hunt investigates **DLL Injection** as a method of process injection, commonly used by adversaries to execute malicious code within the address space of another process. The `rundll32.exe` binary was monitored for suspicious behavior, as it is frequently abused to execute malicious DLLs.

---

## 🛠 Platforms and Tools Used

- **Microsoft Azure** (Windows Virtual Machine: `vm-test-zedd`)
- **Microsoft Defender for Endpoint** (EDR Telemetry and Threat Hunting Platform)
- **Kusto Query Language (KQL)** for querying process, alert, image load, and file event telemetry
- **Atomic Red Team** (T1055.001 simulation tests)
- **PowerShell** for manual invocation and telemetry review

---

## 🧪 Scenario Overview

The objective of this threat hunt is to simulate and identify **DLL Injection activity** using `rundll32.exe`, a native Windows binary that can be abused to execute arbitrary DLL functions. Simulations were carried out using the Atomic Red Team test for [T1055.001](https://attack.mitre.org/techniques/T1055/001/) on the test machine `vm-test-zedd`. Various telemetry sources were reviewed to assess system response and visibility.

---

## 🔍 IoC-Based Threat Hunting Plan

- **Process Execution:**
  - Detect execution of `rundll32.exe` with unusual DLLs or arguments.
- **Image Load Activity:**
  - Check for suspicious DLLs being loaded into legitimate processes.
- **Defender Alerts:**
  - Identify whether any Defender alerts were triggered during the DLL injection simulation.
- **File Creation or Dropping:**
  - Look for payload DLLs or temporary files created during injection.
- **Script Block Logging:**
  - Capture any obfuscated PowerShell or scripting activity used in the attack chain.

---

## 🔍 Investigation Steps

### 🧪 Suspicious rundll32.exe Executions Observed

Multiple instances of `rundll32.exe` were executed on the target system. While many of these were legitimate system or application-related tasks, they were reviewed in the context of potential DLL injection.

- **Device:** vm-test-zedd  
- **Accounts:** SYSTEM, labuser  
- **Command Line Examples:**
  - `rundll32.exe AppXDeploymentExtensions.OneCore.dll,ShellRefresh`
  - `"rundll32.exe" Startupscan.dll,SusRunTask`
  - `"rundll32.exe" C:\Windows\system32\PcaSvc.dll,PcaPatchSdbTask`
- **Parent Process:** `svchost.exe`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "vm-test-zedd"
| where FileName =~ "rundll32.exe"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
![1](https://github.com/user-attachments/assets/eccadc9c-434e-4b00-a3d9-27a2d73b578c)

---

### 🧬 Image Load Activity – No Results Found

To determine whether any DLLs were injected into legitimate processes, image load telemetry was queried. However, no evidence of DLL loading triggered by `rundll32.exe` or a custom injector was found.

**KQL Query Used:**
```kql
DeviceImageLoadEvents
| where DeviceName == "vm-test-zedd"
| where InitiatingProcessFileName has_any ("rundll32.exe", "injector.exe")
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName
| order by Timestamp desc
```

---

## 🕒 Chronological Timeline of Events – rundll32.exe Execution Reconnaissance

**Device:** `vm-test-zedd`  
**Date Range:** May 29–30, 2025

| **Time**             | **Event**                     | **Details** |
|----------------------|-------------------------------|-------------|
| May 30, 2025 5:41 PM | rundll32.exe execution        | `labuser` ran `rundll32.exe AppXDeploymentExtensions.OneCore.dll,ShellRefresh` |
| May 30, 2025 5:40 PM | rundll32.exe execution        | `system` ran `"rundll32.exe" C:\Windows\system32\PcaSvc.dll,PcaPatchSdbTask` |
| May 29, 2025 10:39 PM| rundll32.exe execution        | `system` ran `"rundll32.exe" C:\Windows\system32\PcaSvc.dll,PcaPatchSdbTask` |
| May 29, 2025 8:38 PM | rundll32.exe execution        | `labuser` ran `"rundll32.exe" Startupscan.dll,SusRunTask` |
| *(none)*             | 📁 Script Block Logging       | No script block logs were captured for rundll32 activity. |
| *(none)*             | 🧬 DLL Image Load Activity     | No DLL image loads were triggered by rundll32.exe. |
| *(none)*             | 🚨 Defender Alerts             | No Defender for Endpoint alerts were triggered by these events. |

---

## 🧾 Summary of Findings

Between **May 29 and May 30, 2025**, the endpoint **vm-test-zedd** executed multiple instances of `rundll32.exe`, initiated by both the `SYSTEM` and `labuser` accounts. These invocations of rundll32 were used to run various DLL exports, commonly seen in Windows system tasks. 

- No unusual DLLs or non-standard commands were detected.
- Execution context included `svchost.exe` as the parent process, consistent with legitimate Windows behavior.
- No corresponding script block logging events or image load events were identified.
- Microsoft Defender for Endpoint did not raise any alerts for the observed behavior.

The observed activity appears benign and consistent with normal system operations or controlled simulation.

---

## ✅ Containment and Remediation

- **No active threats identified**: Observed `rundll32.exe` executions did not display malicious behavior.
- **Verify context**: Ensure all rundll32 usages align with scheduled tasks, legitimate system services, or controlled red team exercises.
- **Continued monitoring**: Flag any future rundll32 executions with unusual DLLs, encoded arguments, or anomalous user context for further review.

No remediation actions are necessary at this time, but increased visibility is recommended.
