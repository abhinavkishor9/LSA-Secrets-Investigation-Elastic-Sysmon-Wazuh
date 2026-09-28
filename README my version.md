# LSA-Secrets-Investigation-Elastic-Sysmon-Wazuh
## Overview
LSA Secrets are protected Windows secrets stored by the Local Security Authority. Windows and installed applications can use them to store sensitive information such as:

Service-account credentials
Cached authentication-related secrets
Machine/application secrets
Credentials used by scheduled or background services
Other protected configuration secrets

The important DFIR question is not simply:

"Can I extract the secret?"

Instead:

Which process accessed protected LSA-related areas, under which account, when, and what process/user context surrounded the access?

This lab focuses on the detection and investigation of activity potentially associated with Windows LSA (Local Security Authority) Secrets.

LSA Secrets are protected Windows security-related data stored by the Local Security Authority. They may be used by Windows and applications to maintain sensitive information associated with services, authentication, scheduled tasks, and other protected system functions.

The objective of this lab was not to extract or expose credentials. Instead, the investigation focused on understanding how a SOC/DFIR analyst can identify and correlate telemetry surrounding protected LSA-related registry locations.

The investigation was performed on a Windows 11 Pro workstation operating in a WORKGROUP environment, using Sysmon and Wazuh telemetry.

## Lab Objectives

The objectives of this lab are to:

- Understand the role of Windows Local Security Authority (LSA) Secrets and why they are relevant to credential-access investigations.
- Identify the protected `HKLM:\SECURITY\Policy\Secrets` registry location without enumerating or exposing its contents.
- Establish a baseline of the Windows workstation, operating system, investigation time, and relevant registry locations.
- Verify that Sysmon is active and determine whether registry telemetry is available through Event IDs 12, 13, and 14.
- Investigate Sysmon registry events associated with LSA-related paths and document the available telemetry.
- Review Sysmon Event ID 1 process creation events for processes that may provide useful context during a credential-access investigation.
- Correlate registry activity with process execution, timestamps, command-line information, and user context where the telemetry is available.
- Examine Wazuh telemetry for corresponding Windows process and registry activity during the investigation window.
- Distinguish confirmed observations from assumptions when interpreting LSA-related telemetry.
- Identify limitations in Sysmon and Wazuh visibility and document situations where the available evidence is insufficient for attribution.
- Build a basic DFIR timeline connecting registry events, process activity, and SIEM telemetry.
- Practice investigating potential LSA-related activity without dumping, extracting, or exposing actual credentials or protected secret values.

## Lab Scenario

A Windows 11 Pro workstation is being investigated for activity potentially associated with access to protected **LSA (Local Security Authority) Secrets**. LSA Secrets are security-sensitive Windows data that can contain credentials and other protected configuration information used by services, applications, and the operating system. Because unauthorized access to these areas can be relevant to credential-access investigations, the objective is to determine whether suspicious or unusual activity is visible in available endpoint telemetry.

The investigation is performed without extracting, dumping, enumerating, or exposing the actual secret values. Instead, the analyst focuses on observable evidence such as registry activity, process creation, command-line information, user context, parent-child relationships, and timestamps.

### Investigation Focus

The analyst will investigate:

- Whether the protected `HKLM:\SECURITY\Policy\Secrets` registry location exists on the workstation.
- Whether Sysmon records registry activity associated with LSA-related paths.
- Which processes were created around the observed registry activity.
- Whether command-line and parent-process information provides useful investigative context.
- Whether Wazuh provides additional process or registry telemetry for the investigation window.
- Whether the available evidence supports a confirmed finding, a plausible explanation, or only an investigative lead.
- What telemetry limitations prevent stronger attribution or conclusions.

### Investigation Scenario

The analyst begins by establishing a baseline of the workstation, operating system, investigation time, and LSA-related registry locations. Sysmon telemetry is then reviewed for registry events associated with the protected LSA area, followed by process-creation events that may provide surrounding execution context.

The resulting telemetry is correlated by **time, process, registry activity, user context, and parent process information** where available. Wazuh is used as an additional telemetry source to determine whether the same investigation window contains relevant Windows process or registry events.

The investigation follows an evidence-first approach: **an observed registry event is treated as evidence of registry activity, not automatically as proof of credential theft or LSA Secret extraction**. Missing or incomplete telemetry is documented as a visibility limitation rather than interpreted as proof that no activity occurred.

### Safety Boundary

This lab is intentionally limited to defensive detection and forensic investigation. It does **not** attempt to:

- Dump LSA Secrets.
- Extract passwords or credential material.
- Enumerate protected secret values.
- Modify protected LSA configuration.
- Perform credential theft.

The expected outcome is a documented investigation showing how Windows endpoint telemetry can be used to examine potential LSA-related activity while preserving the confidentiality of protected secret data.

  
## Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows 11 Pro |
| Environment | WORKGROUP |
| Endpoint | DESKTOP-9MMM37V |
| Telemetry | Sysmon |
| SIEM / Monitoring | Wazuh |
| Sysmon Log | Microsoft-Windows-Sysmon/Operational |
| Wazuh Agent | 001 |
| Lab Directory | `C:\LSASecretsLab` |
| Evidence Directory | `C:\LSASecretsLab\Evidence` |

## Investigation Approach

The investigation followed a correlation-based DFIR workflow:

```text
Host Baseline
      |
      v
LSA Registry Location
      |
      v
Sysmon Registry Telemetry
      |
      v
Process Creation Telemetry
      |
      v
Wazuh Correlation
      |
      v
Timeline Analysis
      |
      v
Visibility Assessment
```

The main investigative relationship was:

```text
Process
  |
  +--> User / Logon Context
  |
  +--> Command Line
  |
  +--> Parent Process
  |
  +--> Registry Activity
  |
  +--> Timestamp
  |
  +--> Wazuh Telemetry
```

## LSA Registry Location

The investigation focused on:

```text
HKLM:\SECURITY\Policy\Secrets
```

The existence of the location was verified without enumerating or extracting the protected secret contents.

The broader security policy location was also checked:

```text
HKLM:\SECURITY\Policy
```

Both locations returned `True` during the baseline verification.

## Evidence Collection

The following evidence files were created under:

```text
C:\LSASecretsLab\Evidence
```

- `Host-Role.txt`
- `Operating-System.txt`
- `Investigation-Time.txt`
- `LSA-Secrets-Baseline.txt`
- `LSA-Investigation-Telemetry.txt`
- `Investigation-Summary.txt`

These files provide a basic record of the host, operating system, investigation time, LSA registry location, and collected Sysmon telemetry.

## Sysmon Investigation

Sysmon was confirmed to be running:

```text
Status  Name     DisplayName
------  ----     -----------
Running Sysmon64 Sysmon64
```

The investigation reviewed the following Sysmon event types:

| Event ID | Purpose |
|---|---|
| 1 | Process creation |
| 12 | Registry object create/delete |
| 13 | Registry value set |
| 14 | Registry key/value rename |

The registry telemetry search returned Sysmon Event ID 13 records matching the investigation search for the LSA-related registry path.

Observed matching events included:

```text
28-09-2026 07:40:23
```

The broader Sysmon registry review also returned Event ID 12 and Event ID 13 activity around:

```text
28-09-2026 07:49:31
28-09-2026 07:49:36
28-09-2026 07:49:40
28-09-2026 07:50:11
```

The available screenshot output shows event summaries rather than the complete event payloads. Therefore, the exact registry value names, processes responsible for each event, and complete access context cannot be established from the captured output alone.

## Process Investigation

Sysmon Event ID 1 was queried for processes commonly relevant to credential-access investigations:

```text
powershell.exe
cmd.exe
reg.exe
rundll32.exe
wmic.exe
```

The query returned repeated process creation events between approximately:

```text
28-09-2026 07:54:59
```

and:

```text
28-09-2026 07:57:24
```

The captured output only displays:

```text
Process Create:...
```

Therefore, the complete command lines and parent processes are not available in the screenshot evidence.

This is an important limitation because process context is required before interpreting a registry-related event as suspicious.

## Wazuh Telemetry

Wazuh telemetry was reviewed for:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

A captured Wazuh event showed a Windows Command Processor execution:

```text
C:\Windows\System32\cmd.exe
```

The command line observed was:

```text
C:\WINDOWS\system32\cmd.exe /d /s /c "reg query "HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.manageengine.devicetrust" /ve"
```

The event showed:

- Process: `cmd.exe`
- Integrity level: Medium
- Current directory associated with Zoho Mail Desktop
- Windows Command Processor description

This particular Wazuh event does not demonstrate access to LSA Secrets. It is relevant as surrounding process telemetry and demonstrates why command-line context must be correlated with the registry path being investigated.

## Investigation Limitation

A registry event matching an LSA-related path should not automatically be interpreted as credential theft.

A stronger investigation would require correlation between:

```text
Registry Activity
        +
Process Identity
        +
Command Line
        +
Parent Process
        +
User / Logon Context
        +
Timestamp
        +
Related Security Telemetry
```

The screenshots captured for this lab do not provide the complete payload for every matching Sysmon event. Therefore, conclusions are limited to what can be supported by the available telemetry.

Absence of a specific LSA-related event also cannot be treated as proof that no access occurred.

