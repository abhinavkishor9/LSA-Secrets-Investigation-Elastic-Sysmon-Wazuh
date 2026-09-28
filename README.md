# LSA Secrets Investigation — Elastic, Sysmon & Wazuh

## Overview

This lab focuses on the detection and investigation of activity potentially associated with Windows LSA (Local Security Authority) Secrets.

LSA Secrets are protected Windows security-related data stored by the Local Security Authority. They may be used by Windows and applications to maintain sensitive information associated with services, authentication, scheduled tasks, and other protected system functions.

The objective of this lab was not to extract or expose credentials. Instead, the investigation focused on understanding how a SOC/DFIR analyst can identify and correlate telemetry surrounding protected LSA-related registry locations.

The investigation was performed on a Windows 11 Pro workstation operating in a WORKGROUP environment, using Sysmon and Wazuh telemetry.

## Investigation Objective

The primary objective was to investigate whether available endpoint telemetry could provide useful evidence of activity associated with:

- Windows LSA Secrets
- The protected `HKLM:\SECURITY\Policy\Secrets` registry location
- Registry modification events
- Process creation activity
- Command-line execution
- User and process context
- Wazuh ingestion of Sysmon telemetry
- Visibility limitations affecting LSA-related investigations

The investigation deliberately avoided extracting, dumping, or disclosing actual LSA secret values.

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

## Key Findings

The investigation confirmed that:

1. The protected LSA Secrets registry location exists on the system.
2. Sysmon is running and producing registry telemetry.
3. Sysmon Event ID 13 records were returned by the LSA-related registry search.
4. Additional Sysmon Event ID 12 and Event ID 13 activity was observed during the investigation period.
5. Process creation telemetry was available through Sysmon Event ID 1.
6. Wazuh was ingesting Windows process telemetry from the endpoint.
7. A captured Wazuh `cmd.exe` event showed registry activity against an unrelated Edge Native Messaging registry location.
8. The available evidence does not establish that an LSA secret was extracted or disclosed.
9. The available evidence does not, by itself, establish malicious activity.

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

## Security Perspective

From a SOC/DFIR perspective, LSA-related activity becomes more meaningful when it occurs alongside suspicious process execution, unexpected administrative activity, credential-access behavior, or other indicators of compromise.

The appropriate investigative approach is therefore:

```text
Detect
  |
  v
Identify Process
  |
  v
Identify User
  |
  v
Review Command Line
  |
  v
Review Parent Process
  |
  v
Correlate Registry Activity
  |
  v
Review Related Telemetry
  |
  v
Assess Evidence and Limitations
```

## Safety Boundary

This lab intentionally does not:

- Dump LSA Secrets
- Extract credentials
- Display protected secret values
- Modify protected security configuration
- Simulate credential theft against real accounts

The investigation is based on safe artifact and telemetry analysis.

## Learning Outcomes

This lab demonstrates practical experience with:

- Windows LSA concepts
- Windows registry investigation
- Sysmon Event ID 1
- Sysmon Event IDs 12, 13 and 14
- Wazuh endpoint telemetry
- Process-to-registry correlation
- Command-line investigation
- DFIR timeline construction
- Evidence-based conclusions
- Telemetry visibility limitations

## Investigation Principle

> Follow the evidence, not the assumption.

A registry event is an observation.

A suspicious process is an observation.

A command line is an observation.

The investigative conclusion should only be stronger than those observations when the available evidence supports it.
