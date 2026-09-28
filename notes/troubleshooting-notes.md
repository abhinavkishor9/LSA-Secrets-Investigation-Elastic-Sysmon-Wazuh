# Troubleshooting Notes — LSA Secrets Investigation

## Overview

This document records troubleshooting observations and investigation limitations encountered while performing the LSA Secrets investigation.

The purpose is to distinguish genuine telemetry findings from situations where the available data was incomplete.

## 1. LSA Secrets Registry Location

### Check

```powershell
Test-Path "HKLM:\SECURITY\Policy\Secrets"
```

### Result

```text
True
```

The registry location exists on the workstation.

### Investigation Decision

The lab did not enumerate the contents of the Secrets key.

This was intentional because the objective was telemetry investigation rather than credential extraction.

## 2. Sysmon Service Verification

### Check

```powershell
Get-Service Sysmon64 |
Select-Object Status, Name, DisplayName
```

### Result

```text
Status  Name     DisplayName
------  ----     -----------
Running Sysmon64 Sysmon64
```

### Interpretation

Sysmon was running and available for telemetry collection.

## 3. Sysmon Registry Telemetry

The following event IDs were investigated:

```text
12
13
14
```

The registry search returned multiple events, including Event ID 12 and Event ID 13.

Observed timestamps included:

```text
28-09-2026 07:49:31
28-09-2026 07:49:36
28-09-2026 07:49:40
28-09-2026 07:50:11
```

The LSA-specific search returned Event ID 13 records at:

```text
28-09-2026 07:40:23
```

### Limitation

The screenshot output displays abbreviated messages:

```text
Registry value set:...
```

Therefore, the complete event details are not available in the captured evidence.

### Troubleshooting Lesson

When investigating registry events, a summary table alone may not provide enough information for attribution.

The complete event payload should be retained when possible.

## 4. Registry Search Matching

The investigation searched for LSA-related registry activity.

The search included the protected location:

```text
HKLM\SECURITY\Policy\Secrets
```

A matching event does not automatically mean that a secret was accessed or extracted.

### Important Distinction

```text
Registry telemetry
        !=
Credential theft
```

The event establishes telemetry matching the search criteria. Additional evidence is required before determining why the registry activity occurred.

## 5. Process Creation Search

The investigation searched Sysmon Event ID 1 for:

```text
powershell.exe
cmd.exe
reg.exe
rundll32.exe
wmic.exe
```

Multiple process creation events were returned between approximately:

```text
07:54:59
```

and:

```text
07:57:24
```

### Limitation

The captured screenshot shows:

```text
Process Create:...
```

instead of the full event details.

Therefore, the screenshot cannot independently establish the exact process-to-registry relationship.

### Troubleshooting Lesson

Process name filtering is useful for discovery, but it should not be treated as proof of malicious behavior.

The command line, parent process, user, integrity level, and timing are required for stronger attribution.

## 6. Wazuh Process Telemetry

A Wazuh event was captured for:

```text
C:\Windows\System32\cmd.exe
```

The associated command line queried:

```text
HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.manageengine.devicetrust
```

### Important Observation

This registry location is different from:

```text
HKLM\SECURITY\Policy\Secrets
```

Therefore, the event should not be classified as LSA Secrets access.

### Why It Matters

This demonstrates why registry investigation must consider the exact path rather than simply the presence of `reg.exe` or `cmd.exe`.

## 7. Absence of LSA-Specific Wazuh Events

If Wazuh does not return an event specifically matching the LSA Secrets path, that should be documented as a telemetry visibility limitation.

It should not be rewritten as:

```text
No LSA access occurred.
```

A more accurate conclusion is:

```text
No LSA-specific event was identified in the available Wazuh telemetry for the investigated period.
```

This distinction is important in DFIR.

## 8. Sysmon Event Coverage

Sysmon Event IDs 12, 13 and 14 provide useful registry telemetry, but they do not represent every possible registry access.

The absence of an event can therefore have several explanations:

- The relevant action did not generate the configured event type.
- The Sysmon configuration did not capture the activity.
- The activity occurred outside the investigated time range.
- The search condition did not match the event representation.
- The telemetry was not successfully forwarded to Wazuh.
- The event was not retained in the queried log window.

Therefore:

```text
No matching event
        !=
No activity
```

## 9. Incomplete Event Payloads

Several screenshots contain abbreviated PowerShell output such as:

```text
Process Create:...
```

and:

```text
Registry value set:...
```

This means the screenshots are useful evidence of event existence but are insufficient for complete forensic attribution.

For future investigations, retain the complete event properties where possible.

Useful fields include:

```text
UtcTime
ProcessGuid
ProcessId
Image
CommandLine
ParentImage
ParentProcessId
User
IntegrityLevel
LogonId
TargetObject
Details
```

## 10. Investigation Time Correlation

The investigation contained multiple timestamps:

```text
07:40:23
07:43:33
07:49:31
07:49:36
07:49:40
07:50:11
07:54:59
07:55:04
...
07:57:24
```

These should not automatically be treated as one continuous malicious sequence.

Each event should be evaluated based on:

- Exact timestamp
- Event type
- Process identity
- Command line
- User
- Parent process
- Registry object
- Related telemetry

## 11. Evidence Handling

The investigation evidence was stored under:

```text
C:\LSASecretsLab\Evidence
```

Expected files include:

```text
Host-Role.txt
Operating-System.txt
Investigation-Time.txt
LSA-Secrets-Baseline.txt
LSA-Investigation-Telemetry.txt
Investigation-Summary.txt
```

The evidence directory provides a reproducible structure for the lab.

## 12. Safety Boundary

The investigation deliberately avoided:

- Dumping LSA Secrets
- Extracting credentials
- Enumerating secret values
- Publishing secret material
- Modifying protected security data

The lab therefore remains focused on detection, telemetry, and DFIR methodology.

## 13. Final Troubleshooting Assessment

The lab successfully demonstrated:

```text
LSA Registry Exists
        |
        v
Sysmon Running
        |
        v
Registry Telemetry Available
        |
        v
LSA-Related Event Matches Observed
        |
        v
Process Telemetry Available
        |
        v
Wazuh Telemetry Available
```

The main limitation was incomplete event payload visibility in the captured screenshots.

The correct response to that limitation is to document it and avoid making unsupported conclusions.
