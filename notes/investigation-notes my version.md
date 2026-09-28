# Investigation Notes 

## 1. Lab Preparation

A dedicated investigation directory was created:

```text
C:\LSASecretsLab
```

The evidence directory was:

```text
C:\LSASecretsLab\Evidence
```

The directory creation completed successfully.

## 2. Host Baseline

The host baseline was collected using:

```powershell
Get-CimInstance Win32_ComputerSystem |
Select-Object Name, Domain, DomainRole
```

The operating system information was collected using:

```powershell
Get-CimInstance Win32_OperatingSystem |
Select-Object Caption, Version, BuildNumber
```

The investigation timestamp was also recorded.

The host was operating in a WORKGROUP environment rather than a domain environment.

## 3. LSA Registry Location

The primary registry location investigated was:

```text
HKLM:\SECURITY\Policy\Secrets
```

The existence of the location was tested with:

```powershell
Test-Path "HKLM:\SECURITY\Policy\Secrets"
```

Result:

```text
True
```

The broader security policy location was also checked:

```powershell
Test-Path "HKLM:\SECURITY\Policy"
```

Result:

```text
True
```

No enumeration of individual secrets was performed.

## 4. Evidence Baseline

The LSA registry baseline was recorded in:

```text
LSA-Secrets-Baseline.txt
```

The recorded information included:

- Hostname
- LSA Secrets registry path
- Whether the path exists
- Investigation timestamp

This establishes the investigative context without exposing protected registry contents.

## 5. Sysmon Status

Sysmon was checked using:

```powershell
Get-Service Sysmon64 |
Select-Object Status, Name, DisplayName
```

Observed result:

```text
Status  Name     DisplayName
------  ----     -----------
Running Sysmon64 Sysmon64
```

Therefore, Sysmon was active during the investigation.

## 6. Registry Event Review

The investigation reviewed:

- Sysmon Event ID 12
- Sysmon Event ID 13
- Sysmon Event ID 14

These represent:

- Event ID 12 — Registry object create/delete
- Event ID 13 — Registry value set
- Event ID 14 — Registry key/value rename

The registry search returned multiple events.

Observed examples included:

```text
28-09-2026 07:49:31
28-09-2026 07:49:36
28-09-2026 07:49:40
28-09-2026 07:50:11
```

The LSA-related search returned two Event ID 13 records at:

```text
28-09-2026 07:40:23
```

The available screenshot only shows:

```text
Registry value set:...
```

Therefore, the complete event payload is not available in the captured evidence.

## 7. Interpretation of Registry Events

The presence of a registry event associated with an LSA-related path indicates that Sysmon recorded registry activity matching the search condition.

It does not independently prove:

- Credential theft
- Secret extraction
- Malicious activity
- Successful access to a specific secret
- Disclosure of a credential

A registry event should therefore be correlated with process and user telemetry before assigning security significance.

## 8. Process Creation Investigation

Sysmon Event ID 1 was searched for commonly relevant processes:

```text
powershell.exe
cmd.exe
reg.exe
rundll32.exe
wmic.exe
```

The query returned repeated process creation events.

The observed process creation activity ranged approximately from:

```text
28-09-2026 07:54:59
```

to:

```text
28-09-2026 07:57:24
```

The captured output displays:

```text
Process Create:...
```

rather than the complete event payload.

Consequently, the screenshots alone do not establish the exact command line, parent process, user, or process ID for every returned event.

## 9. Wazuh Investigation

Wazuh was queried using the endpoint identity:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

The investigation focused on the same general time period as the local Sysmon review.

A Wazuh process creation event was captured with:

```text
Image:
C:\Windows\System32\cmd.exe
```

The associated command line was:

```text
C:\WINDOWS\system32\cmd.exe /d /s /c "reg query "HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.manageengine.devicetrust" /ve"
```

The process had:

```text
Integrity Level: Medium
```

The working directory was associated with:

```text
C:\Users\Dell\AppData\Local\Programs\Zoho Mail - Desktop\
```

## 10. Wazuh Event Interpretation

The captured Wazuh event demonstrates that Windows command-line activity was being collected by Wazuh.

However, the registry path queried in that event was:

```text
HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.manageengine.devicetrust
```

This is not the LSA Secrets location.

Therefore, this particular event should not be treated as evidence of LSA Secrets access.

It is useful as contextual process telemetry demonstrating the type of information available for correlation.

## 11. Evidence Correlation

The investigation can be represented as:

```text
LSA Registry Location
        |
        v
Sysmon Registry Event
        |
        v
Timestamp
        |
        v
Process Creation
        |
        v
Command Line
        |
        v
User / Logon Context
        |
        v
Wazuh Telemetry
```

The captured evidence provides portions of this chain but not the complete chain for every registry event.

## 12. Current Assessment

### Confirmed

- The LSA Secrets registry location exists.
- Sysmon is running.
- Sysmon registry telemetry is available.
- Sysmon Event ID 12 and Event ID 13 activity was observed.
- The LSA-related search returned Event ID 13 records.
- Sysmon process creation telemetry is available.
- Wazuh is receiving Windows process telemetry.

### Not Established

The available evidence does not establish:

- Actual extraction of an LSA secret
- Disclosure of credentials
- Malicious use of the LSA Secrets location
- The specific process responsible for the two LSA-related Event ID 13 records
- The complete command line associated with those registry events
- A confirmed security incident

## 13. DFIR Considerations

For a real investigation, the next level of analysis would be to retrieve the complete Sysmon event payload and correlate:

```text
Event Timestamp
Process GUID
Process ID
Image
Command Line
Parent Image
Parent Process ID
User
Integrity Level
Logon ID
Registry Object
Registry Value
```

The same identifiers could then be correlated with Wazuh records and other endpoint telemetry.

