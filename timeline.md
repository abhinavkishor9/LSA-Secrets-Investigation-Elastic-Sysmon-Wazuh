# Investigation Timeline — LSA Secrets Investigation

## Timeline Overview

This timeline records the significant timestamps observed during the LSA Secrets investigation.

The timestamps are presented as observed in the captured Windows and Wazuh telemetry.

The timeline should be interpreted as an evidence chronology rather than proof of a single malicious sequence.

## Timeline

| Time | Source | Event | Interpretation |
|---|---|---|---|
| 07:40:23 | Sysmon | Event ID 13 — Registry value set | LSA-related registry search returned two matching registry value-set events. Exact event payload is not available in the screenshot. |
| 07:43:33 | Wazuh | Process creation telemetry | `cmd.exe` executed a registry query against an Edge Native Messaging registry location. |
| 07:49:31 | Sysmon | Event ID 13 — Registry value set | Multiple registry value-set events observed. |
| 07:49:36 | Sysmon | Event ID 12 — Registry object added/deleted | Registry object activity observed. |
| 07:49:40 | Sysmon | Event ID 13 — Registry value set | Registry value-set activity observed. |
| 07:50:11 | Sysmon | Event ID 13 — Registry value set | Multiple registry value-set events observed. |
| 07:54:59 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:55:04 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:55:09 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:55:15 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:55:20 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:55:25 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:55:30 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:55:35 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:55:41 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:55:46 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:55:51 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:55:56 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:01 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:07 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:12 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:17 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:22 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:27 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:33 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:38 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:43 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:48 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:53 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:56:58 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:57:04 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:57:09 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:57:14 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:57:19 | Sysmon | Event ID 1 — Process creation | Process creation event returned by the investigation query. |
| 07:57:24 | Sysmon | Event ID 1 — Process creation | Latest process creation event visible in the captured output. |

## Baseline Activities

Before the telemetry analysis, the following activities were performed:

1. Created `C:\LSASecretsLab`.
2. Created the `Evidence` subdirectory.
3. Recorded host information.
4. Recorded operating system information.
5. Recorded the investigation timestamp.
6. Verified the existence of `HKLM:\SECURITY\Policy\Secrets`.
7. Verified the existence of `HKLM:\SECURITY\Policy`.
8. Confirmed that Sysmon was running.

## LSA-Related Observation

The most directly relevant telemetry was observed at:

```text
28-09-2026 07:40:23
```

The Sysmon query returned two Event ID 13 records matching the LSA-related registry search.

The captured output identifies them as:

```text
Registry value set:...
```

The exact registry value and complete event metadata were not visible in the screenshot.

## Wazuh Observation

At:

```text
28-09-2026 07:43:33
```

Wazuh displayed a process creation event for:

```text
C:\Windows\System32\cmd.exe
```

The command line queried:

```text
HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.manageengine.devicetrust
```

This is not the LSA Secrets registry location.

Therefore, this event is treated as surrounding endpoint telemetry rather than confirmed LSA Secrets activity.

## Registry Telemetry Burst

Between approximately:

```text
07:49:31
```

and:

```text
07:50:11
```

the Sysmon registry query returned multiple Event ID 12 and Event ID 13 records.

These demonstrate registry activity during the investigation period.

However, the captured summaries do not provide enough information to attribute every event to a particular process or user.

## Process Creation Activity

From approximately:

```text
07:54:59
```

through:

```text
07:57:24
```

the Sysmon Event ID 1 query returned repeated process creation events.

The query was filtered for:

```text
powershell.exe
cmd.exe
reg.exe
rundll32.exe
wmic.exe
```

The screenshot does not contain the full process event payloads.

Therefore, the timeline establishes the existence of matching process creation telemetry but does not establish that every process event was related to the earlier registry events.

## Correlation Assessment

The available timeline contains several useful evidence points:

```text
07:40:23
LSA-related registry telemetry
        |
        v
07:43:33
Wazuh process telemetry
        |
        v
07:49:31–07:50:11
Additional registry activity
        |
        v
07:54:59–07:57:24
Repeated process creation telemetry
```

These timestamps are useful for further investigation, but they should not be treated as a confirmed attack chain without complete event-level correlation.

## Timeline Limitations

The captured evidence does not provide:

- Complete Sysmon XML for every event
- Complete process command lines
- Parent process information for every process event
- Complete user information for every event
- Exact registry value names for the LSA-related events
- A confirmed process responsible for the LSA-related registry events
- Evidence of actual LSA secret extraction

## Final Timeline Assessment

The timeline demonstrates that the endpoint generated registry and process telemetry during the investigation period and that Wazuh was receiving process telemetry.

The most relevant observation is the pair of Sysmon Event ID 13 records returned by the LSA-related registry search at approximately `07:40:23`.

Because the available event payload is incomplete, the appropriate DFIR conclusion is that **LSA-related registry telemetry was observed and requires correlation**, not that credential theft or LSA secret extraction was confirmed.
