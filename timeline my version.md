# Investigation Timeline 

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

