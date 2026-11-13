# Sigma lab report

12 rules against 29 events (29 labelled).

## Rules

| Rule | Level | Techniques | Hits | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|---|---|---|
| Encoded PowerShell command line | high | T1059.001 | 2 | 2 | 0 | 1 | 100% | 67% |
| LSASS memory dump via procdump or comsvcs | critical | T1003.001 | 2 | 2 | 0 | 0 | 100% | 100% |
| Shadow copies deleted or recovery disabled | critical | T1490 | 2 | 2 | 0 | 0 | 100% | 100% |
| Windows event log cleared | high | T1070.001 | 2 | 2 | 0 | 0 | 100% | 100% |
| Scheduled task created from the command line | medium | T1053.005 | 2 | 1 | 1 | 0 | 50% | 100% |
| RDP logon from an external address | high | T1021.001 | 1 | 1 | 0 | 0 | 100% | 100% |
| Local user account created | medium | T1136.001 | 2 | 1 | 1 | 0 | 50% | 100% |
| Rundll32 running a script or a remote resource | high | T1218.011 | 1 | 1 | 0 | 0 | 100% | 100% |
| Defender real-time protection disabled | high | T1562.001 | 1 | 1 | 0 | 0 | 100% | 100% |
| Certutil used to download a file | high | T1105 | 1 | 1 | 0 | 0 | 100% | 100% |
| Kerberos service ticket requested with RC4 | high | T1558.003 | 1 | 1 | 0 | 0 | 100% | 100% |
| Suspicious cmd | low | - | 2 | 1 | 1 | 0 | 50% | 100% |

## Lint

- **Shadow copies deleted or recovery disabled**: bcd: "CommandLine|contains" with a very short value will be noisy
- **Suspicious cmd**: no ATT&CK technique tag; missing or very short description; no falsepositives documented; no logsource; selection: "CommandLine|contains" with a very short value will be noisy

## False positives to tune

- Scheduled task created from the command line: unexpected hit on event 19
- Local user account created: unexpected hit on event 26
- Suspicious cmd: unexpected hit on event 18

## Missed detections

- Encoded PowerShell command line: expected but not matched on event 3

## ATT&CK coverage by tactic

- **execution**: T1053.005 Scheduled Task, T1059.001 PowerShell
- **persistence**: T1053.005 Scheduled Task, T1136.001 Local Account
- **privilege-escalation**: T1053.005 Scheduled Task
- **defense-evasion**: T1070.001 Clear Windows Event Logs, T1218.011 Rundll32, T1562.001 Disable or Modify Tools
- **credential-access**: T1003.001 LSASS Memory, T1558.003 Kerberoasting
- **lateral-movement**: T1021.001 Remote Desktop Protocol
- **command-and-control**: T1105 Ingress Tool Transfer
- **impact**: T1490 Inhibit System Recovery

## Threat profile

9 of 14 target techniques covered, 1 partially.

| Technique | Name | State | Rules |
|---|---|---|---|
| T1566.001 | Spearphishing Attachment | gap | - |
| T1059.001 | PowerShell | covered | ps-encoded |
| T1003.001 | LSASS Memory | covered | lsass-dump |
| T1021.001 | Remote Desktop Protocol | covered | rdp-external |
| T1021.002 | SMB/Windows Admin Shares | gap | - |
| T1053.005 | Scheduled Task | covered | schtask-create |
| T1490 | Inhibit System Recovery | covered | inhibit-recovery |
| T1486 | Data Encrypted for Impact | gap | - |
| T1562.001 | Disable or Modify Tools | covered | defender-off |
| T1070.001 | Clear Windows Event Logs | covered | log-cleared |
| T1105 | Ingress Tool Transfer | covered | certutil-download |
| T1558.003 | Kerberoasting | covered | kerberoast |
| T1047 | Windows Management Instrumentation | gap | - |
| T1218 | System Binary Proxy Execution | partial | rundll32-script |

_Coverage means a rule is tagged for the technique, not that it detects every variant. Precision and recall use only the events that carry an `_expect` label._
