/** A subset of MITRE ATT&CK Enterprise: the techniques most often seen in detection rules. Names and tactics follow the public matrix; extend as needed. */

export const TACTICS = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"] as const;
export type Tactic = (typeof TACTICS)[number];

const E = "execution", P = "persistence", PE = "privilege-escalation", DE = "defense-evasion", CA = "credential-access", D = "discovery", LM = "lateral-movement", C = "collection", C2 = "command-and-control", EX = "exfiltration", I = "impact", IA = "initial-access";

export const TECHNIQUES: Record<string, { name: string; tactics: Tactic[] }> = {
  T1003: { name: "OS Credential Dumping", tactics: [CA] }, "T1003.001": { name: "LSASS Memory", tactics: [CA] }, "T1003.002": { name: "Security Account Manager", tactics: [CA] }, "T1003.003": { name: "NTDS", tactics: [CA] },
  T1005: { name: "Data from Local System", tactics: [C] }, T1016: { name: "System Network Configuration Discovery", tactics: [D] }, T1018: { name: "Remote System Discovery", tactics: [D] },
  T1021: { name: "Remote Services", tactics: [LM] }, "T1021.001": { name: "Remote Desktop Protocol", tactics: [LM] }, "T1021.002": { name: "SMB/Windows Admin Shares", tactics: [LM] }, "T1021.004": { name: "SSH", tactics: [LM] },
  T1027: { name: "Obfuscated Files or Information", tactics: [DE] }, T1033: { name: "System Owner/User Discovery", tactics: [D] }, T1036: { name: "Masquerading", tactics: [DE] },
  T1041: { name: "Exfiltration Over C2 Channel", tactics: [EX] }, T1046: { name: "Network Service Discovery", tactics: [D] }, T1047: { name: "Windows Management Instrumentation", tactics: [E] },
  T1048: { name: "Exfiltration Over Alternative Protocol", tactics: [EX] }, T1049: { name: "System Network Connections Discovery", tactics: [D] },
  T1053: { name: "Scheduled Task/Job", tactics: [E, P, PE] }, "T1053.005": { name: "Scheduled Task", tactics: [E, P, PE] },
  T1055: { name: "Process Injection", tactics: [DE, PE] }, T1056: { name: "Input Capture", tactics: [C, CA] }, T1057: { name: "Process Discovery", tactics: [D] },
  T1059: { name: "Command and Scripting Interpreter", tactics: [E] }, "T1059.001": { name: "PowerShell", tactics: [E] }, "T1059.003": { name: "Windows Command Shell", tactics: [E] }, "T1059.004": { name: "Unix Shell", tactics: [E] }, "T1059.005": { name: "Visual Basic", tactics: [E] }, "T1059.006": { name: "Python", tactics: [E] }, "T1059.007": { name: "JavaScript", tactics: [E] },
  T1068: { name: "Exploitation for Privilege Escalation", tactics: [PE] }, T1070: { name: "Indicator Removal", tactics: [DE] }, "T1070.001": { name: "Clear Windows Event Logs", tactics: [DE] }, "T1070.004": { name: "File Deletion", tactics: [DE] },
  T1071: { name: "Application Layer Protocol", tactics: [C2] }, "T1071.001": { name: "Web Protocols", tactics: [C2] }, T1078: { name: "Valid Accounts", tactics: [IA, P, PE, DE] },
  T1082: { name: "System Information Discovery", tactics: [D] }, T1083: { name: "File and Directory Discovery", tactics: [D] }, T1087: { name: "Account Discovery", tactics: [D] }, T1098: { name: "Account Manipulation", tactics: [P] },
  T1105: { name: "Ingress Tool Transfer", tactics: [C2] }, T1110: { name: "Brute Force", tactics: [CA] }, "T1110.003": { name: "Password Spraying", tactics: [CA] }, T1112: { name: "Modify Registry", tactics: [DE] },
  T1114: { name: "Email Collection", tactics: [C] }, T1133: { name: "External Remote Services", tactics: [IA, P] }, T1135: { name: "Network Share Discovery", tactics: [D] }, T1136: { name: "Create Account", tactics: [P] }, "T1136.001": { name: "Local Account", tactics: [P] },
  T1140: { name: "Deobfuscate/Decode Files or Information", tactics: [DE] }, T1190: { name: "Exploit Public-Facing Application", tactics: [IA] }, T1197: { name: "BITS Jobs", tactics: [DE, P] },
  T1202: { name: "Indirect Command Execution", tactics: [DE] }, T1204: { name: "User Execution", tactics: [E] }, "T1204.002": { name: "Malicious File", tactics: [E] },
  T1218: { name: "System Binary Proxy Execution", tactics: [DE] }, "T1218.005": { name: "Mshta", tactics: [DE] }, "T1218.011": { name: "Rundll32", tactics: [DE] }, T1219: { name: "Remote Access Software", tactics: [C2] }, T1222: { name: "File and Directory Permissions Modification", tactics: [DE] },
  T1482: { name: "Domain Trust Discovery", tactics: [D] }, T1485: { name: "Data Destruction", tactics: [I] }, T1486: { name: "Data Encrypted for Impact", tactics: [I] }, T1489: { name: "Service Stop", tactics: [I] }, T1490: { name: "Inhibit System Recovery", tactics: [I] },
  T1491: { name: "Defacement", tactics: [I] }, T1496: { name: "Resource Hijacking", tactics: [I] }, T1505: { name: "Server Software Component", tactics: [P] }, "T1505.003": { name: "Web Shell", tactics: [P] },
  T1529: { name: "System Shutdown/Reboot", tactics: [I] }, T1531: { name: "Account Access Removal", tactics: [I] }, T1543: { name: "Create or Modify System Process", tactics: [P, PE] }, "T1543.003": { name: "Windows Service", tactics: [P, PE] },
  T1547: { name: "Boot or Logon Autostart Execution", tactics: [P, PE] }, "T1547.001": { name: "Registry Run Keys / Startup Folder", tactics: [P, PE] }, T1548: { name: "Abuse Elevation Control Mechanism", tactics: [PE, DE] }, "T1548.002": { name: "Bypass User Account Control", tactics: [PE, DE] },
  T1550: { name: "Use Alternate Authentication Material", tactics: [DE, LM] }, "T1550.002": { name: "Pass the Hash", tactics: [DE, LM] }, T1552: { name: "Unsecured Credentials", tactics: [CA] }, T1555: { name: "Credentials from Password Stores", tactics: [CA] },
  T1558: { name: "Steal or Forge Kerberos Tickets", tactics: [CA] }, "T1558.003": { name: "Kerberoasting", tactics: [CA] }, T1560: { name: "Archive Collected Data", tactics: [C] }, T1562: { name: "Impair Defenses", tactics: [DE] }, "T1562.001": { name: "Disable or Modify Tools", tactics: [DE] },
  T1566: { name: "Phishing", tactics: [IA] }, "T1566.001": { name: "Spearphishing Attachment", tactics: [IA] }, T1567: { name: "Exfiltration Over Web Service", tactics: [EX] }, T1569: { name: "System Services", tactics: [E] }, "T1569.002": { name: "Service Execution", tactics: [E] },
  T1572: { name: "Protocol Tunneling", tactics: [C2] }, T1573: { name: "Encrypted Channel", tactics: [C2] }, T1574: { name: "Hijack Execution Flow", tactics: [P, PE, DE] },
};

/** "attack.t1059.001" -> "T1059.001"; tactic tags return null. */
export function techniqueOfTag(tag: string): string | null {
  const m = /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(tag.trim());
  return m ? m[1]!.toUpperCase() : null;
}

export function tacticOfTag(tag: string): Tactic | null {
  const m = /^attack\.([a-z-]+)$/i.exec(tag.trim());
  const t = m?.[1]?.toLowerCase() as Tactic | undefined;
  return t && (TACTICS as readonly string[]).includes(t) ? t : null;
}

export const parentOf = (id: string): string => id.split(".")[0]!;
