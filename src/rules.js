export const detectionRules = [
  {
    id: "rule-brute-force",
    name: "Repeated authentication failures",
    description: "Detects five failed authentications from the same source and identity within five minutes.",
    type: "correlation",
    severity: "high",
    enabled: true,
    threshold: 5,
    windowMinutes: 5,
    techniqueId: "T1110",
    techniqueName: "Brute Force",
    tactic: "Credential Access"
  },
  {
    id: "rule-success-after-failures",
    name: "Successful login after repeated failures",
    description: "Detects a successful authentication preceded by at least three failures from the same source.",
    type: "correlation",
    severity: "critical",
    enabled: true,
    threshold: 3,
    windowMinutes: 10,
    techniqueId: "T1078",
    techniqueName: "Valid Accounts",
    tactic: "Defense Evasion / Persistence"
  },
  {
    id: "rule-encoded-powershell",
    name: "Encoded PowerShell execution",
    description: "Detects PowerShell command lines using encoded or hidden execution patterns.",
    type: "match",
    severity: "high",
    enabled: true,
    techniqueId: "T1059.001",
    techniqueName: "PowerShell",
    tactic: "Execution"
  },
  {
    id: "rule-web-exploit",
    name: "Web exploitation pattern",
    description: "Detects common traversal, injection and command execution strings in HTTP requests.",
    type: "match",
    severity: "high",
    enabled: true,
    techniqueId: "T1190",
    techniqueName: "Exploit Public-Facing Application",
    tactic: "Initial Access"
  },
  {
    id: "rule-scheduled-task",
    name: "Scheduled task creation",
    description: "Detects task creation through endpoint telemetry or schtasks command lines.",
    type: "match",
    severity: "medium",
    enabled: true,
    techniqueId: "T1053.005",
    techniqueName: "Scheduled Task/Job: Scheduled Task",
    tactic: "Execution / Persistence"
  },
  {
    id: "rule-network-scan",
    name: "Network service discovery",
    description: "Detects one source contacting eight or more distinct destination ports in two minutes.",
    type: "correlation",
    severity: "medium",
    enabled: true,
    threshold: 8,
    windowMinutes: 2,
    techniqueId: "T1046",
    techniqueName: "Network Service Discovery",
    tactic: "Discovery"
  }
];
