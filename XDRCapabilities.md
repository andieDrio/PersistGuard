# Advanced Extended Detection and Response (XDR)

MITRE ATT&CK-aligned capabilities and detection requirements

This is the PersistGuard capability baseline and evaluation catalog. Use telemetry and test evidence to record the implementation status of each capability.

## Loop Instruction for Project Updates

The project architecture governs implementation and defines the update loop.
[PROJECT_ARCHITECTURE.md](PROJECT_ARCHITECTURE.md#loop-instruction-for-project-updates)

Consult this baseline for
capability requirements, telemetry needs, and validation criteria. After testing,
record the evidence in the coverage matrix and return to the architecture for the
next update. Revise this catalog when the capability requirements change.

GUI presentation of coverage, evidence, and validation results follows the GUI
baseline. [Standard_UIUX.md](Standard_UIUX.md)

## PURPOSE

Technical requirements baseline for XDR evaluation, SOC detection engineering,
procurement/RFP, threat hunting, incident investigation and response.
This is a recommended detection catalog. Validate each detection with real telemetry and testing.
Technique IDs refer to MITRE ATT&CK Enterprise. Verify current tactics and
technique definitions in the [MITRE Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/).

## 1. CORE XDR CAPABILITIES

- Endpoint Detection and Response (EDR): process trees, memory behavior,
  persistence, ransomware, forensic collection and endpoint isolation.
- Network Detection and Response (NDR): traffic analytics, DNS, C2,
  scanning, lateral movement and suspicious egress.
- Identity Threat Detection and Response (ITDR): Active Directory,
  authentication, privileged accounts, token abuse and cloud identities.
- Email threat detection: phishing, malicious attachments and links,
  business email compromise and mailbox abuse.
- Cloud detection and response: AWS, Azure, GCP audit events,
  workload compromise and IAM abuse.
- SaaS detection: OAuth grants, account takeover, file sharing and downloads.
- Application and API detection: exploit activity, web shells, API misuse.
- Container/Kubernetes security: runtime events, privileged containers,
  Kubernetes RBAC and secrets access.
- Data security: mass access, collection, staging and exfiltration.
- Threat intelligence: IOC enrichment, actor/TTP correlation, STIX/TAXII.
- Analytics: cross-domain correlation, behavioral analysis, UEBA, risk scoring.
- Investigation: unified incidents, entity graph, timelines, historical search.
- Threat hunting: advanced queries and ATT&CK-based hypotheses.
- Response/SOAR: isolate host, terminate process, quarantine file,
  revoke tokens, disable accounts, block indicators, automate workflows.
- Engineering/governance: detection-as-code, rule tuning, RBAC, audit trail,
  telemetry health, coverage reporting and attack simulation.

## 2. MITRE ATT&CK DETECTION CATALOG

- **P1** critical
- **P2** high
- **P3** enhanced

### A. RECONNAISSANCE / RESOURCE DEVELOPMENT

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| External vulnerability scanning | T1595.002 | P2 |
| IP range scanning | T1595.001 | P2 |
| Wordlist scanning | T1595.003 | P2 |
| DNS reconnaissance | T1590.002 | P3 |
| Phishing for information | T1598 | P2 |
| Acquire infrastructure | T1583 | P3 |
| Compromise accounts | T1586 | P2 |
| Stage capabilities | T1608 | P3 |

Telemetry: WAF, firewall, DNS, proxy, email, external threat intelligence.
Note: Off-network activity may not be directly observable by internal XDR.

### B. INITIAL ACCESS

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| Spearphishing attachment | T1566.001 | P1 |
| Spearphishing link | T1566.002 | P1 |
| Spearphishing via service | T1566.003 | P2 |
| Exploit public-facing application | T1190 | P1 |
| External remote services | T1133 | P1 |
| Valid account abuse | T1078 | P1 |
| Drive-by compromise | T1189 | P1 |
| Supply chain compromise | T1195 | P1 |
| Trusted relationship abuse | T1199 | P2 |
| Replication through removable media | T1091 | P2 |

Telemetry: email, EDR, IdP, VPN, WAF, proxy and DNS.

### C. EXECUTION

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| PowerShell abuse | T1059.001 | P1 |
| Windows command shell abuse | T1059.003 | P1 |
| Unix shell abuse | T1059.004 | P1 |
| Python execution abuse | T1059.006 | P2 |
| JavaScript execution abuse | T1059.007 | P2 |
| Windows Management Instrumentation | T1047 | P1 |
| Scheduled task execution | T1053.005 | P1 |
| Service execution | T1569.002 | P1 |
| User execution: malicious file | T1204.002 | P1 |
| Exploitation for client execution | T1203 | P1 |
| Shared modules | T1129 | P2 |
| Native API | T1106 | P2 |
| Cloud API execution | T1059.009 | P2 |
| Container CLI/API execution | T1059.013 | P2 |

Telemetry: process/command-line, PowerShell, WMI, OS audit, cloud API,
container runtime.

### D. PERSISTENCE

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| Registry Run Keys/Startup Folder | T1547.001 | P1 |
| Scheduled task persistence | T1053.005 | P1 |
| Windows service persistence | T1543.003 | P1 |
| Create account | T1136 | P1 |
| Web shell | T1505.003 | P1 |
| Browser extensions | T1176 | P2 |
| Office application startup | T1137 | P2 |
| WMI event subscription | T1546.003 | P1 |
| SSH authorized keys | T1098.004 | P1 |
| Account manipulation | T1098 | P1 |
| Boot/logon initialization scripts | T1037 | P2 |
| Additional cloud credentials | T1098.001 | P1 |

Telemetry: registry, services, tasks, file integrity, AD, IdP, cloud IAM.

### E. PRIVILEGE ESCALATION

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| Exploitation for privilege escalation | T1068 | P1 |
| UAC bypass | T1548.002 | P1 |
| Sudo abuse | T1548.003 | P1 |
| Token impersonation/theft | T1134.001 | P1 |
| Process injection | T1055 | P1 |
| Additional local/domain group privileges | T1098.007 | P1 |
| Windows service manipulation | T1543.003 | P2 |
| Setuid/setgid abuse | T1548.001 | P2 |
| Group Policy modification | T1484.001 | P1 |
| Escape to host | T1611 | P1 |

Telemetry: EDR, privileged process and OS events, AD and container runtime.

### F. STEALTH / DEFENSE IMPAIRMENT

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| Process injection | T1055 | P1 |
| Process hollowing | T1055.012 | P1 |
| Reflective code loading | T1620 | P1 |
| Masquerading | T1036 | P1 |
| Obfuscated files or information | T1027 | P1 |
| Rootkit | T1014 | P1 |
| Disable or modify security tools | T1562.001 | P1 |
| Clear Windows event logs | T1070.001 | P1 |
| Clear Linux/macOS system logs | T1070.002 | P1 |
| File deletion | T1070.004 | P2 |
| Timestomping | T1070.006 | P2 |
| Disable/modify firewall | T1562.004 | P1 |
| Disable/modify cloud logs | T1562.008 | P1 |
| Indicator removal | T1070 | P2 |

Telemetry: endpoint tamper alerts, EDR, audit logs, firewall, cloud control plane.
Note: Confirm current tactic associations in the live MITRE matrix.

### G. CREDENTIAL ACCESS

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| LSASS memory | T1003.001 | P1 |
| SAM database | T1003.002 | P1 |
| NTDS database | T1003.003 | P1 |
| DCSync | T1003.006 | P1 |
| Kerberoasting | T1558.003 | P1 |
| AS-REP roasting | T1558.004 | P1 |
| Password spraying | T1110.003 | P1 |
| Password guessing | T1110.001 | P1 |
| Credential stuffing | T1110.004 | P1 |
| Browser credential stores | T1555.003 | P1 |
| Keylogging | T1056.001 | P1 |
| Adversary-in-the-middle | T1557 | P1 |
| Steal application access token | T1528 | P1 |
| Unsecured credentials | T1552 | P1 |
| Cloud instance metadata API | T1552.005 | P1 |

Telemetry: EDR, Kerberos, domain controller, IdP, cloud IAM, memory access.

### H. DISCOVERY

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| Account discovery | T1087 | P2 |
| Domain account discovery | T1087.002 | P1 |
| Network service discovery | T1046 | P1 |
| Network share discovery | T1135 | P2 |
| Remote system discovery | T1018 | P1 |
| System information discovery | T1082 | P2 |
| Security software discovery | T1518.001 | P1 |
| Domain trust discovery | T1482 | P1 |
| Permission group discovery | T1069 | P2 |
| Process discovery | T1057 | P2 |
| Cloud infrastructure discovery | T1580 | P2 |
| Cloud service discovery | T1526 | P2 |

Telemetry: EDR command lines, directory queries, NDR, cloud API.

### I. LATERAL MOVEMENT

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| RDP | T1021.001 | P1 |
| SMB/Windows Admin Shares | T1021.002 | P1 |
| SSH | T1021.004 | P1 |
| WinRM | T1021.006 | P1 |
| Pass-the-Hash | T1550.002 | P1 |
| Pass-the-Ticket | T1550.003 | P1 |
| Internal spearphishing | T1534 | P2 |
| Lateral tool transfer | T1570 | P1 |
| Exploit remote services | T1210 | P1 |
| Remote session hijacking | T1563 | P1 |
| Alternate authentication material | T1550 | P1 |

Telemetry: EDR, Windows auth, Kerberos, network flows, SSH, VPN.

### J. COLLECTION

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| Data from local system | T1005 | P1 |
| Data from network shared drive | T1039 | P1 |
| Email collection | T1114 | P1 |
| Remote email collection | T1114.002 | P1 |
| Screen capture | T1113 | P2 |
| Clipboard data | T1115 | P2 |
| Archive collected data | T1560 | P1 |
| Automated collection | T1119 | P1 |
| Data from cloud storage | T1530 | P1 |
| Data from information repositories | T1213 | P1 |
| Data staged | T1074 | P1 |

Telemetry: file access, endpoint processes, DLP, SaaS and cloud audit.

### K. COMMAND AND CONTROL

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| DNS C2 | T1071.004 | P1 |
| Web protocols C2 | T1071.001 | P1 |
| Encrypted channel | T1573 | P1 |
| Non-standard port | T1571 | P1 |
| Fast flux DNS | T1568.001 | P2 |
| Domain generation algorithms | T1568.002 | P1 |
| Proxy | T1090 | P1 |
| Web service C2 | T1102 | P1 |
| Remote access software | T1219 | P1 |
| Ingress tool transfer | T1105 | P1 |
| Protocol tunneling | T1572 | P1 |
| Data obfuscation | T1001 | P2 |

Telemetry: NDR, DNS, proxy, TLS metadata, firewall, EDR network events.

### L. EXFILTRATION

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| Exfiltration over C2 channel | T1041 | P1 |
| Exfiltration to cloud storage | T1567.002 | P1 |
| Exfiltration over web service | T1567 | P1 |
| Exfiltration over alternative protocol | T1048 | P1 |
| Exfiltration over physical medium | T1052 | P2 |
| Automated exfiltration | T1020 | P1 |
| Data transfer size limits | T1030 | P2 |
| Scheduled transfer | T1029 | P2 |
| Unencrypted non-C2 protocol | T1048.003 | P1 |

Telemetry: egress traffic, DNS, cloud/SaaS audit, DLP, USB events.

### M. IMPACT

| Detection use case | Technique ID | Priority |
| --- | --- | --- |
| Data encrypted for impact | T1486 | P1 |
| Inhibit system recovery | T1490 | P1 |
| Data destruction | T1485 | P1 |
| Disk wipe | T1561 | P1 |
| System shutdown/reboot | T1529 | P1 |
| Service stop | T1489 | P1 |
| Network denial of service | T1498 | P1 |
| Endpoint denial of service | T1499 | P1 |
| Data manipulation | T1565 | P1 |
| Resource hijacking | T1496 | P1 |

Telemetry: EDR file behavior, backup logs, OS services, cloud billing,
network availability.

## 3. ADVANCED ANALYTICS REQUIREMENTS

- [ ] Cross-domain correlation across endpoint, network, identity, email, cloud.
- [ ] Multi-stage attack chain correlation and incident stitching.
- [ ] UEBA and baselined behavioral anomaly detection.
- [ ] Asset criticality, vulnerability and identity-aware risk scoring.
- [ ] Evidence-backed alert explanations and entity graph.
- [ ] Historical hunting and retrospective IOC matching.
- [ ] Threat intelligence enrichment and STIX/TAXII ingestion.
- [ ] Detection-as-code, version control, CI/CD, testing and tuning.
- [ ] Detection suppression, allowlists, false-positive tracking.
- [ ] Telemetry ingestion health and collection gap alerts.
- [ ] ATT&CK Navigator coverage export and evidence-based reporting.
- [ ] Attack simulation/emulation and continuous detection validation.

## 4. RESPONSE AND CONTAINMENT REQUIREMENTS

- [ ] Endpoint isolation with management access retained.
- [ ] Malicious process termination and file quarantine.
- [ ] Domain/IP/hash/URL blocking through available controls.
- [ ] Account disablement, session/token revocation and credential reset.
- [ ] Network blocking and NAC/firewall isolation integrations.
- [ ] Email quarantine/purge and mailbox remediation.
- [ ] Cloud credential revocation and workload quarantine.
- [ ] Automated SOAR playbooks and human approval gates.
- [ ] Incident case management and ticketing integrations.
- [ ] Audit trail for every response action, including failures.
- [ ] Investigation evidence preservation and recovery guidance.

## 5. DETECTION RULE STANDARD FIELDS

- Detection ID, name, ATT&CK tactic, technique or sub-technique, and description
- Data source, required telemetry, and detection logic
- Severity, confidence, correlation window, and false positives
- Recommended response and validation test
- Rule owner, status, vendor support, evidence, and last test date

## 6. EXAMPLE CORRELATED RANSOMWARE ATTACK CHAIN

T1566.001 Malicious attachment -> T1059.001 Suspicious PowerShell ->
T1003.001 LSASS dumping -> T1021.002 SMB lateral movement ->
T1562.001 Security tool tampering -> T1486 File encryption.
Expected XDR outcome: correlated incident, attack timeline, impacted assets,
confidence scoring, analyst evidence, and approved automated containment.
Individual stages can trigger detections because attack paths vary.

## 7. VENDOR ACCEPTANCE / MEASUREMENT

- Telemetry coverage: applicable techniques with adequate data sources.
- Deployed detection coverage: applicable techniques with tested rules.
- Effectiveness: representative emulation tests successfully detected.
- Response coverage: scenarios with tested containment workflows.
- Operations: MTTD, MTTR, false positives, investigation time, data health.
Classify every requirement: Native / Integrated / Custom / Partial /
Unsupported / Not Applicable. Request demonstrations and evidence.
A mapped ATT&CK ID alone does NOT prove detection effectiveness.

## OFFICIAL REFERENCES

- [MITRE Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE Techniques](https://attack.mitre.org/techniques/)
- [MITRE Detection Strategies](https://attack.mitre.org/detectionstrategies/)
- [MITRE ATT&CK Navigator](https://attack.mitre.org/resources/attack-navigator/)

