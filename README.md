# ThreatChain 🔗

**ThreatChain** is a collection of curated **Kusto Query Language (KQL)** threat hunting queries
mapped to the **MITRE ATT&CK Framework**.  
It’s designed to help defenders detect and investigate malicious behavior
across different stages of the attack chain.

## 🎯 Goals

- Provide modular, high-quality KQL queries mapped to ATT&CK Tactics & Techniques.
- Encourage collaboration and standardization of query development.
- Serve as a reference for detection engineering and threat hunting.

## 🧱 Structure

Each folder represents an ATT&CK **Tactic** (e.g., Discovery, Execution, Persistence).  
Inside are `.kql` files for individual **Techniques**, with each query including:

- MITRE ID (e.g., `T1087.001`)
- Description & detection logic
- References
- Test data or simulation notes (optional)

## 🧩 Example Query

```kql
// MITRE ATT&CK: T1087.001 - Account Discovery: Local Accounts
SecurityEvent
| where EventID == 4798
| extend AccountQueried = TargetUserName
| summarize Count = count() by AccountQueried, Computer, bin(TimeGenerated, 1h)
| where Count > 5
```
