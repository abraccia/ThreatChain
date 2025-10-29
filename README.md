# ThreatChain 🔗

**ThreatChain** is a collection of curated **Kusto Query Language (KQL)** threat hunting queries  
mapped to the **MITRE ATT&CK Framework** and enriched with real-world **CVE detections**.  
It’s designed to help defenders detect and investigate malicious behavior across different stages of the attack chain.

---

## 🎯 Goals

- Provide modular, high-quality KQL queries mapped to **MITRE ATT&CK Tactics & Techniques**.
- Include **CVE-specific detections** for recent or high-impact vulnerabilities.
- Encourage collaboration and standardization of detection logic.
- Serve as a reference for **detection engineering** and **threat hunting**.

---

## 🧱 Structure

Each folder represents an ATT&CK **Tactic** (e.g., Discovery, Execution, Persistence).  
Inside are `.kql` files for individual **Techniques** or **CVEs**, with each query including:

- **MITRE Technique ID** (e.g., `T1087.001`)
- **CVE Reference** (if applicable, e.g., `CVE-2024-37085`)
- **Description & Detection Logic**
- **References / External Analysis Links**
- **Test Data or Simulation Notes** (optional)

---

## 🧩 Example Query

```kql
// MITRE ATT&CK: T1087.001 - Account Discovery: Local Accounts
// CVE: N/A (Generic Technique)
SecurityEvent
| where EventID == 4798
| extend AccountQueried = TargetUserName
| summarize Count = count() by AccountQueried, Computer, bin(TimeGenerated, 1h)
| where Count > 5
```
