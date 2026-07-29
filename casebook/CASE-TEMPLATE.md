# CASE-XXX - <short title>

| Field | Value |
|-------|-------|
| **Case ID** | CASE-XXX |
| **Date/Time (UTC)** | <detection time> |
| **Analyst** | <name / L1> |
| **Source alert** | Wazuh rule `<id>` - "<description>" |
| **Severity** | <level> |
| **MITRE technique** | <Txxxx - name> |
| **Asset** | <hostname / agent> |
| **Status** | Open / Escalated / Closed |

## 1. Alert summary
<What fired, in one or two sentences. Include the raw log line if useful.>

<!-- EVIDENCE: attach Wazuh alert screenshot -->

## 2. Triage (the L1 questions)
- **Internal or external?** <>
- **Known asset / user?** <>
- **Expected behavior?** <>
- **Enrichment corroborates?** <>
- **Correlated?** <>
- **Severity vs impact?** <>

## 3. Enrichment
<IP reputation (VirusTotal), geolocation, RFC1918 status, asset/user context, prior history.>

<!-- EVIDENCE: attach enrichment output (VT score, n8n verdict, etc.) -->

## 4. Analysis
<The reasoning: what the evidence adds up to, and any alternative explanations considered.>

## 5. Verdict
**<True Positive / False Positive / Benign True Positive>** - <one-line justification>

## 6. Action taken
<Containment applied (automated or manual), what was done within L1 authority.>

## 7. Escalation / handoff
<If escalated: what L2 needs - the open question, scope, and what's already contained.
 If closed: closure reason and any tuning recommendation.>

## 8. IOCs
| Type | Value |
|------|-------|
| <IP / user / process / hash> | <value> |
