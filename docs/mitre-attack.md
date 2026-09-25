# MITRE ATT&CK Mapping

| Tactic | ID | Technique | Evidence |
|---|---|---|---|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Payroll-themed messages directed users to credential-harvesting links |
| Credential Access | T1598.003 | Phishing for Information: Spearphishing Link | Users were asked to submit login/payroll information through the phishing site |
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | Harvested credentials were subsequently used for successful cloud sign-ins |

## Contextual infrastructure mapping

The campaign used a lookalike domain. `T1583.001 - Acquire Infrastructure: Domains` is useful context, but domain-registration activity itself was not directly observed in the supplied telemetry, so it should not be presented as a confirmed attacker action.
