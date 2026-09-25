# Indicators of Compromise

> Synthetic training indicators only.

| Type | Indicator | Investigation context |
|---|---|---|
| Domain | `cloudora-hr-portal.example` | Lookalike domain used by the payroll phishing campaign |
| Subdomain | `login.cloudora-hr-portal.example` | Variant B credential-harvesting host |
| URL path | `/payroll/login` | Variant A credential-harvesting path |
| URL path | `/verify` | Variant B credential-harvesting path |
| IPv4 | `198.18.44.10` | Variant A sending / campaign infrastructure |
| IPv4 | `198.18.44.23` | Variant A sending infrastructure |
| IPv4 | `198.18.51.7` | Variant B sending infrastructure |
| IPv4 | `198.18.7.200` | Suspicious successful sign-ins to both compromised accounts |

## Defensive use

The indicators were blocked at the simulated mail gateway and web proxy during containment. They should not replace behavioural detection: attacker infrastructure changes quickly, so the stronger long-term control is correlation of phishing interaction with anomalous successful authentication.
