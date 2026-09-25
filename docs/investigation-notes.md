# Investigation Notes

## Investigation question

A payroll email was reported to the SOC. The objective was to determine whether it was malicious, establish campaign scope, identify user interaction and credential exposure, determine whether accounts were compromised, and contain the incident.

## Evidence path

1. Compared two phishing messages with a legitimate Cloudora payroll reference.
2. Reviewed SPF, DKIM and DMARC results and sender infrastructure.
3. Used simulated VirusTotal and AbuseIPDB evidence to enrich the domain/IP findings.
4. Queried message trace to scope delivery and quarantine.
5. Queried click telemetry to identify six clickers and two credential submissions.
6. Correlated the two credential victims with successful identity sign-ins.
7. Pivoted on `198.18.7.200`, identifying the same two compromised accounts.
8. Built Ryan Boyd's account timeline to distinguish normal London/iOS activity from Amsterdam/Windows/Chrome access.
9. Applied containment, eradication and recovery actions.
10. Developed a phishing-click-to-anomalous-sign-in detection concept.

## Analyst conclusions

- Variant A was direct sender spoofing and failed SPF/DKIM/DMARC.
- Variant B authenticated successfully for the attacker's lookalike domain; authentication success did not make the message legitimate.
- Six users clicked; two submitted credentials.
- Freya Lynn and Ryan Boyd were confirmed compromised within the supplied training evidence.
- Four users clicked without credential submission and were treated as elevated risk.
- Thirty delivered recipients did not click, and four targeted recipients were fully protected by quarantine.
- The Cloudora Monthly Mailchimp newsletter was investigated and cleared as legitimate.

## Response sequence

**Detection & Analysis:** email triage, authentication analysis, campaign scoping, click analysis, credential-victim correlation and sign-in investigation.

**Containment:** revoke sessions/refresh tokens first; block malicious sender/sign-in infrastructure and lookalike domains.

**Eradication:** reset credentials, require MFA re-registration and purge phishing messages.

**Recovery:** return remediated accounts to safe use and verify post-containment authentication.

**Post-Incident:** document findings and improve behavioural detections.
