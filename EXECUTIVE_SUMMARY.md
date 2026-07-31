# Executive Summary

## What problem does this solve that existing tools don't?

This tool solves the problem of lightweight, local, batch analysis of SSH logs without needing a commercial license or a full SIEM deployment. Existing tools like Splunk ES, IBM QRadar, or even the ELK stack require dedicated infrastructure, indexing pipelines, and significant storage before you can ask a simple question like "show me brute force attempts against SSH." This tool runs on a single server, reads logs directly from disk, and produces alerts in seconds. It does not replace a full SIEM, but it fills the gap for teams that need immediate visibility into SSH threats without procurement cycles or centralized log shipping.

## Why is this better than just using Fail2ban or grep?

Fail2ban is reactive and threshold-based: it blocks an IP after N failures in M minutes. It does not correlate failures across accounts or detect the pattern where an attacker gets a success after repeated failures. Grep can find individual lines, but it cannot correlate events across a time window or across multiple usernames.

For example, an attacker might try one password against four accounts in five minutes. Fail2ban's default threshold of five failures from one IP would never trigger because each account sees only one failure. This tool's password-spraying rule catches that pattern instantly. Similarly, if an attacker tries three passwords for `analyst` and then succeeds, grep would show four lines but would not flag the correlation. This tool's success-after-failure rule detects it and marks it as critical.

## What would it take to deploy this in a Fortune 500 company tomorrow?

Several real blockers prevent overnight deployment at that scale:

- **Scaling to 10,000 servers**: The current batch model reads one file at a time. A Fortune 500 environment would need centralized log aggregation (e.g., Fluentd, Vector, or syslog-ng) and a message queue to feed a distributed version of this engine.
- **Centralized log aggregation**: Logs must be normalized, deduplicated, and time-aligned across data centers and cloud regions before correlation is meaningful.
- **Multi-tenancy**: The tool would need RBAC, tenant isolation, and per-tenant rule tuning so that one team's alerts do not leak into another's.
- **Timezone normalization**: Servers across the globe report in local time. Without a canonical timestamp and timezone mapping, correlation windows break.
- **Event deduplication**: Virtualization and load balancers can duplicate log lines. The engine would need a deduplication stage to avoid inflated event counts and false alerts.
- **Staffing to tune rules**: Every environment is different. A team of detection engineers would be needed to baseline normal behavior, adjust thresholds, suppress false positives, and maintain Sigma rule mappings.

In short, the core logic is sound, but production deployment requires the same operational scaffolding that any enterprise SIEM demands.
