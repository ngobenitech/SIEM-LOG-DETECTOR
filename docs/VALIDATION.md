# Validation Record

## Reproducible commands

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

Run static lint checks:

```bash
python -m ruff check src tests
```

Run the sample scenario:

```bash
python -m siem_log_detector sample_logs/auth.log
```

Generate machine-readable evidence:

```bash
python -m siem_log_detector sample_logs/auth.log \
  --format json \
  --output reports/sample-alerts.json

python -m siem_log_detector sample_logs/auth.log \
  --format csv \
  --output reports/sample-alerts.csv
```

## Automated test matrix

| Area | Scenario | Expected result |
|---|---|---|
| Parser | ISO 8601 failure | Normalized failure event |
| Parser | ISO 8601 accepted public key | Normalized success event |
| Parser | Traditional syslog timestamp | Timestamp assigned requested year |
| Parser | IPv6 address | Canonical IPv6 value |
| Parser | Invalid address | Record skipped |
| Parser | Unrelated authentication record | Record skipped |
| Brute force | Five failures inside five minutes | `SSH-BF-001` |
| Brute force | Five failures outside the window | No alert |
| Password spray | Four accounts from one source | `SSH-PS-002` |
| Success correlation | Three failures then success | `SSH-SAF-003` |
| Success correlation | Success from a different source | No alert |
| Configuration | Custom threshold | New threshold enforced |
| Configuration | Zero or negative threshold | Configuration rejected |
| Report | JSON schema and summary | Valid report with correct counts |
| Report | CSV output | Header plus one row per alert |
| CLI | `--fail-on-alert` | Exit code `1` when alerts exist |
| Fixture | Benign sample | No alerts |

## Sample dataset

`sample_logs/auth.log` is synthetic and uses address ranges reserved for
documentation. It contains:

- a normal public-key login;
- an isolated failed login;
- five rapid failures against `root`;
- four distinct accounts targeted by one source;
- three failures followed by a successful login;
- unsupported records to verify skip accounting.

Expected result:

- 17 input lines;
- 15 parsed SSH authentication events;
- 2 skipped records;
- 3 alerts, one for each rule.

## Evidence integrity

The files under `reports/` are generated directly by the committed program using
the committed sample data. `evidence/sample-run.txt` records the corresponding
console invocation. The records are labelled synthetic; they are not represented
as production incidents.
