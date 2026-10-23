---
name: incomplete-secret-allowlist-audit
description: Audit pattern for finding credential info-disclosure bugs caused by incomplete "sensitive keys" redaction lists. Projects in the Java/JVM big-data ecosystem (Flink, Spark, Airflow, Kafka Connect, NiFi, Hadoop, Hive, Trino, Druid) commonly expose a `/config` or `/configuration` HTTP endpoint that dumps the full Configuration with some keys redacted to `******`. The redaction is typically a `contains()` allowlist of substrings like `password / secret / token / apikey`. The gap: cloud filesystem access-key identifiers (`s3.access-key`, `fs.s3a.access.key`, `fs.oss.accessKeyId`, `aws.access-key-id`, `gs.*.keyId`) often don't contain any of those substrings and leak in cleartext. Use when auditing a JVM big-data project's REST/admin surface for info-disclosure; also applicable when reviewing source of a new platform that implements its own redaction.
---

# Audit: incomplete credential redaction allowlist

## The bug class

```java
// Typical shape (Flink, Airflow plugin configs, custom platforms)
private static final String[] SENSITIVE_KEYS = {
    "password", "secret", "token", "apikey", "api-key",
    "auth-params", "service-key", "jaas.config", "http-headers"
};

public static boolean isSensitive(String key) {
    final String k = key.toLowerCase();
    for (String h : SENSITIVE_KEYS) {
        if (k.contains(h)) return true;
    }
    return false;
}
```

The `contains(substring)` check is case-insensitive and permissive, which feels safe. But it's a **denylist pretending to be an allowlist**: any key name that doesn't happen to contain one of the listed words slips through.

## Targets where this consistently fails

These keys are set by operators in real-world `flink-conf.yaml` / `spark-defaults.conf` / `core-site.xml` and are NOT caught by typical allowlists:

| Key (lowercased) | Reason not caught | Impact if leaked |
|---|---|---|
| `s3.access-key` / `s3.access.key` | no substring match | AWS account identification |
| `fs.s3a.access.key` | same | Hadoop S3A account |
| `fs.oss.accesskeyid` | `keyid` ≠ `apikey` | Alibaba OSS account |
| `aws.access-key-id` | `access-key-id` ≠ `api-key` | AWS principal |
| `gs.auth.service.account.email` | no match | GCP service-account email → IAM enum |
| `gs.auth.service.account.private.key.id` | `private.key.id` ≠ any | GCP key ID |
| `kafka.ssl.keystore.location` | path only, but reveals layout | filesystem enum |
| `client.id` (OAuth / OIDC) | no match | app identity |
| `sentry.dsn` | no match | Sentry DSN (contains project token sometimes) |

Things that ARE caught (the "why secrets are safe" illusion):
- `s3.secret-key` → contains `secret` ✓
- `fs.s3a.secret.key` → contains `secret` ✓
- `fs.oss.accessKeySecret` → contains `secret` ✓
- `password` keys → ✓
- `token` keys → ✓

## Audit procedure

### 1. Find the redaction function

```bash
grep -rn "SENSITIVE_KEYS\|sensitiveKeys\|isSensitive\|hideSensitive\|REDACTED_KEYS\|filterSensitive" \
  --include="*.java" --include="*.scala" --include="*.py" --include="*.go"
```

Read the list. Typical patterns:

- Apache-family: static `String[] SENSITIVE_KEYS` in a `GlobalConfiguration` / `Configuration` / `ConfigurationUtils` class.
- Django/Flask admin panels: `SESSION_COOKIE` / settings auto-redaction.
- Node/Express: custom middleware checking `req.body`.

### 2. Find the redaction call site (sink)

```bash
grep -rn "hideSensitive\|redact\|toDisplayMap\|filterConfig" --include="*.java" --include="*.scala"
```

Confirm it's invoked by the public endpoint (e.g. `ClusterConfigHandler`, `/admin/config`).

### 3. Enumerate cloud-filesystem + auth config keys

For each cloud filesystem module in the project:

```bash
# Flink example
grep -rn "ConfigOptions.key(" flink-filesystems --include="*.java" | grep -v test | head -30
# Spark
grep -rn "ConfigBuilder(" --include="*.scala" | head -30
```

Extract the actual config key strings. Compare against the SENSITIVE_KEYS list.

### 4. Case-insensitive cross-check

```python
SENSITIVE = ["password","secret","fs.azure.account.key","apikey","api-key",
             "auth-params","service-key","token","basic-auth","jaas.config","http-headers"]
KEYS = ["s3.access-key","s3.access.key","fs.s3a.access.key","fs.oss.accessKeyId",
        "aws.access-key-id","gs.auth.service.account.email","client.id","sentry.dsn"]
for k in KEYS:
    kl = k.lower()
    hit = [s for s in SENSITIVE if s in kl]
    print(f"{k:50s} -> {'REDACTED via '+hit[0] if hit else 'LEAKED'}")
```

### 5. Dynamic validation

```bash
# Set placeholder creds in the target project's config
echo "s3.access-key: AKIA_POC_LEAK_1234567890" >> project-conf.yaml
echo "s3.secret-key: poc_secret_SHOULD_BE_REDACTED" >> project-conf.yaml

# Start the service (use official docker image)
docker run -d -p 8081:8081 -v $PWD/project-conf.yaml:/opt/project/conf/project-conf.yaml $IMAGE

# Hit the config endpoint, diff redacted vs leaked
curl -s http://localhost:8081/<config-endpoint> | jq ...
```

## Proposed fix template

For each project, the fix is a small patch:

```java
private static final String[] SENSITIVE_KEYS = new String[] {
    "access-key", "access.key", "accesskey",   // <-- add this line
    "password", "secret", ...
};
```

Because matching is `toLowerCase() + contains()`, these three strings together cover:
- `s3.access-key`, `s3.access.key`, `fs.s3a.access.key` (via `access-key` / `access.key`)
- `fs.oss.accessKeyId` → `accesskey` in lowercase → match
- `aws.access-key-id`, `gs.*.keyId` variants → match

Plus extend the unit tests:
```java
assertThat(isSensitive("s3.access-key")).isTrue();
assertThat(isSensitive("fs.oss.accessKeyId")).isTrue();
assertThat(isSensitive("aws.access-key-id")).isTrue();
// Negative: non-credential keys stay visible
assertThat(isSensitive("rest.bind-address")).isFalse();
```

## Known instances (validated)

- **Apache Flink master (2.4-SNAPSHOT)** — confirmed 2026-04-24 via Docker 1.19.0.
  `GlobalConfiguration.SENSITIVE_KEYS` missing access-key variants.
  See `vuln-review/flink/` in this repo for the disclosure artifacts.

## Where to look next (candidate projects, not validated)

- Apache Spark: `SparkConf#toDebugString` + `SparkConf#getRedactionPattern` (regex-based, actually safer — but check if cloud keys are in the default pattern).
- Apache Airflow: `airflow.configuration.Configuration#as_dict(display_sensitive=False)` — default-blocked key list.
- Apache NiFi: `ProcessorAuditor` / REST API exposes processor configs, some properties flagged sensitive by type but cloud connector properties may not be.
- Apache Kafka Connect: `/connectors/{name}/config` endpoint; "password"-named fields are redacted but custom connectors often leak.
- Apache Druid: `/druid/coordinator/v1/config` and similar.
- Trino: `system.runtime.config_properties`.

## Severity calibration

- Access-key IDs are not secrets per se, but AWS docs treat them as "sensitive information" (rotate if exposed).
- Value: IAM principal enumeration, targeted phishing, account-ID discovery via `sts:GetAccessKeyInfo`, correlation with separate secret leaks.
- Typical CVSS: 4.3–5.3 (Low–Medium, information disclosure, unauthenticated when the endpoint is).
- Upgrade to Medium if the endpoint is authenticated (trust-boundary crossing).

## Related skills

- `asf-security-disclosure` — reporting flow for ASF projects.
- `security-evidence-integrity` — how to screenshot this finding credibly.
