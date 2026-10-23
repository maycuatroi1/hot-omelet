---
name: shodan-osint
description: Shodan-based OSINT for discovering exposed services and infrastructure by country, organization, or technology. Use when asked to "find exposed devices", "shodan search", "discover IoT devices", "find exposed services by country", "OSINT reconnaissance", or any Shodan/Censys-based discovery task.
---

# Shodan OSINT Discovery

Service discovery and analysis using Shodan API for authorized research.

## Prerequisites

Shodan API key stored in `.env` as `SHODAN_API_KEY`. Initialize:
```bash
shodan init $(grep SHODAN_API_KEY .env | cut -d= -f2)
```

## Core Commands

### Count targets
```bash
shodan count 'country:KH "hikvision"'
shodan count 'country:VN port:6379'
```

### Search and extract
```bash
shodan search --limit 100 --fields ip_str,port,hostnames,product,org,data 'QUERY'
```

### Download for large datasets
```bash
shodan download results 'QUERY'
shodan parse --fields ip_str,port,product results.json.gz
```

## Search Query Patterns

### By Country + Device Type
| Target | Query |
|--------|-------|
| Hikvision | `country:XX "hikvision"` |
| Dahua | `country:XX "dahua"` |
| DVR | `country:XX "DVR" port:80` |
| RTSP streams | `country:XX port:554` |

### By Service Type
| Target | Query |
|--------|-------|
| Redis | `country:XX port:6379` |
| MongoDB | `country:XX port:27017 "MongoDB"` |
| Elasticsearch | `country:XX port:9200 "elasticsearch"` |
| Apache Airflow | `country:XX "Apache Airflow"` |
| MinIO | `country:XX "MinIO"` |
| PostgreSQL | `country:XX port:5432 "PostgreSQL"` |

## Methodology

### Phase 1: Enumerate Scale
Run `shodan count` for each service type.

### Phase 2: Download Targets
Use `shodan search --limit 100` per query.

### Phase 3: Parse and Classify
Python script to deduplicate and classify results.

### Phase 4: Live Probe with httpx
```bash
cat target_ips.txt | ~/go/bin/httpx -ports 80,443,8080 -timeout 8 -threads 100 -title -server -status-code -tech-detect -json -o live_probe.json
```

### Phase 5: Version Identification
Extract version info from Shodan data for CVE mapping.

### Phase 6: Report
Output structured report with device counts, version distribution, and recommended next steps.

## Integration with hot-omelet

After discovery, chain into validation:
```bash
hot scan <IP>
/validate <service> <IP>
/cve <CVE-ID> <IP>
/cred-scan <IP>
```
