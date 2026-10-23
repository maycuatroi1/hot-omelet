---
name: pii-evidence
description: Extract PII evidence from compromised databases and export to Excel/JSON for reporting. Use when asked to "dump PII", "export evidence", "PII report", "extract customer data", "evidence to excel", or any PII extraction and evidence packaging task.
---

# PII Evidence Extraction & Packaging

Extract personally identifiable information from compromised databases and package as evidence for security assessment reports.

## Supported Sources

- **MongoDB**: Auto-detect PII fields across all collections
- **Redis**: Extract PII from queue jobs, session data, cached records
- **PostgreSQL/MySQL**: Extract from user tables, logs, configs
- **JSON/CSV files**: Parse existing data dumps

## CLI Quick Start

```bash
# MongoDB PII extraction to Excel
hot mongo pii --host TARGET --port 27017 --limit 200 --output evidence.xlsx

# With auth
hot mongo pii --host TARGET --port 27017 --username USER --password PASS --output evidence.xlsx

# Export both Excel and JSON
hot mongo pii --host TARGET --port 27017 --format all --output evidence

# Custom target name in report header
hot mongo pii --host TARGET --port 27017 --target-name "Company XYZ" --output evidence.xlsx
```

## PII Detection

Auto-detects these field categories:
- **Phone**: phone, mobile, tel, sdt, receiver_mobile, customer_mobile
- **Name**: name, full_name, ho_ten, customer_name, receiver_name
- **Email**: email, mail
- **Address**: address, dia_chi, customer_address, delivery_address
- **ID Card**: cmnd, cccd, citizen_id
- **Secrets**: password, token, api_key, jwt, credential

Also pattern-matches:
- Vietnamese phone numbers: `0[3-9]\d{8}`
- Email addresses: standard regex

## Excel Output Format

Each source collection gets its own sheet with:
- Red header row with white text
- Thin borders on all cells
- Auto-sized columns
- Impact Summary sheet with totals and metadata

## Workflow

1. **Scan**: Auto-scan all databases/collections for PII fields
2. **Extract**: Pull latest N records with PII from each source
3. **Classify**: Categorize by PII type (phone, name, email, address, secrets)
4. **Export**: Package into formatted Excel with Impact Summary sheet
5. **Report**: Include file path in assessment report

## Integration with Assessment Reports

Evidence files should be saved to:
```
reports/{target}/
├── {target}_compromised_pii.xlsx    # Excel evidence
├── {target}_compromised_pii.json    # JSON evidence
└── full_assessment_report.md        # Reference evidence files
```

## Python API

```python
from hot_omelet.mongo_explorer.pii_extractor import PIIExtractor

extractor = PIIExtractor(host="1.2.3.4", port=27017)
extractor.connect()
pii_map = extractor.scan_pii()           # Detect PII fields
records = extractor.extract_pii(limit=200)  # Extract records
extractor.export_excel(records, "evidence.xlsx", target_name="Target Co")
```
