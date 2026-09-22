# PAN-OS Automation Suite (`panos_suite`)

An enterprise Python automation toolkit for auditing, sanitizing, and deploying security policy configurations on Palo Alto Networks (PAN-OS) firewalls.

## Features
- **Policy Auditor**: Identifies unused address objects, unlogged security rules, and shadowed policy signatures.
- **Data Sanitizer**: Mask IP addresses and sensitive identifiers before exporting logs or pipeline results.
- **Offline Mock Engine**: Dry-run audits and deployment workflows without requiring physical hardware or virtual firewall instances.

## Usage
```bash
# Run policy audit in offline mock mode
python -m panos_suite.cli audit --mock

# Run policy audit with automated IP and entity redaction
python -m panos_suite.cli audit --mock --sanitize
