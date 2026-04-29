# Mamba Security - Professional OSINT Library

[![Python Version](https://img.shields.io/pypi/pyversions/mamba-security)](https://pypi.org/project/mamba-security/)
[![License](https://img.shields.io/github/license/mamba-security/mamba)](https://github.com/mamba-security/mamba/blob/main/LICENSE)
[![PyPI version](https://badge.fury.io/py/mamba-security.svg)](https://badge.fury.io/py/mamba-security)

**Mamba** is a powerful, production-ready OSINT (Open Source Intelligence) library for Python. Designed for security professionals, researchers, and developers who need reliable, easy-to-use intelligence gathering tools.

## Features

- **Email Intelligence** - Breach checking, validation, and variation generation
- **Domain Reconnaissance** - WHOIS, DNS records, subdomain enumeration
- **Username Search** - Check presence across 12+ platforms
- **Phone Validation** - Format validation and carrier detection for multiple countries
- **IP Investigation** - Geolocation and reputation checking
- **Production Ready** - Rate limiting, caching, retries, and comprehensive error handling

## Installation

```bash
pip install mamba-security
```
## Basic Usage
```python
from mamba import MambaClient, EmailReputation, DomainIntel


client = MambaClient()

# Email validation
email = EmailReputation(client)
result = email.validate_format("user@example.com")
print(f"Valid: {result.success}")
print(f"MX Records: {result.data['has_mx_records']}")

# Domain WHOIS
domain = DomainIntel(client)
result = domain.whois_lookup("google.com")
print(f"Registrar: {result.data['registrar']}")

# Clean up
client.close()
```

## Advanced(API)

```python
from mamba import MambaClient, IPInvestigator

# Initialize with API keys
client = MambaClient(api_keys={
    "abuseipdb": "your-api-key",
    "virustotal": "your-vt-key"
})

# Or set them later
client.set_api_key("abuseipdb", "your-key")

# Use IP reputation checking
ip = IPInvestigator(client)
result = ip.reputation_check("8.8.8.8")
```

Mamba --> Easy but powerful
