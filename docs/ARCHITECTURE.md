# Architecture

```
spectre/
├── cli.py               # CLI, module dispatch
├── config.py            # Metadata, legal warning
├── models.py            # AttackResult, EngagementContext
├── logger.py            # Colored logging
├── output.py            # Banner, results, JSON export
├── exceptions.py        # Typed exceptions
├── modules/
│   ├── base.py          # BaseModule ABC
│   ├── subdomain.py     # Subdomain enumeration (CT, DNS brute, resolution)
│   ├── email.py         # Email harvesting
│   ├── dnsintel.py      # DNS intelligence (records, zone transfer, DNSSEC)
│   ├── cert.py          # Certificate transparency & SSL analysis
│   ├── search.py        # Infrastructure fingerprinting
│   └── social.py        # Organization footprinting
├── utils/
│   └── network.py       # HTTP, DNS, hostname resolution, delay
└── data/
    └── __init__.py      # Wordlists, signatures, patterns
```
