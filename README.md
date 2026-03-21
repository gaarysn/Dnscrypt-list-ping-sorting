# DNSCrypt-Sorter

Measure and rank DNS resolvers from the official DNSCrypt catalogs by latency.

The tool loads resolver lists from `dnscrypt.info`, filters them by protocol and flags, probes each endpoint, and sorts the results by response time. It supports both an interactive terminal wizard and a command-line mode.

## Features

- Official catalogs: `public-resolvers`, `relays`, `parental-control`, `opennic`, `onion-services`, `odoh-servers`, `odoh-relays`
- Protocol filters: `DNSCrypt`, `DoH`, `ODoH`, `DNSCrypt relay`, `ODoH relay`
- Resolver filters: `nofilter`, `nolog`, `dnssec`, IP version, country
- Probe profiles: `fast`, `balanced`, `deep`
- Interactive terminal UI with progress indicators
- JSON output for automation
- Cache support for resolver catalogs

## Requirements

- Python 3.10+
- Internet access for downloading catalogs and probing resolvers
- `rich` for the enhanced terminal UI

## Installation

```bash
git clone https://github.com/gaarysn/DNSCrypt-Sorter.git
cd DNSCrypt-Sorter
python3 -m pip install -e .
```

## Run

Interactive mode:

```bash
dnscrypt-sorter
```

Direct script run:

```bash
python3 ping_dnscrypt.py
```

Help for command-line options:

```bash
python3 ping_dnscrypt.py --help
```

## Examples

Check the default catalog with the balanced probe profile:

```bash
python3 ping_dnscrypt.py
```

Top 10 DNSCrypt resolvers with no filtering and no logging, IPv4 only:

```bash
python3 ping_dnscrypt.py \
  --catalog public-resolvers \
  --proto DNSCrypt \
  --require-nofilter \
  --require-nolog \
  --ip-version ipv4 \
  --profile balanced \
  --top 10
```

All DoH endpoints in Germany:

```bash
python3 ping_dnscrypt.py \
  --catalog all \
  --proto DoH \
  --country Germany \
  --profile deep \
  --all
```

JSON output:

```bash
python3 ping_dnscrypt.py \
  --catalog public-resolvers \
  --proto all \
  --top 25 \
  --json
```

## Common Flags

### Catalogs and protocols

- `--catalog NAME` select a catalog, repeatable
- `--catalog all` load every official catalog
- `--list-catalogs` print supported catalogs and exit
- `--proto NAME` select a protocol, repeatable
- `--list-protos` print supported protocols and exit

### Filters

- `--require-nofilter` keep only resolvers advertising no filtering
- `--require-nolog` keep only resolvers advertising no logging
- `--dnssec-only` keep only DNSSEC-validating resolvers
- `--ip-version any|ipv4|ipv6` filter by address family
- `--country NAME` filter by country, repeatable

### Probing

- `--profile fast|balanced|deep` choose a probe preset
- `-n, --number-ping` set the number of attempts
- `-p, --ping-delay` delay between attempts
- `-s, --server-delay` delay before each server
- `-m, --time-out` per-attempt timeout
- `-t, --threading` enable concurrent probes
- `--workers` set the worker count
- `--tcp-only` disable ICMP fallback

### Output

- `--top N` show the fastest `N` results
- `--all` show all successful results
- `--stamp-mode compact|full|hidden` control SDNS stamp display
- `--json` print machine-readable JSON
- `--cache-dir PATH` set the catalog cache directory

## Project Layout

- `dnscrypt_sorter/cli.py` main application logic and CLI
- `dnscrypt_sorter/source.py` catalog loading and parsing
- `dnscrypt_sorter/filters.py` resolver filters
- `dnscrypt_sorter/latency.py` latency measurement
- `dnscrypt_sorter/ui.py` terminal UI
- `ping_dnscrypt.py` direct script entry point

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python3 -m pytest tests/ -v
```

## License

MIT
