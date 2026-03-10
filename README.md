# Dnscrypt-list-ping-sorting

A program to ping and sort the DNS servers proposed by DNSCrypt ([dnscrypt.info](https://dnscrypt.info/)).

This project is an evolved version of the original [Magalame/Dnscrypt-list-ping-sorting](https://github.com/Magalame/Dnscrypt-list-ping-sorting), which pings resolvers and displays them sorted by latency. Many thanks to the original author for the idea and the initial implementation.

The script now loads official DNSCrypt catalogs, checks latency with visible probe progress, and shows results in a modern terminal UI with compact `sdns://...` stamps. The core idea—ping each server, show average and reliability, list responders sorted by ping time—remains the same; the data source, filters, and interface have been updated.

## Supported catalogs

The tool can now load the official DNSCrypt catalogs directly:

- `public-resolvers`
- `relays`
- `parental-control`
- `opennic`
- `onion-services`
- `odoh-servers`
- `odoh-relays`

By default an interactive selection screen is shown when you run:

```bash
python3 ping_dnscrypt.py
```

There you can choose multiple catalogs and multiple protocols to test. The interactive wizard now also lets you:

- choose optional filters such as `nofilter`, `nolog`, `DNSSEC`, IP version, and countries, or use the built-in `I don't know` option
- choose whether to show `top N` or all results
- save the final result as `txt`, `json` or `csv` with an auto-generated name based on date and selected categories
- go back to the previous step with `0`
- return to the main menu after results

You can still select catalogs explicitly with flags or use `--catalog all`.

## Protocol selection

Protocols can now be selected explicitly, including multiple values:

- `DNSCrypt`
- `DoH`
- `ODoH`
- `DNSCrypt relay`
- `ODoH relay`

You can pass `--proto` multiple times, or choose them interactively on startup.

## Explicit filters

Filtering is now fully explicit. Instead of fixed presets, you can combine the criteria you want:

- `--require-nofilter`
- `--require-nolog`
- `--dnssec-only`
- `--ip-version any|ipv4|ipv6`
- `--country NAME` and repeat it as needed

If you do not pass any of these flags, the tool keeps the default behavior neutral and only requires resolvers to be measurable.

## Probe profiles

To avoid checks that feel too fast and opaque, the tool now has explicit probe profiles:

- `fast`
- `balanced`
- `deep`

These presets control attempt count, delays, timeout and the default threaded worker budget. You can still override them manually with:

- `-n`, `--number-ping`
- `-p`, `--ping-delay`
- `-s`, `--server-delay`
- `-m`, `--time-out`
- `--workers`

Latency is measured by:

1. TCP connect latency against the decoded resolver host/port.
2. ICMP fallback if TCP probing fails, unless `--tcp-only` is enabled.
3. Repeated probing with mean latency, standard error and reliability.

## Terminal UI

Terminal output now includes:

- animated progress while catalogs are loading and resolvers are being checked
- live counters for successful and failed checks
- compact stamp rendering so long `sdns://...` values no longer break terminal width
- optional full stamp display when needed

Progress is written to `stderr`, so machine-readable output can still be redirected safely from `stdout`.

During interactive latency checks you can press `Ctrl+C` to stop the current run and return to the main menu.

## Usage

Run the legacy entry point:

```bash
python3 ping_dnscrypt.py --catalog public-resolvers --profile balanced -t --top 10
```

Or use the package entry point:

```bash
python3 -m dnscrypt_sorter.cli --catalog all --proto all --require-nolog --ip-version ipv4 --profile deep -t --all
```

Useful options:

- `--catalog NAME`: select an official catalog, repeatable
- `--catalog all`: load all official catalogs
- `--list-catalogs`: print supported catalog names
- `--proto NAME`: select protocol to test, repeatable
- `--list-protos`: print supported protocol names
- `--require-nofilter`
- `--require-nolog`
- `--dnssec-only`
- `--ip-version any|ipv4|ipv6`
- `--country NAME`
- `--profile fast|balanced|deep`
- `--top N`: print the fastest `N` results
- `--all`: print all successful results
- `--stamp-mode compact|full|hidden`
- `--json`: emit JSON instead of terminal UI
- `--cache-dir PATH`: directory used to cache downloaded catalogs

## Interactive wizard flow

The default interactive flow is now:

1. choose one or more catalogs
2. choose one or more protocols
3. choose optional filters
4. choose result size: `top N` or `all`
5. run checks
6. save results or return to the main menu

At every wizard step after the first one you can type `0` to return to the previous menu. In the main menu and on the first catalog step, `0` exits the program.

Examples:

Check DNSCrypt resolvers from `public-resolvers` with `nofilter`, `nolog`, and IPv4 only, then show the top 10:

```bash
python3 ping_dnscrypt.py --catalog public-resolvers --proto DNSCrypt --require-nofilter --require-nolog --ip-version ipv4 --profile balanced -t --top 10
```

Check all official catalogs, keep only DoH endpoints in Germany, and print everything:

```bash
python3 ping_dnscrypt.py --catalog all --proto DoH --country Germany --profile deep -t --all
```

Emit JSON with full stamps:

```bash
python3 ping_dnscrypt.py --catalog public-resolvers --proto all --top 25 --json
```

Save results non-interactively by redirecting output if needed, or use the built-in wizard save step in interactive mode. The suggested filename now includes the current date plus the selected catalogs, protocols, and filters.

## Credits

Original project: [Magalame/Dnscrypt-list-ping-sorting](https://github.com/Magalame/Dnscrypt-list-ping-sorting) — a program to ping and sort the DNS servers proposed by dnscrypt.

## Development

Run tests:

```bash
python3 -m unittest discover -s tests -v
```

Install as a local package:

```bash
python3 -m pip install -e .
```
