# Silent subnet finder
A simple tool to get a valid IP and netmask in an unknown environment

## Dependencies
You must install tshark for this tool to work

## Installation
```bash
cd silent_subnet_finder
pipx install .
```

## Usage
```bash
 Usage: silent-subnet-finder [OPTIONS] IFACE:{lo|eno1}

 Update tour network config to a right one

╭─ Arguments ───────────────────────────────────────────────────────────────────────────────╮
│ *    iface      IFACE:{lo|eno1}                      Interface to configure               │
│                                                      [default: None]                      │
│                                                      [required]                           │
╰───────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ─────────────────────────────────────────────────────────────────────────────────╮
│ --install-completion            Install completion for the current shell.                 │
│ --show-completion               Show completion for the current shell, to copy it or      │
│                                 customize the installation.                               │
│ --help                -h        Show this message and exit.                               │
╰───────────────────────────────────────────────────────────────────────────────────────────╯
```
