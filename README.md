# sshinto
SSH on crack

## Usage

### Fully explicit CLI invocation

```bash
sshinto run -h 172.31.0.11 -U sherpa -d cisco_ios -c 'show version'
```

With a private key and legacy crypto:

```bash
sshinto run -h 172.31.0.11 -U sherpa -k ~/.ssh/id_ed25519 -d cisco_ios --legacy-crypto -c 'show version'
```

Multiple commands:

```bash
sshinto run -h 172.31.0.11 -U sherpa -d cisco_ios -c 'show version' -c 'show ip route'
```

### Using a config file

Create `sshinto.toml` in your project directory, or `~/.sshinto/sshinto.toml` for a global config. The project-local file takes priority.

```toml
[defaults]
username = "sherpa"
key_file = "~/.ssh/id_ed25519"
timeout = 10
legacy_crypto = false
port = 22
```

### Config merge priority

Values are resolved in this order (highest wins):

```
CLI flag  →  [defaults]  →  hardcoded default
```

Commands (`-c`) are always specified on the CLI.

### Running jobs across multiple hosts

Create a jobfile (e.g. `upgrade.toml`):

```toml
[defaults]
username = "sherpa"
key_file = "~/.ssh/id_ed25519"
commands = ["show version", "show ip route"]

[[groups]]
name = "ios_devices"
device_type = "cisco_ios"
legacy_crypto = true
timeout = 10

[[groups]]
name = "eos_devices"
device_type = "arista_eos"
timeout = 15
commands = ["show version"]   # overrides defaults commands for this group

[[hosts]]
name = "lab-router"
host = "172.31.0.11"
group = "ios_devices"

[[hosts]]
name = "core-switch"
host = "10.0.1.1"
group = "eos_devices"
username = "admin"
```

Groups let you define named bundles of settings that multiple hosts can reference via `group = "name"`, reducing duplication across hosts of the same type. Groups can set any field that `[defaults]` supports, including `commands`.

Run the job:

```bash
sshinto job ./upgrade.toml
```

Limit concurrency:

```bash
sshinto job ./upgrade.toml --workers 5
```

Each host's output is grouped together, followed by a summary:

```
=== lab-router (172.31.0.11) ===

--- show version ---
Cisco IOS Software...

--- show ip route ---
...

=== core-switch (10.0.1.1) ===

--- show version ---
...

=== Summary ===
lab-router: ok
core-switch: error - authentication failed
```

Host entries inherit from their group (if set), then `[defaults]`, and can override any field. Merge priority: `host entry → group → defaults → hardcoded`. If any host requires password authentication and no password is set, you'll be prompted once.

## Supported device types

- `cisco_ios`
- `cisco_ios_xr`
- `cisco_nxos`
- `juniper_junos`
- `arista_eos`
