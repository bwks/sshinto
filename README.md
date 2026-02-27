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

[hosts.lab-router]
host = "172.31.0.11"
device_type = "cisco_ios"
legacy_crypto = true

[hosts.core-switch]
host = "10.0.1.1"
port = 2222
device_type = "arista_eos"
username = "admin"
key_file = "~/.ssh/arista_key"
```

Then reference hosts by name:

```bash
# Named host — only commands on CLI
sshinto run lab-router -c 'show version'

# Named host with a CLI override
sshinto run lab-router -U different_user -c 'show version'
```

### Config merge priority

Values are resolved in this order (highest wins):

```
CLI flag  →  host entry  →  [defaults]  →  hardcoded default
```

Commands (`-c`) are always specified on the CLI.

## Supported device types

- `cisco_ios`
- `cisco_ios_xr`
- `cisco_nxos`
- `juniper_junos`
- `arista_eos`
