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

### Connecting through a jump host

Use `-J` to connect through a bastion/jump host:

```bash
sshinto run -h 172.31.0.11 -U sherpa -d cisco_ios --legacy-crypto \
  -J admin@bastion.example.com --jumphost-key-file ~/.ssh/id_ed25519 \
  -c 'show version'
```

The jump host spec supports `user@host:port`, `user@host`, `host:port`, or just `host`. If the user is omitted it defaults to the target's username; port defaults to 22.

Use `--jumphost-username` to override the username independently from the `-J` spec:

```bash
sshinto run -h 172.31.0.11 -U sherpa -d cisco_ios \
  -J bastion.example.com --jumphost-username admin --jumphost-key-file ~/.ssh/id_ed25519 \
  -c 'show version'
```

With password auth for the jump host:

```bash
sshinto run -h 10.0.0.1 -U sherpa -P 'secret' -d arista_eos \
  -J bastion:2222 --jumphost-password 'jumppass' \
  -c 'show version'
```

Jump host defaults can also be set in the config file:

```toml
[defaults]
username = "sherpa"
jumphost = "admin@bastion.example.com"
jumphost_key_file = "~/.ssh/id_ed25519"
```

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

#### Jobs with a jump host

Set `jumphost` in the jobfile defaults, a group, or a per-host entry:

```toml
[defaults]
username = "sherpa"
device_type = "cisco_ios"
commands = ["show version"]
jumphost = "admin@bastion.example.com"
jumphost_key_file = "~/.ssh/id_ed25519"

[[hosts]]
name = "lab-router"
host = "172.31.0.11"
legacy_crypto = true

[[hosts]]
name = "dmz-switch"
host = "10.99.0.1"
device_type = "arista_eos"
jumphost = "admin@dmz-bastion:2222"   # per-host override
jumphost_password = "dmzpass"
```

You can also override the jump host from the CLI, which takes priority over anything in the jobfile:

```bash
sshinto job ./upgrade.toml -J admin@bastion --jumphost-key-file ~/.ssh/id_ed25519
```

### Uploading files via SCP

Upload a local file to a remote device:

```bash
sshinto scp -h 172.31.0.11 -U sherpa -k ~/.ssh/id_ed25519 --source config.txt --dest /tmp/config.txt
```

With a jump host:

```bash
sshinto scp -h 172.31.0.11 -U sherpa -k ~/.ssh/id_ed25519 \
  -J admin@bastion --jumphost-key-file ~/.ssh/id_ed25519 \
  --source config.txt --dest /tmp/config.txt
```

The default transfer timeout is 30 seconds; override with `-t`:

```bash
sshinto scp -h 172.31.0.11 -U sherpa -k ~/.ssh/id_ed25519 --source bigfile.bin --dest /tmp/bigfile.bin -t 120
```

### Uploading files in jobs

Jobs can upload files to each host before running commands. Add `[[defaults.uploads]]`, `[[groups.uploads]]`, or `[[hosts.uploads]]` entries:

```toml
[defaults]
username = "sherpa"
key_file = "~/.ssh/id_ed25519"
device_type = "cisco_ios"
commands = ["show version"]

[[defaults.uploads]]
source = "configs/acl.txt"
dest = "/tmp/acl.txt"

[[hosts]]
name = "dev01"
host = "172.31.0.11"
```

Uploads inherit with the same priority as other fields: host entry > group > defaults. A job with only uploads and no commands is also valid.

## Supported device types

- `cisco_ios`
- `cisco_ios_xr`
- `cisco_nxos`
- `juniper_junos`
- `arista_eos`
