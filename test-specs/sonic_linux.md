# Test Specification: sonic_linux

Covers SONiC Linux devices (open-source network OS from Microsoft).

**Lab host:** 172.31.1.20 (dev22, SONiC master.0-bb0612a10)
**Auth:** `sherpa` / key `sherpa_ssh_key`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `show version` |
| Multi-command pair (TC-COMMON-003) | `show version` + `show interface status` |
| Long output — paging test (TC-COMMON-005) | `show runningconfiguration all` |
| File presence check after SCP (TC-COMMON-004) | `ls /tmp/` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-SONIC-001: Standard Linux prompt is recognised

**Purpose:** SONiC uses a standard bash prompt (`user@switch:~$`).
Verify prompt detection works correctly.

**Pass criteria:**
- `sshinto check` succeeds and detected prompt matches `user@hostname:~$`

---

## TC-SONIC-002: SONiC `show` commands return output

**Purpose:** SONiC wraps its management CLI in Python scripts available as
`show` commands from the bash shell. Verify these are accessible.

**Commands:**
```
sshinto run ... -c 'show version' -c 'show interface status'
```

**Pass criteria:**
- `show version` output contains `SONiC Software Version`
- `show interface status` output contains at least the loopback interface
- Both commands return output without corruption

---

## TC-SONIC-003: Docker container status is accessible

**Purpose:** SONiC runs its components in Docker containers. Verify that
`show services` or `docker ps` returns a non-empty list of running containers.

**Commands:**
```
sshinto run ... -c 'show services'
```

**Pass criteria:**
- Output contains at least one running service/container name
- No error or permission denial

---

## TC-SONIC-004: Standard Linux commands work alongside SONiC commands

**Commands:**
```
sshinto run ... -c 'uname -a' -c 'show version'
```

**Pass criteria:**
- `uname -a` contains a valid Linux kernel string
- `show version` contains `SONiC Software Version`
- Outputs are not mixed
