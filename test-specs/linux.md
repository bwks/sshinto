# Test Specification: linux

Covers generic Linux and BSD hosts — including FRRouting appliances,
devboxes, and any standard Linux system not covered by a more specific type.

**Lab host:** 172.31.1.18 (dev20, frr_linux — container)
**Auth:** `sherpa` / key `sherpa_ssh_key`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `uname -a` |
| Multi-command pair (TC-COMMON-003) | `uname -a` + `ip addr` |
| Long output — paging test (TC-COMMON-005) | `ip route show` |
| File presence check after SCP (TC-COMMON-004) | `ls /tmp/` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-LINUX-001: Both `user@host:path$` and `host:path$` prompt formats match

**Purpose:** Some Linux hosts do not include the username in the prompt.
Verify both formats are recognised.

**Pass criteria:**
- `sshinto check` succeeds whether the prompt is `user@host:~$` or `host:~$`

---

## TC-LINUX-002: FRRouting `vtysh` commands are accessible

**Purpose:** On FRR appliances, the routing CLI is available via `vtysh`.
Verify that running a `vtysh` command works correctly.

**Commands:**
```
sshinto run ... -c 'vtysh -c "show version"'
```

**Pass criteria:**
- Output contains `FRRouting` and a version number
- No error from the shell (e.g. `vtysh: command not found`)

---

## TC-LINUX-003: No paging command interferes with the session

**Purpose:** `paging_disable` for the `linux` type is an empty string — no
command is sent. Verify that this does not cause a timeout or extra prompt
to be consumed.

**Pass criteria:**
- First command in a session returns correct output with no extra delay
- No spurious data from the paging disable phase appears in command output
