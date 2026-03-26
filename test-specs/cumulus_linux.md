# Test Specification: cumulus_linux

Covers Cumulus Linux devices (5.x with NVUE).

**Lab host:** see `test-specs/lab-devices.md`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `nv show system` |
| Multi-command pair (TC-COMMON-003) | `nv show system` + `ip addr` |
| Long output — paging test (TC-COMMON-005) | `nv show interface` |
| File presence check after SCP (TC-COMMON-004) | `ls /tmp/` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-CUMULUS-001: VRF-qualified prompt is recognised

**Purpose:** Cumulus Linux 5.x includes the management VRF name in the shell
prompt: `user@switch:mgmt:~$`. Verify the prompt regex matches this format as
well as the plain format (`user@switch:~$`).

**Pass criteria:**
- `sshinto check` succeeds and the detected prompt includes the VRF segment
  (e.g. `sherpa@dev21:mgmt:~$`)

---

## TC-CUMULUS-002: bash readline ANSI sequences do not corrupt output

**Purpose:** Cumulus Linux's bash uses readline which emits `\x1b[?2004l\r`
(bracketed paste disable) before each command echo. Verify this sequence is
stripped and does not appear in command output or prevent echo detection.

**Pass criteria:**
- Output of `nv show system` does not start with `[?2004l` or any ANSI escape
- The command echo (`nv show system`) does not appear in the output

---

## TC-CUMULUS-003: NVUE operational commands return structured output

**Commands:**
```
sshinto run ... -c 'nv show system' -c 'nv show interface'
```

**Pass criteria:**
- `nv show system` output contains `hostname`, `build`, and `uptime` fields
- `nv show interface` output contains at least the loopback interface (`lo`)
- Outputs are not mixed between commands

---

## TC-CUMULUS-004: Standard Linux commands work alongside NVUE

**Purpose:** Cumulus is a full Linux system; both standard Linux commands and
NVUE commands must work in the same session.

**Commands:**
```
sshinto run ... -c 'uname -a' -c 'nv show system'
```

**Pass criteria:**
- `uname -a` returns a valid Linux kernel string containing `GNU/Linux`
- `nv show system` returns NVUE output
- Outputs are not mixed
