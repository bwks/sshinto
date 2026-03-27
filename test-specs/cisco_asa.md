# Test Specification: cisco_asa

Covers Cisco ASA OS devices (ASAv and physical ASA).

**Lab host:** see `test-specs/lab-devices.md`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `show version` |
| Multi-command pair (TC-COMMON-003) | `show version` + `show interface` |
| Long output — paging test (TC-COMMON-005) | `show running-config` |
| File presence check after SCP (TC-COMMON-004) | `dir disk0:` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-ASA-001: Privileged EXEC mode is entered automatically

**Purpose:** ASA may open in user EXEC mode (`>`). Verify `enable` is sent
and privileged mode (`#`) is reached before commands run.

**Pass criteria:**
- `show running-config` returns output without `% Error` or `Permission denied`
- No `enable` prompt appears in any command output

---

## TC-ASA-002: Paging disabled via `terminal pager 0`

**Purpose:** ASA uses `terminal pager 0` to disable the pager.

**Pass criteria:**
- `show running-config` returns complete configuration without `<--- More --->`

---

## TC-ASA-003: Configuration mode entry and exit

**Commands:**
```
sshinto run ... -c 'configure terminal' -c 'show running-config' -c 'end'
```

**Pass criteria:**
- `show running-config` returns the full running config while in config context
- `end` returns to privileged EXEC without a config-mode prompt leaking into output
