# Test Specification: aruba_aos

Covers Aruba AOS-CX devices.

**Lab host:** see `test-specs/lab-devices.md`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `show version` |
| Multi-command pair (TC-COMMON-003) | `show version` + `show interface all` |
| Long output — paging test (TC-COMMON-005) | `show running-config` |
| File presence check after SCP (TC-COMMON-004) | `dir /tmp/` (from bash shell context) |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-ARUBA-001: Privileged EXEC mode is entered automatically

**Purpose:** Aruba AOS-CX may open in operator mode (`>`). Verify `enable` is
sent and manager mode (`#`) is reached before commands run.

**Pass criteria:**
- `show running-config` returns output without `Permission denied`
- No `enable` prompt appears in any command output

---

## TC-ARUBA-002: Paging disabled via `no page`

**Purpose:** Aruba AOS-CX uses `no page` to disable the pager.

**Pass criteria:**
- `show running-config` returns complete configuration without `--More--`

---

## TC-ARUBA-003: Configuration mode entry and exit

**Commands:**
```
sshinto run ... -c 'configure terminal' -c 'show running-config' -c 'end'
```

**Pass criteria:**
- `show running-config` returns the full running config while in config context
- `end` returns to manager EXEC without a config-mode prompt leaking into output
