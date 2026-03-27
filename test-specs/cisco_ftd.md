# Test Specification: cisco_ftd

Covers Cisco Firepower Threat Defense (FTD) devices accessed via FTD CLISH.

**Lab host:** see `test-specs/lab-devices.md`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `show version` |
| Multi-command pair (TC-COMMON-003) | `show version` + `show interface` |
| Long output — paging test (TC-COMMON-005) | `show running-config` |
| File presence check after SCP (TC-COMMON-004) | `show disk` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-FTD-001: FTD CLISH prompt is detected

**Purpose:** FTD CLISH presents a `>` prompt (optionally preceded by the
hostname). Verify that sshinto detects this prompt correctly on login.

**Pass criteria:**
- `sshinto check` exits 0 and prints a non-empty `Prompt detected:` line
- The detected prompt ends with `>`

---

## TC-FTD-002: No paging interference

**Purpose:** FTD CLISH does not have a traditional pager; verify that long
output commands complete without any `--More--` style interruption.

**Pass criteria:**
- `show running-config` (or equivalent) returns output without a pager prompt
- Output is complete (contains expected final lines)

---

## TC-FTD-003: No mode escalation required

**Purpose:** FTD CLISH has no separate privileged or configuration mode.
Verify that commands run without any enable/configure prompt being sent.

**Pass criteria:**
- Standard operational commands return output without `enable` or `configure`
  appearing in the output headers
