# Test Specification: palo_alto_panos

Covers Palo Alto Networks PAN-OS devices (PA-VM and physical firewalls).

**Lab host:** see `test-specs/lab-devices.md`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `show system info` |
| Multi-command pair (TC-COMMON-003) | `show system info` + `show interface all` |
| Long output — paging test (TC-COMMON-005) | `show running security-policy` |
| File presence check after SCP (TC-COMMON-004) | `show system files` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-PANOS-001: Operational mode prompt is detected

**Purpose:** PAN-OS operational mode presents an `admin@hostname>` style
prompt. Verify sshinto detects it correctly on login.

**Pass criteria:**
- `sshinto check` exits 0 and prints a non-empty `Prompt detected:` line
- The detected prompt contains `>` (operational mode)

---

## TC-PANOS-002: Paging disabled via `set cli pager off`

**Purpose:** PAN-OS uses `set cli pager off` to disable the pager.

**Pass criteria:**
- `show running security-policy` (or any long-output command) returns complete
  output without `---[###]---` or similar pager interruptions

---

## TC-PANOS-003: Configuration mode entry and exit

**Commands:**
```
sshinto run ... -c 'configure' -c 'show' -c 'exit'
```

**Pass criteria:**
- Prompt changes to `#` (configure mode) after `configure`
- `show` returns the candidate configuration
- `exit` returns to operational mode (`>`) without config-mode prompt leaking
  into subsequent output
