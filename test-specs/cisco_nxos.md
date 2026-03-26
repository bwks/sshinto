# Test Specification: cisco_nxos

Covers Cisco NX-OS devices (Nexus switches, virtual Nexus).

**Lab host:** see `test-specs/lab-devices.md`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `show version` |
| Multi-command pair (TC-COMMON-003) | `show version` + `show interface brief` |
| Long output — paging test (TC-COMMON-005) | `show running-config` |
| File presence check after SCP (TC-COMMON-004) | `dir bootflash:` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-NXOS-001: Paging disable via `terminal length 0`

**Purpose:** NX-OS uses the same paging command as IOS. Verify it is effective.

**Pass criteria:**
- `show running-config` returns complete configuration without `--More--`

---

## TC-NXOS-002: No `enable` command is required

**Purpose:** NX-OS does not use a separate privileged EXEC mode; the device
opens directly in a privileged context. Verify that the `enable` command is
not sent and does not cause an error.

**Pass criteria:**
- `show running-config` returns output on first connection without any privilege
  escalation being performed
- No `enable` command appears in the session

---

## TC-NXOS-003: Configuration mode entry and exit

**Commands:**
```
sshinto run ... -c 'configure terminal' -c 'show version' -c 'end'
```

**Pass criteria:**
- `show version` returns version output while in config mode
- `end` returns to privileged EXEC cleanly
