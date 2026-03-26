# Test Specification: mikrotik_ros

Covers MikroTik RouterOS devices (CHR and physical).

**Lab host:** see `test-specs/lab-devices.md`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `/system identity print` |
| Multi-command pair (TC-COMMON-003) | `/system identity print` + `/ip address print` |
| Long output — paging test (TC-COMMON-005) | `/ip route print` |
| File presence check after SCP (TC-COMMON-004) | `/file print` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-ROS-001: Bracket prompt format is recognised

**Purpose:** MikroTik prompts use a bracketed format: `[user@host] >` or
`[user@host] /ip/address>`. Verify both the top-level and path-qualified
variants match.

**Pass criteria:**
- `sshinto check` succeeds and detected prompt matches `[...]>` or `[...] >`

---

## TC-ROS-002: No paging command is needed

**Purpose:** RouterOS does not have an interactive pager; long outputs are
printed fully without intervention. The `paging_disable` field is intentionally
empty. Verify that no paging command is sent and output is complete.

**Pass criteria:**
- `/ip route print` returns all routes without truncation or pager prompt
- The connection does not error on the empty paging command

---

## TC-ROS-003: Hierarchical menu navigation

**Purpose:** RouterOS commands can be prefixed with a menu path. Verify that
multi-segment paths work and the prompt correctly reflects the current menu
context when changed.

**Commands:**
```
sshinto run ... -c '/ip address print' -c '/system resource print'
```

**Pass criteria:**
- Each command returns the expected output for that menu path
- Outputs are not mixed between commands
