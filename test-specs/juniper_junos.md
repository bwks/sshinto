# Test Specification: juniper_junos

Covers Juniper JunOS devices (vSRX, vMX, vQFX, virtual router, etc.).

**Lab host:** 172.31.1.15 (dev13, juniper_vrouter)
**Auth:** `sherpa` / key `sherpa_ssh_key`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `show version` |
| Multi-command pair (TC-COMMON-003) | `show version` + `show interfaces terse` |
| Long output — paging test (TC-COMMON-005) | `show configuration` |
| File presence check after SCP (TC-COMMON-004) | `file list /var/tmp/` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-JUNOS-001: Prompt variants are recognised

**Purpose:** JunOS uses `>` (operational mode) and `#` (configuration mode)
and also `%` for the root shell. Verify the prompt regex matches all variants.

**Pass criteria:**
- `sshinto check` succeeds when logged in as a regular user (prompt `user@host>`)
- `sshinto check` succeeds when logged in as root from shell (prompt `root@host%`)

---

## TC-JUNOS-002: Paging disable via `set cli screen-length 0`

**Purpose:** JunOS uses `set cli screen-length 0` (not `terminal length 0`).
Confirm this takes effect.

**Pass criteria:**
- `show configuration` returns the full configuration without `---<more>---`

---

## TC-JUNOS-003: Configuration mode entry and exit

**Purpose:** JunOS uses `configure` to enter config mode and
`exit configuration-mode` to return to operational mode.

**Commands:**
```
sshinto run ... -c 'configure' -c 'show | compare' -c 'exit configuration-mode'
```

**Pass criteria:**
- `show | compare` returns empty output (no uncommitted changes) or a valid diff
- `exit configuration-mode` returns to operational mode
- A command after exit (e.g. `show version`) works correctly
