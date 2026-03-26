# Test Specification: cisco_iosxr

Covers Cisco IOS-XR devices.

**Lab host:** none currently active in lab
**Auth:** `sherpa` / key `sherpa_ssh_key`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `show version` |
| Multi-command pair (TC-COMMON-003) | `show version` + `show interfaces brief` |
| Long output — paging test (TC-COMMON-005) | `show running-config` |
| File presence check after SCP (TC-COMMON-004) | `dir disk0:` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-IOSXR-001: Prompt format is recognised

**Purpose:** IOS-XR prompts include the route-processor path
(`RP/0/RSP0/CPU0:hostname#`), which differs from IOS. Verify the pattern
matches correctly.

**Pass criteria:**
- `sshinto check` detects the prompt and prints the full RP-qualified string
- No timeout or misdetection

---

## TC-IOSXR-002: Configuration mode entry and commit

**Purpose:** IOS-XR uses a two-phase commit model. Verify that entering config
mode, making a change, and issuing `commit` (or `abort`) works without
corrupting subsequent command reads.

**Commands:**
```
sshinto run ... -c 'configure' -c 'abort'
```

**Pass criteria:**
- `configure` transitions to config mode (no output or config prompt in output)
- `abort` returns to privileged EXEC cleanly
- A third command after `abort` runs successfully

---

## TC-IOSXR-003: Paging disable verified

**Purpose:** `show running-config` on IOS-XR can be lengthy.
`terminal length 0` must suppress the pager.

**Pass criteria:**
- No pager prompt (`--More--`) appears in the output
- Output ends with the last configuration stanza, not a truncation artifact
