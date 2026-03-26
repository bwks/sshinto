# Test Specification: nokia_srlinux

Covers Nokia SR Linux devices.

**Lab host:** 172.31.1.16 (dev17, nokia_srlinux — container)
**Auth:** `sherpa` / key `sherpa_ssh_key`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `show version` |
| Multi-command pair (TC-COMMON-003) | `show version` + `show system information` |
| Long output — paging test (TC-COMMON-005) | `info flat` |
| File presence check after SCP (TC-COMMON-004) | `bash ls /tmp/` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-SRL-001: Prompt letter prefix is recognised

**Purpose:** SR Linux prompts begin with a single letter denoting the role
(`A` for active, `B` for standby, etc.) followed by `:hostname#` or
`A:user@hostname#`. Verify all variants are matched.

**Pass criteria:**
- `sshinto check` succeeds and detected prompt starts with a letter and colon
  (e.g. `A:admin@dev17#`)

---

## TC-SRL-002: Paging disabled via `environment cli-engine type basic`

**Purpose:** SR Linux uses a TUI-based CLI by default. `environment cli-engine
type basic` switches to plain-text output, which is required for correct
command output capture.

**Pass criteria:**
- `info flat` returns complete flat-format configuration without any TUI
  artefacts or truncation
- No pager prompts appear

---

## TC-SRL-003: Running in candidate and state contexts

**Purpose:** SR Linux uses `enter candidate` / `enter state` to switch between
edit and read-only contexts. Verify context switching does not break prompt
detection.

**Commands:**
```
sshinto run ... -c 'enter candidate' -c 'show version' -c 'quit'
```

**Pass criteria:**
- `show version` returns version output while in candidate context
- `quit` returns to the top-level context
- A command run after `quit` succeeds
