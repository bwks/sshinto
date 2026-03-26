# Test Specification: arista_eos

Covers Arista EOS devices (physical and virtual — vEOS, cEOS).

**Lab host:** 172.31.1.12 (dev01, arista_veos)
**Auth:** `sherpa` / key `sherpa_ssh_key`

All cases in `common.md` must pass in addition to the cases below.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `show version` |
| Multi-command pair (TC-COMMON-003) | `show version` + `show interfaces status` |
| Long output — paging test (TC-COMMON-005) | `show running-config` |
| File presence check after SCP (TC-COMMON-004) | `dir flash:` |
| Invalid command (TC-COMMON-006) | `sshinto_invalid_command_xyz` |

---

## TC-EOS-001: Privileged EXEC mode is entered automatically

**Purpose:** Arista EOS may open in user EXEC mode (`>`). Verify `enable` is
sent and privileged mode is reached before commands are run.

**Pass criteria:**
- `show running-config` returns output (requires privilege level 15)
- No `% Authorization denied` error in the output

---

## TC-EOS-002: Paging disable via `terminal length 0`

**Purpose:** Arista EOS uses the same paging command as Cisco IOS.

**Pass criteria:**
- `show running-config` returns the complete config ending with `!` or `end`
- No `--More--` string in output

---

## TC-EOS-003: Configuration mode entry and exit

**Commands:**
```
sshinto run ... -c 'configure' -c 'show running-config' -c 'end'
```

**Pass criteria:**
- `show running-config` returns the full running configuration
- `end` exits config mode cleanly
- No config-mode prompt (`(config)#`) appears in any command output
