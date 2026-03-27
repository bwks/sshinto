# Test Specification: cisco_ios

Covers Cisco IOS and Cisco IOS-XE devices.

**Lab host:** see `test-specs/lab-devices.md`
**Flags:** `--legacy-crypto` is NOT required for cat8000v; may be needed for older IOS devices.

All cases in `common.md` must pass in addition to the cases below.

**Note on TC-COMMON-006:** IOS treats any single bare word at the privileged EXEC prompt as a
hostname and performs a DNS lookup if `no ip domain-lookup` is not configured. Use
`show sshinto-invalid-xyz` instead of a bare invalid token — `show` is a recognised keyword so
IOS returns `% Invalid input detected at '^' marker.` immediately without a DNS lookup.

---

## Reference commands

| Purpose | Command |
|---------|---------|
| Show version (TC-COMMON-002) | `show version` |
| Multi-command pair (TC-COMMON-003) | `show version` + `show ip interface brief` |
| Long output — paging test (TC-COMMON-005) | `show running-config` |
| File presence check after SCP (TC-COMMON-004) | `dir flash:` |
| Invalid command (TC-COMMON-006) | `show sshinto-invalid-xyz` |

---

## TC-IOS-001: Prompt detection in user EXEC mode

**Purpose:** Confirm the prompt regex matches both `>` (user EXEC) and `#`
(privileged EXEC) variants.

**Method:** Connect with a user that lands in user EXEC mode (prompt ends `>`).
Run `sshinto check`. Then connect as a privileged user (prompt ends `#`) and
repeat.

**Pass criteria:**
- Both prompt variants are detected without timeout
- Detected prompt string matches `<hostname>#` or `<hostname>>`

---

## TC-IOS-002: Privileged EXEC mode is entered automatically

**Purpose:** Verify that sshinto sends the `enable` command when the device
opens in user EXEC mode and that subsequent commands run in privileged context.

**Note:** This requires the device to be configured to require `enable`, and
the `enable` password to be available. The current lab host (cat8000v) opens
directly in privileged mode; test against a device configured with exec
privilege level < 15 to exercise this path.

**Pass criteria:**
- Commands that require privileged mode (e.g. `show running-config`) return
  output rather than `% Invalid input detected`
- No `enable` prompt leaks into command output

---

## TC-IOS-003: Configuration mode entry and exit

**Purpose:** Verify sshinto can enter global configuration mode, run a config
command, and return to privileged EXEC cleanly.

**Commands:**
```
sshinto run ... -c 'configure terminal' -c 'do show version' -c 'end'
```

**Pass criteria:**
- `configure terminal` output is empty or contains only the config prompt transition
- `do show version` returns version output
- `end` returns the device to privileged EXEC (subsequent commands work)
- No config-mode prompt (`(config)#`) appears in the output of `do show version`

---

## TC-IOS-004: Paging disable verified for running-config

**Purpose:** `show running-config` on a real device will exceed one page.
Confirm `terminal length 0` takes effect.

**Pass criteria:**
- Output contains `end` as the final non-empty line (Cisco IOS always ends
  running-config with `end`)
- No `--More--` string appears anywhere in the output
