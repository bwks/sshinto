# Common Test Specification

These test cases apply to **every device model** supported by sshinto.
When adding a new device type, all cases in this file must pass before
the device type is considered complete. Device-specific test files may
extend these with additional cases.

---

## TC-COMMON-001: Connectivity and prompt detection

**Purpose:** Verify that sshinto can connect, authenticate, and detect the
device prompt without timing out or misidentifying the prompt.

**Command:**
```
sshinto check -h <host> -U <user> -k <key> -d <device_type>
```

**Pass criteria:**
- Exits 0
- Prints `Prompt detected: <something>` where `<something>` is a non-empty string
- Prints `Check passed for <host> (<DeviceKind>)`
- Completes within the default timeout

---

## TC-COMMON-002: Single command — output is correct

**Purpose:** Verify that running one command returns only that command's
output: no echoed command line, no shell prompt, and no ANSI escape sequences
that corrupt the content.

**Command:**
```
sshinto run -h <host> -U <user> -k <key> -d <device_type> -c '<show_version_equivalent>'
```

Use the device-appropriate version command (see each device spec).

**Pass criteria:**
- Exits 0
- stdout contains the expected version string for that platform
- stdout does NOT contain the command text as the first line
- stdout does NOT contain the shell/CLI prompt
- Content is stable across repeated runs (same command, same output)

---

## TC-COMMON-003: Multiple commands — outputs are not mixed

**Purpose:** Verify that when two or more commands are run in sequence, each
command's output is attributed to the correct command and outputs do not bleed
into each other.

**Command:**
```
sshinto run -h <host> -U <user> -k <key> -d <device_type> \
  -c '<command_1>' -c '<command_2>'
```

**Pass criteria:**
- Exits 0
- Output for command 1 does not appear under the command 2 header and vice versa
- Both outputs are non-empty
- The output under each `--- <command> ---` header matches what running that
  command alone would produce

---

## TC-COMMON-004: SCP file upload

**Purpose:** Verify that a file can be uploaded to the device at the type's
default `base_path`.

**Command:**
```
echo "sshinto-test" > /tmp/sshinto-test.txt
sshinto scp -h <host> -U <user> -k <key> -d <device_type> --source /tmp/sshinto-test.txt
```

Then verify the file exists on the device:
```
sshinto run -h <host> -U <user> -k <key> -d <device_type> \
  -c '<list_or_cat_base_path_command>'
```

**Pass criteria:**
- `sshinto scp` exits 0 and prints `Upload complete.`
- The follow-up command confirms the file is present at `<base_path>/sshinto-test.txt`

---

## TC-COMMON-005: Paging is disabled — long output is not truncated

**Purpose:** Verify that the paging disable command is effective and that
commands producing more output than one terminal page return complete results.

**Command:**
```
sshinto run -h <host> -U <user> -k <key> -d <device_type> -c '<long_output_command>'
```

Use a command known to produce multi-page output on that platform (see each
device spec for the recommended command).

**Pass criteria:**
- Output does not contain a pager prompt (`--More--`, `<--- More --->`, `(END)`, etc.)
- Output is complete (contains the expected final lines of the command)

---

## TC-COMMON-006: Invalid command — error is returned cleanly

**Purpose:** Verify that an unrecognised command returns an error message from
the device and does not hang, crash, or corrupt subsequent command reads.

**Command:**
```
sshinto run -h <host> -U <user> -k <key> -d <device_type> \
  -c 'sshinto_invalid_command_xyz' -c '<valid_command>'
```

**Pass criteria:**
- Exits 0 (the tool itself does not error out)
- Output for `sshinto_invalid_command_xyz` contains the device's error text
  (e.g. `Invalid input`, `% Unknown command`, `command not found`)
- Output for the valid command is correct and unaffected
