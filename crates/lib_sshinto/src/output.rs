use regex::Regex;

/// Strip the echoed command (first line) and trailing prompt (last line)
/// from raw SSH output, returning only the command's actual response.
pub fn strip_command_output(raw: &str, command: &str, prompt_re: &Regex) -> String {
    let mut text = raw;
    let cmd = command.trim();

    // Strip echo: find the last line that looks like the echoed command and
    // discard everything up to and including it.
    //
    // Three echo styles are handled:
    // 1. Normal echo  — first line equals the command exactly.
    // 2. Wide-terminal echo (MikroTik at 200 cols) — one long line that both
    //    starts and ends with the command text.
    // 3. Redraw echo (PAN-OS CLISH) — multiple lines; each is an intermediate
    //    redraw of the command as it is processed character-by-character.
    //    The last redraw line ends with the full command, possibly preceded by
    //    the prompt (e.g. "admin@fw> show system info").
    //
    // We scan from the beginning and track the byte offset immediately after
    // the last line that looks like an echo line.  If we find one, we skip
    // everything up to that point.
    let mut last_echo_end: Option<usize> = None;
    let mut scan = text;
    let mut byte_offset: usize = 0;

    while let Some(nl) = scan.find('\n') {
        let raw_line = &scan[..nl];
        let clean = crate::session::strip_ansi(raw_line.trim_end_matches('\r'));
        // Take the visible portion after the last \r (handles in-line overwrite
        // redraws that collapse multiple writes into one visible line).
        let visible = clean.rsplit('\r').next().unwrap_or(&clean).trim();

        let is_echo = visible == cmd
            // Wide-terminal: line starts AND ends with the command (with padding
            // between, e.g. MikroTik).
            || (visible.starts_with(cmd) && visible.ends_with(cmd) && visible.len() > cmd.len())
            // Redraw echo: prompt text precedes the command on the line.
            || visible.ends_with(cmd);

        if is_echo {
            last_echo_end = Some(byte_offset + nl + 1);
        }

        byte_offset += nl + 1;
        scan = &scan[nl + 1..];
    }

    if let Some(end) = last_echo_end {
        text = &text[end..];
    }

    // Strip trailing prompt: trim whitespace from the end, then check if
    // the last line matches the prompt regex.
    let trimmed = text.trim_end();
    if let Some(last_nl) = trimmed.rfind('\n') {
        let last_line = trimmed[last_nl + 1..].trim_end_matches('\r').trim();
        if prompt_re.is_match(last_line) {
            text = &text[..last_nl + 1];
        }
    } else {
        // Single line remaining — check if it's just a prompt.
        let last_line = trimmed.trim_end_matches('\r').trim();
        if prompt_re.is_match(last_line) {
            return String::new();
        }
    }

    text.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cisco_prompt_re() -> Regex {
        Regex::new(r"^[\w\-\.]+[>#]$").unwrap()
    }

    fn juniper_prompt_re() -> Regex {
        Regex::new(r"^\w+@[\w\-\.]+[>%#]$").unwrap()
    }

    fn iosxr_prompt_re() -> Regex {
        Regex::new(r"^RP/\d+/\w+/\w+:[\w\-\.]+#$").unwrap()
    }

    fn panos_prompt_re() -> Regex {
        Regex::new(r"[\w\-\.@]+[#>]\s*$").unwrap()
    }

    #[test]
    fn basic_strip() {
        let raw = "show version\r\nCisco IOS v15.1\r\nrouter#\r\n";
        let result = strip_command_output(raw, "show version", &cisco_prompt_re());
        assert_eq!(result, "Cisco IOS v15.1\r\n");
    }

    #[test]
    fn multiline_output() {
        let raw = "show ip route\r\nGateway of last resort\r\n10.0.0.0/8 via 10.1.1.1\r\n172.16.0.0/12 via 10.1.1.1\r\nrouter#\r\n";
        let result = strip_command_output(raw, "show ip route", &cisco_prompt_re());
        assert_eq!(
            result,
            "Gateway of last resort\r\n10.0.0.0/8 via 10.1.1.1\r\n172.16.0.0/12 via 10.1.1.1\r\n"
        );
    }

    #[test]
    fn trailing_whitespace_on_prompt() {
        let raw = "show version\r\nCisco IOS v15.1\r\nrouter#  \r\n  \n";
        let result = strip_command_output(raw, "show version", &cisco_prompt_re());
        assert_eq!(result, "Cisco IOS v15.1\r\n");
    }

    #[test]
    fn empty_output_echo_and_prompt_only() {
        let raw = "show version\r\nrouter#\r\n";
        let result = strip_command_output(raw, "show version", &cisco_prompt_re());
        assert_eq!(result, "");
    }

    #[test]
    fn no_echo_match_preserves_output() {
        let raw = "different command\r\nSome output\r\nrouter#\r\n";
        let result = strip_command_output(raw, "show version", &cisco_prompt_re());
        assert_eq!(result, "different command\r\nSome output\r\n");
    }

    #[test]
    fn no_prompt_match_preserves_output() {
        let raw = "show version\r\nCisco IOS v15.1\r\nsome trailing text\r\n";
        let result = strip_command_output(raw, "show version", &cisco_prompt_re());
        assert_eq!(result, "Cisco IOS v15.1\r\nsome trailing text\r\n");
    }

    #[test]
    fn juniper_prompt() {
        let raw = "show version\r\nJunos: 21.4R3\r\nuser@router>\r\n";
        let result = strip_command_output(raw, "show version", &juniper_prompt_re());
        assert_eq!(result, "Junos: 21.4R3\r\n");
    }

    #[test]
    fn iosxr_prompt() {
        let raw = "show version\r\nCisco IOS XR Software\r\nRP/0/RSP0/CPU0:router#\r\n";
        let result = strip_command_output(raw, "show version", &iosxr_prompt_re());
        assert_eq!(result, "Cisco IOS XR Software\r\n");
    }

    #[test]
    fn bare_newline_endings() {
        let raw = "show version\nCisco IOS v15.1\nrouter#\n";
        let result = strip_command_output(raw, "show version", &cisco_prompt_re());
        assert_eq!(result, "Cisco IOS v15.1\n");
    }

    #[test]
    fn ansi_prefixed_echo_is_stripped() {
        // bash readline on Cumulus/SONiC prepends \x1b[?2004l\r before the echo
        let linux_prompt = Regex::new(r"[\w\-\.@]+:[\w~\/\-\.]+[\$#]\s*$").unwrap();
        let raw = "\x1b[?2004l\runame -a\r\nLinux dev21 6.1.0\r\nsherpa@dev21:mgmt:~$\r\n";
        let result = strip_command_output(raw, "uname -a", &linux_prompt);
        assert_eq!(result, "Linux dev21 6.1.0\r\n");
    }

    #[test]
    fn panos_redraw_echo_is_stripped() {
        // PAN-OS CLISH sends character-by-character redraw lines, each ending
        // with an increasing prefix of the command (and the last ending with
        // the full command, possibly preceded by the prompt).
        let raw = "show \r\nsherpa@dev18> show system \r\nsherpa@dev18> show system info\r\nhostname: dev18\r\nsherpa@dev18>\r\n";
        let result = strip_command_output(raw, "show system info", &panos_prompt_re());
        assert_eq!(result, "hostname: dev18\r\n");
    }
}
