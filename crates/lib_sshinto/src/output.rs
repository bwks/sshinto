use regex::Regex;

/// Strip the echoed command (first line) and trailing prompt (last line)
/// from raw SSH output, returning only the command's actual response.
pub fn strip_command_output(raw: &str, command: &str, prompt_re: &Regex) -> String {
    let mut text = raw;

    // Strip echo: if the first line matches the command, discard it.
    if let Some(idx) = text.find('\n') {
        let first_line = text[..idx].trim_end_matches('\r').trim();
        if first_line == command.trim() {
            text = &text[idx + 1..];
        }
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
}
