use clap::ValueEnum;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "snake_case")]
pub enum DeviceKind {
    CiscoIos,
    CiscoIosXr,
    CiscoNxos,
    JuniperJunos,
    AristaEos,
}

#[derive(Debug, Clone)]
pub struct DeviceProfile {
    pub kind: DeviceKind,
    pub name: &'static str,
    pub prompt_pattern: &'static str,
    pub privileged_prompt_pattern: &'static str,
    pub config_prompt_pattern: &'static str,
    pub paging_disable: &'static str,
    pub line_separator: &'static str,
    pub exit_config_command: &'static str,
    pub enable_command: &'static str,
}

const CISCO_IOS: DeviceProfile = DeviceProfile {
    kind: DeviceKind::CiscoIos,
    name: "Cisco IOS",
    // "router01#" or "router01>"
    prompt_pattern: r"[\w\-\.]+[#>]\s*$",
    // "router01#"
    privileged_prompt_pattern: r"[\w\-\.]+#\s*$",
    // "router01(config)#" or "router01(config-if)#"
    config_prompt_pattern: r"[\w\-\.]+\([\w\-]+\)#\s*$",
    paging_disable: "terminal length 0",
    line_separator: "\n",
    exit_config_command: "end",
    enable_command: "enable",
};

const CISCO_IOS_XR: DeviceProfile = DeviceProfile {
    kind: DeviceKind::CiscoIosXr,
    name: "Cisco IOS-XR",
    // "RP/0/RSP0/CPU0:router01#" or "RP/0/RSP0/CPU0:router01>"
    prompt_pattern: r"RP/\d+/[\w/]+:[\w\-\.]+[#>]\s*$",
    // "RP/0/RSP0/CPU0:router01#"
    privileged_prompt_pattern: r"RP/\d+/[\w/]+:[\w\-\.]+#\s*$",
    // "RP/0/RSP0/CPU0:router01(config)#"
    config_prompt_pattern: r"RP/\d+/[\w/]+:[\w\-\.]+\([\w\-]+\)#\s*$",
    paging_disable: "terminal length 0",
    line_separator: "\n",
    exit_config_command: "end",
    enable_command: "",
};

const CISCO_NXOS: DeviceProfile = DeviceProfile {
    kind: DeviceKind::CiscoNxos,
    name: "Cisco NX-OS",
    // "nxos-sw01#" or "nxos-sw01>"
    prompt_pattern: r"[\w\-\.]+[#>]\s*$",
    // "nxos-sw01#"
    privileged_prompt_pattern: r"[\w\-\.]+#\s*$",
    // "nxos-sw01(config)#" or "nxos-sw01(config-if)#"
    config_prompt_pattern: r"[\w\-\.]+\([\w\-]+\)#\s*$",
    paging_disable: "terminal length 0",
    line_separator: "\n",
    exit_config_command: "end",
    enable_command: "",
};

const JUNIPER_JUNOS: DeviceProfile = DeviceProfile {
    kind: DeviceKind::JuniperJunos,
    name: "Juniper JUNOS",
    // "user@router01>" or "user@router01#" or "root@fw%"
    prompt_pattern: r"[\w\-\.@]+[>#%]\s*$",
    // "user@router01>"
    privileged_prompt_pattern: r"[\w\-\.@]+>\s*$",
    // "user@router01#"
    config_prompt_pattern: r"[\w\-\.@]+#\s*$",
    paging_disable: "set cli screen-length 0",
    line_separator: "\n",
    exit_config_command: "exit configuration-mode",
    enable_command: "",
};

const ARISTA_EOS: DeviceProfile = DeviceProfile {
    kind: DeviceKind::AristaEos,
    name: "Arista EOS",
    // "eos-sw01#" or "eos-sw01>"
    prompt_pattern: r"[\w\-\.]+[#>]\s*$",
    // "eos-sw01#"
    privileged_prompt_pattern: r"[\w\-\.]+#\s*$",
    // "eos-sw01(config)#" or "eos-sw01(config-if)#"
    config_prompt_pattern: r"[\w\-\.]+\([\w\-]+\)#\s*$",
    paging_disable: "terminal length 0",
    line_separator: "\n",
    exit_config_command: "end",
    enable_command: "enable",
};

impl DeviceKind {
    pub fn profile(&self) -> &'static DeviceProfile {
        match self {
            DeviceKind::CiscoIos => &CISCO_IOS,
            DeviceKind::CiscoIosXr => &CISCO_IOS_XR,
            DeviceKind::CiscoNxos => &CISCO_NXOS,
            DeviceKind::JuniperJunos => &JUNIPER_JUNOS,
            DeviceKind::AristaEos => &ARISTA_EOS,
        }
    }
}

impl DeviceProfile {
    pub fn prompt_regex(&self) -> Regex {
        Regex::new(self.prompt_pattern).expect("built-in prompt pattern must be valid regex")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_KINDS: [DeviceKind; 5] = [
        DeviceKind::CiscoIos,
        DeviceKind::CiscoIosXr,
        DeviceKind::CiscoNxos,
        DeviceKind::JuniperJunos,
        DeviceKind::AristaEos,
    ];

    #[test]
    fn profile_returns_correct_name_and_paging() {
        let cases = [
            (DeviceKind::CiscoIos, "Cisco IOS", "terminal length 0"),
            (DeviceKind::CiscoIosXr, "Cisco IOS-XR", "terminal length 0"),
            (DeviceKind::CiscoNxos, "Cisco NX-OS", "terminal length 0"),
            (DeviceKind::JuniperJunos, "Juniper JUNOS", "set cli screen-length 0"),
            (DeviceKind::AristaEos, "Arista EOS", "terminal length 0"),
        ];
        for (kind, expected_name, expected_paging) in cases {
            let p = kind.profile();
            assert_eq!(p.name, expected_name);
            assert_eq!(p.paging_disable, expected_paging);
        }
    }

    #[test]
    fn all_prompt_patterns_compile() {
        for kind in ALL_KINDS {
            let p = kind.profile();
            Regex::new(p.prompt_pattern).unwrap();
            Regex::new(p.privileged_prompt_pattern).unwrap();
            Regex::new(p.config_prompt_pattern).unwrap();
        }
    }

    #[test]
    fn cisco_ios_prompt_matches() {
        let p = DeviceKind::CiscoIos.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("dev01#"));
        assert!(re.is_match("router.lab>"));
        assert!(re.is_match("sw-core01#"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("not a prompt"));
    }

    #[test]
    fn cisco_iosxr_prompt_matches() {
        let p = DeviceKind::CiscoIosXr.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("RP/0/RSP0/CPU0:router01#"));
        assert!(re.is_match("RP/0/RSP0/CPU0:router01>"));
        assert!(!re.is_match("dev01#"));
    }

    #[test]
    fn juniper_prompt_matches() {
        let p = DeviceKind::JuniperJunos.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("user@router01>"));
        assert!(re.is_match("admin@sw-01#"));
        assert!(re.is_match("root@fw%"));
        assert!(!re.is_match(""));
    }

    #[test]
    fn config_prompt_matches() {
        let p = DeviceKind::CiscoIos.profile();
        let re = Regex::new(p.config_prompt_pattern).unwrap();
        assert!(re.is_match("router01(config)#"));
        assert!(re.is_match("sw-01(config-if)#"));
        assert!(!re.is_match("router01#"));
    }

    #[test]
    fn prompt_rejects_non_prompts() {
        for kind in ALL_KINDS {
            let re = kind.profile().prompt_regex();
            assert!(!re.is_match(""));
            assert!(!re.is_match("just some text"));
            assert!(!re.is_match("show ip route"));
        }
    }
}
