use clap::ValueEnum;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "snake_case")]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DeviceKind {
    CiscoIos,
    CiscoIosxr,
    CiscoNxos,
    CiscoAsa,
    CiscoFtd,
    JuniperJunos,
    AristaEos,
    NokiaSrlinux,
    MikrotikRos,
    ArubaAos,
    PaloAltoPanos,
    Linux,
    CumulusLinux,
    SonicLinux,
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
    pub base_path: &'static str,
}

const CISCO_IOS: DeviceProfile = DeviceProfile {
    kind: DeviceKind::CiscoIos,
    name: "Cisco IOS",
    // "router01#", "router01>", "router01(config)#", "router01(config-if)#"
    prompt_pattern: r"[\w\-\.]+(\([\w\-]+\))?[#>]\s*$",
    // "router01#"
    privileged_prompt_pattern: r"[\w\-\.]+#\s*$",
    // "router01(config)#" or "router01(config-if)#"
    config_prompt_pattern: r"[\w\-\.]+\([\w\-]+\)#\s*$",
    paging_disable: "terminal length 0",
    line_separator: "\n",
    exit_config_command: "end",
    enable_command: "enable",
    base_path: "flash:",
};

const CISCO_IOS_XR: DeviceProfile = DeviceProfile {
    kind: DeviceKind::CiscoIosxr,
    name: "Cisco IOS-XR",
    // "RP/0/RSP0/CPU0:router01#", "RP/0/RSP0/CPU0:router01>", "RP/0/RSP0/CPU0:router01(config)#"
    prompt_pattern: r"RP/\d+/[\w/]+:[\w\-\.]+(\([\w\-]+\))?[#>]\s*$",
    // "RP/0/RSP0/CPU0:router01#"
    privileged_prompt_pattern: r"RP/\d+/[\w/]+:[\w\-\.]+#\s*$",
    // "RP/0/RSP0/CPU0:router01(config)#"
    config_prompt_pattern: r"RP/\d+/[\w/]+:[\w\-\.]+\([\w\-]+\)#\s*$",
    paging_disable: "terminal length 0",
    line_separator: "\n",
    exit_config_command: "end",
    enable_command: "",
    base_path: "/disk0:/",
};

const CISCO_NXOS: DeviceProfile = DeviceProfile {
    kind: DeviceKind::CiscoNxos,
    name: "Cisco NX-OS",
    // "nxos-sw01#", "nxos-sw01>", "nxos-sw01(config)#", "nxos-sw01(config-if)#"
    prompt_pattern: r"[\w\-\.]+(\([\w\-]+\))?[#>]\s*$",
    // "nxos-sw01#"
    privileged_prompt_pattern: r"[\w\-\.]+#\s*$",
    // "nxos-sw01(config)#" or "nxos-sw01(config-if)#"
    config_prompt_pattern: r"[\w\-\.]+\([\w\-]+\)#\s*$",
    paging_disable: "terminal length 0",
    line_separator: "\n",
    exit_config_command: "end",
    enable_command: "",
    base_path: "bootflash:",
};

const CISCO_ASA: DeviceProfile = DeviceProfile {
    kind: DeviceKind::CiscoAsa,
    name: "Cisco ASA",
    // "ciscoasa>", "ciscoasa#", "fw01>", "ciscoasa(config)#"
    prompt_pattern: r"[\w\-\.]+(\([\w\-]+\))?[#>]\s*$",
    // "ciscoasa#"
    privileged_prompt_pattern: r"[\w\-\.]+#\s*$",
    // "ciscoasa(config)#" or "ciscoasa(config-if)#"
    config_prompt_pattern: r"[\w\-\.]+\([\w\-]+\)#\s*$",
    paging_disable: "terminal pager 0",
    line_separator: "\n",
    exit_config_command: "end",
    enable_command: "enable",
    base_path: "disk0:",
};

const CISCO_FTD: DeviceProfile = DeviceProfile {
    kind: DeviceKind::CiscoFtd,
    name: "Cisco FTD",
    // "firepower> " — FTD CLISH prompt; hostname part is optional in some versions
    prompt_pattern: r"[\w\-\.]*>\s*$",
    // No separate privileged mode in FTD CLISH
    privileged_prompt_pattern: r"[\w\-\.]*>\s*$",
    // No separate config mode in FTD CLISH
    config_prompt_pattern: r"[\w\-\.]*>\s*$",
    paging_disable: "",
    line_separator: "\n",
    exit_config_command: "",
    enable_command: "",
    base_path: "/ngfw/var/common/",
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
    base_path: "/var/tmp/",
};

const ARISTA_EOS: DeviceProfile = DeviceProfile {
    kind: DeviceKind::AristaEos,
    name: "Arista EOS",
    // "eos-sw01#", "eos-sw01>", "eos-sw01(config)#", "eos-sw01(config-if)#"
    prompt_pattern: r"[\w\-\.]+(\([\w\-]+\))?[#>]\s*$",
    // "eos-sw01#"
    privileged_prompt_pattern: r"[\w\-\.]+#\s*$",
    // "eos-sw01(config)#" or "eos-sw01(config-if)#"
    config_prompt_pattern: r"[\w\-\.]+\([\w\-]+\)#\s*$",
    paging_disable: "terminal length 0",
    line_separator: "\n",
    exit_config_command: "end",
    enable_command: "enable",
    base_path: "/mnt/flash/",
};

const NOKIA_SRLINUX: DeviceProfile = DeviceProfile {
    kind: DeviceKind::NokiaSrlinux,
    name: "Nokia SR Linux",
    // "A:dev04#" or "A:admin@dev04#"
    prompt_pattern: r"[A-D]:[\w\-\.@]+#\s*$",
    // Same — no separate privileged mode
    privileged_prompt_pattern: r"[A-D]:[\w\-\.@]+#\s*$",
    // Same — config mode changes banner, not prompt line
    config_prompt_pattern: r"[A-D]:[\w\-\.@]+#\s*$",
    paging_disable: "environment cli-engine type basic",
    line_separator: "\n",
    exit_config_command: "quit",
    enable_command: "",
    base_path: "/tmp/",
};

const MIKROTIK_ROS: DeviceProfile = DeviceProfile {
    kind: DeviceKind::MikrotikRos,
    name: "MikroTik RouterOS",
    // "[admin@MikroTik] >" or "[admin@R1] /ip/route>"
    prompt_pattern: r"\].*>\s*$",
    // Same — no separate privileged mode
    privileged_prompt_pattern: r"\].*>\s*$",
    // Same — no separate config mode
    config_prompt_pattern: r"\].*>\s*$",
    paging_disable: "",
    line_separator: "\n",
    exit_config_command: "/",
    enable_command: "",
    base_path: "/",
};

const ARUBA_AOS: DeviceProfile = DeviceProfile {
    kind: DeviceKind::ArubaAos,
    name: "Aruba AOS-CX",
    // "dev07#", "dev07>", "dev07(config)#", "dev07(config-if)#"
    prompt_pattern: r"[\w\-\.]+(\([\w\-]+\))?[#>]\s*$",
    // "dev07#"
    privileged_prompt_pattern: r"[\w\-\.]+#\s*$",
    // "dev07(config)#"
    config_prompt_pattern: r"[\w\-\.]+\([\w\-]+\)#\s*$",
    paging_disable: "no page",
    line_separator: "\n",
    exit_config_command: "end",
    enable_command: "enable",
    base_path: "/",
};

const PALO_ALTO_PANOS: DeviceProfile = DeviceProfile {
    kind: DeviceKind::PaloAltoPanos,
    name: "Palo Alto PAN-OS",
    // "admin@PA-VM>" (operational) or "admin@PA-VM#" (configure)
    prompt_pattern: r"[\w\-\.@]+[#>]\s*$",
    // Operational mode — already privileged, no enable needed
    privileged_prompt_pattern: r"[\w\-\.@]+>\s*$",
    // "admin@PA-VM#" — configure mode
    config_prompt_pattern: r"[\w\-\.@]+#\s*$",
    paging_disable: "set cli pager off",
    line_separator: "\n",
    exit_config_command: "exit",
    enable_command: "",
    // PAN-OS SCP upload uses /scp/config/ path; requires an account with SCP
    // access (e.g. a dedicated scp_admin user or an account with scp privilege).
    base_path: "/scp/config/",
};

const LINUX: DeviceProfile = DeviceProfile {
    kind: DeviceKind::Linux,
    name: "Linux",
    // "user@host:~$" or "host:~$" or "user@host:~#"
    prompt_pattern: r"[\w\-\.@]+:[\w~\/\-\.]+[\$#]\s*$",
    // root prompt "host:~#"
    privileged_prompt_pattern: r"[\w\-\.@]+:[\w~\/\-\.]+#\s*$",
    // No config mode
    config_prompt_pattern: r"[\w\-\.@]+:[\w~\/\-\.]+#\s*$",
    paging_disable: "",
    line_separator: "\n",
    exit_config_command: "",
    enable_command: "",
    base_path: "/tmp/",
};

const CUMULUS_LINUX: DeviceProfile = DeviceProfile {
    kind: DeviceKind::CumulusLinux,
    name: "Cumulus Linux",
    // "user@switch:~$" or "user@switch:mgmt:~$" (with VRF in prompt)
    // The VRF segment ":mgmt" is optional; the pattern matches via the last
    // ":path$" segment regardless of how many colon-separated parts precede it.
    prompt_pattern: r"[\w\-\.@]+:[\w~\/\-\.]+[\$#]\s*$",
    privileged_prompt_pattern: r"[\w\-\.@]+:[\w~\/\-\.]+#\s*$",
    config_prompt_pattern: r"[\w\-\.@]+:[\w~\/\-\.]+#\s*$",
    paging_disable: "",
    line_separator: "\n",
    exit_config_command: "",
    enable_command: "",
    base_path: "/tmp/",
};

const SONIC_LINUX: DeviceProfile = DeviceProfile {
    kind: DeviceKind::SonicLinux,
    name: "SONiC Linux",
    // "user@switch:~$" or "user@switch:~#"
    prompt_pattern: r"[\w\-\.@]+:[\w~\/\-\.]+[\$#]\s*$",
    privileged_prompt_pattern: r"[\w\-\.@]+:[\w~\/\-\.]+#\s*$",
    config_prompt_pattern: r"[\w\-\.@]+:[\w~\/\-\.]+#\s*$",
    paging_disable: "",
    line_separator: "\n",
    exit_config_command: "",
    enable_command: "",
    base_path: "/tmp/",
};

impl DeviceKind {
    /// Return the static [`DeviceProfile`] associated with this device kind.
    pub fn profile(&self) -> &'static DeviceProfile {
        match self {
            DeviceKind::CiscoIos => &CISCO_IOS,
            DeviceKind::CiscoIosxr => &CISCO_IOS_XR,
            DeviceKind::CiscoNxos => &CISCO_NXOS,
            DeviceKind::CiscoAsa => &CISCO_ASA,
            DeviceKind::CiscoFtd => &CISCO_FTD,
            DeviceKind::JuniperJunos => &JUNIPER_JUNOS,
            DeviceKind::AristaEos => &ARISTA_EOS,
            DeviceKind::NokiaSrlinux => &NOKIA_SRLINUX,
            DeviceKind::MikrotikRos => &MIKROTIK_ROS,
            DeviceKind::ArubaAos => &ARUBA_AOS,
            DeviceKind::PaloAltoPanos => &PALO_ALTO_PANOS,
            DeviceKind::Linux => &LINUX,
            DeviceKind::CumulusLinux => &CUMULUS_LINUX,
            DeviceKind::SonicLinux => &SONIC_LINUX,
        }
    }
}

impl DeviceProfile {
    /// Compile `prompt_pattern` into a [`Regex`].
    ///
    /// Panics if the built-in pattern is not valid regex (indicates a programming error).
    pub fn prompt_regex(&self) -> Regex {
        Regex::new(self.prompt_pattern).expect("built-in prompt pattern must be valid regex")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_KINDS: [DeviceKind; 14] = [
        DeviceKind::CiscoIos,
        DeviceKind::CiscoIosxr,
        DeviceKind::CiscoNxos,
        DeviceKind::CiscoAsa,
        DeviceKind::CiscoFtd,
        DeviceKind::JuniperJunos,
        DeviceKind::AristaEos,
        DeviceKind::NokiaSrlinux,
        DeviceKind::MikrotikRos,
        DeviceKind::ArubaAos,
        DeviceKind::PaloAltoPanos,
        DeviceKind::Linux,
        DeviceKind::CumulusLinux,
        DeviceKind::SonicLinux,
    ];

    #[test]
    fn profile_returns_correct_name_and_paging() {
        let cases = [
            (DeviceKind::CiscoIos, "Cisco IOS", "terminal length 0"),
            (DeviceKind::CiscoIosxr, "Cisco IOS-XR", "terminal length 0"),
            (DeviceKind::CiscoNxos, "Cisco NX-OS", "terminal length 0"),
            (DeviceKind::CiscoAsa, "Cisco ASA", "terminal pager 0"),
            (DeviceKind::CiscoFtd, "Cisco FTD", ""),
            (
                DeviceKind::JuniperJunos,
                "Juniper JUNOS",
                "set cli screen-length 0",
            ),
            (DeviceKind::AristaEos, "Arista EOS", "terminal length 0"),
            (
                DeviceKind::NokiaSrlinux,
                "Nokia SR Linux",
                "environment cli-engine type basic",
            ),
            (
                DeviceKind::MikrotikRos,
                "MikroTik RouterOS",
                "",
            ),
            (DeviceKind::ArubaAos, "Aruba AOS-CX", "no page"),
            (DeviceKind::PaloAltoPanos, "Palo Alto PAN-OS", "set cli pager off"),
            (DeviceKind::Linux, "Linux", ""),
            (DeviceKind::CumulusLinux, "Cumulus Linux", ""),
            (DeviceKind::SonicLinux, "SONiC Linux", ""),
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
        assert!(re.is_match("router01(config)#"));
        assert!(re.is_match("sw-core01(config-if)#"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("not a prompt"));
    }

    #[test]
    fn cisco_iosxr_prompt_matches() {
        let p = DeviceKind::CiscoIosxr.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("RP/0/RSP0/CPU0:router01#"));
        assert!(re.is_match("RP/0/RSP0/CPU0:router01>"));
        assert!(re.is_match("RP/0/RSP0/CPU0:router01(config)#"));
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
        // prompt_regex must also match config prompts so sessions don't hang
        let prompt_re = p.prompt_regex();
        assert!(prompt_re.is_match("router01(config)#"));
        assert!(prompt_re.is_match("sw-01(config-if)#"));
    }

    #[test]
    fn nokia_srlinux_prompt_matches() {
        let p = DeviceKind::NokiaSrlinux.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("A:dev04#"));
        assert!(re.is_match("A:admin@dev04#"));
        assert!(re.is_match("B:srl-router.lab#"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("dev04#"));
        assert!(!re.is_match("not a prompt"));
    }

    #[test]
    fn mikrotik_routeros_prompt_matches() {
        let p = DeviceKind::MikrotikRos.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("[admin@MikroTik] >"));
        assert!(re.is_match("[admin@MikroTik] > "));
        assert!(re.is_match("[admin@R1] /ip/route>"));
        assert!(re.is_match("[admin@router.lab] /ip/address>"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("not a prompt"));
    }

    #[test]
    fn aruba_aoscx_prompt_matches() {
        let p = DeviceKind::ArubaAos.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("dev07#"));
        assert!(re.is_match("switch01>"));
        assert!(re.is_match("core-sw.lab#"));
        assert!(re.is_match("dev07(config)#"));
        assert!(re.is_match("dev07(config-if)#"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("not a prompt"));
    }

    #[test]
    fn linux_prompt_matches() {
        let p = DeviceKind::Linux.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("sherpa@dev08:~$"));
        assert!(re.is_match("dev06:~$"));
        assert!(re.is_match("root@host:/tmp#"));
        assert!(re.is_match("user@server:/var/log$"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("not a prompt"));
    }

    #[test]
    fn cumulus_linux_prompt_matches() {
        let p = DeviceKind::CumulusLinux.profile();
        let re = p.prompt_regex();
        // Standard prompt without VRF
        assert!(re.is_match("sherpa@dev21:~$"));
        // Prompt with management VRF (":mgmt" segment inserted by Cumulus PS1)
        assert!(re.is_match("sherpa@dev21:mgmt:~$"));
        assert!(re.is_match("root@leaf01:mgmt:~#"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("not a prompt"));
    }

    #[test]
    fn sonic_linux_prompt_matches() {
        let p = DeviceKind::SonicLinux.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("sherpa@dev22:~$"));
        assert!(re.is_match("admin@sonic-switch:~$"));
        assert!(re.is_match("root@sonic:/tmp#"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("not a prompt"));
    }

    #[test]
    fn cisco_asa_prompt_matches() {
        let p = DeviceKind::CiscoAsa.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("ciscoasa>"));
        assert!(re.is_match("ciscoasa#"));
        assert!(re.is_match("fw01>"));
        assert!(re.is_match("fw-edge.lab#"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("not a prompt"));
    }

    #[test]
    fn cisco_asa_config_prompt_matches() {
        let p = DeviceKind::CiscoAsa.profile();
        let re = Regex::new(p.config_prompt_pattern).unwrap();
        assert!(re.is_match("ciscoasa(config)#"));
        assert!(re.is_match("ciscoasa(config-if)#"));
        assert!(!re.is_match("ciscoasa#"));
    }

    #[test]
    fn cisco_ftd_prompt_matches() {
        let p = DeviceKind::CiscoFtd.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("firepower>"));
        assert!(re.is_match(">"));
        assert!(re.is_match("> "));
        assert!(!re.is_match(""));
        assert!(!re.is_match("not a prompt"));
    }

    #[test]
    fn palo_alto_panos_prompt_matches() {
        let p = DeviceKind::PaloAltoPanos.profile();
        let re = p.prompt_regex();
        assert!(re.is_match("admin@PA-VM>"));
        assert!(re.is_match("admin@fw-lab>"));
        assert!(re.is_match("admin@PA-VM#"));
        assert!(!re.is_match(""));
        assert!(!re.is_match("not a prompt"));
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
