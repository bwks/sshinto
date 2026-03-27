# Lab Devices

This file maps each sshinto device type to the current lab host used for
testing. Update this file when lab nodes change — do not hardcode host
details anywhere else in the test specs.

**Auth:** username `sherpa`, key `sherpa_ssh_key` (password `Everest1953!`)

| Device type | Lab host | IP |
|-------------|----------|----|
| `cisco_ios` | dev06 (cisco_cat8000v) | 172.31.1.15 |
| `cisco_iosxr` | dev08 (cisco_iosxrv9000) | 172.31.1.16 |
| `cisco_nxos` | dev09 (cisco_nexus9300v) | 172.31.1.17 |
| `cisco_asa` | dev04 (cisco_asav) | 172.31.1.14 |
| `cisco_ftd` | dev12 (cisco_ftdv) | 172.31.1.18 — **username: `admin`**, password auth (keyboard-interactive), key auth not supported |
| `juniper_junos` | dev13 (juniper_vrouter) | 172.31.1.19 |
| `arista_eos` | dev01 (arista_veos) | 172.31.1.12 |
| `nokia_srlinux` | dev17 (nokia_srlinux) | 172.31.1.20 |
| `palo_alto_panos` | dev18 (paloalto_panos) | 172.31.1.21 |
| `mikrotik_ros` | dev19 (mikrotik_chr) | 172.31.1.22 |
| `aruba_aos` | dev03 (aruba_aoscx) | 172.31.1.13 |
| `linux` | dev20 (frr_linux) | 172.31.1.23 |
| `cumulus_linux` | dev21 (cumulus_linux) | 172.31.1.24 |
| `sonic_linux` | dev22 (sonic_linux) | 172.31.1.25 |
