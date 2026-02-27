## About
This project is used to connect to network devices,
initally over SSH and apply config or return data.

The goal is to abstract the nuances of handling this process across
multiple network vendors and linux/bsd hosts.

## Project Structure
- `lib_sshinto` - Library functionality for project.
- `sshinto` - CLI utility crate. 
- `models` - Shared data models.

## Guidelines
- Never use `.unwrap()` except in tests.

## Testing
You can SSH to the below devices with the username `sherpa` and the password `Everest1953!`.
You can also use the username `sherpa` and ssh key `sherpa_ssh_key`
Use these device to test the implementation.

### Test Devices
- dev01 | Cisco IOS | 172.31.0.11
- dev02 | Cisco IOS-XE | 172.31.0.12
- dev03 | Arista EOS | 172.31.0.13
- dev04 | Arista EOS | 172.31.0.14