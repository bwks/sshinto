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
You can SSH to a device on `172.31.0.11` with the username `sherpa` and the password `Everest1953!`. Use this device to test the implementation.
