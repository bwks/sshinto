pub fn greet() -> &'static str {
    "Hello from lib_sshinto!"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_greet() {
        assert_eq!(greet(), "Hello from lib_sshinto!");
    }
}
