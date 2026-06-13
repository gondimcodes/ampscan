//! Authentication and Password Management Module.
//!
//! This module provides utilities to securely hash and verify passwords
//! using Argon2id, and handles secure interactive password prompts.
use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// Hash a password using Argon2id with a random salt.
/// Returns the PHC-formatted hash string (includes algorithm, salt, and hash).
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default(); // Argon2id with recommended params
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash string.
pub fn verify_password(password: &str, hash_str: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash_str)
        .map_err(|e| anyhow::anyhow!("Invalid password hash format: {}", e))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Prompt the user for a password with confirmation (for new passwords).
/// Returns the password string.
pub fn prompt_new_password() -> Result<String> {
    loop {
        let password = rpassword::prompt_password("Password: ")
            .context("Failed to read password")?;
        if password.len() < 8 {
            eprintln!("Password must be at least 8 characters. Try again.");
            continue;
        }
        let confirm = rpassword::prompt_password("Confirm password: ")
            .context("Failed to read password confirmation")?;
        if password != confirm {
            eprintln!("Passwords do not match. Try again.");
            continue;
        }
        return Ok(password);
    }
}

/// Prompt the user for a password (for login).
pub fn prompt_password() -> Result<String> {
    rpassword::prompt_password("Password: ").context("Failed to read password")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }
}
