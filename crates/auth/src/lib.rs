use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
pub fn hash_password(password: &str) -> Result<String> {
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("Password hashing: {e}"))
}
pub fn verify(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).ok().is_some_and(|h| {
        Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}
pub fn token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}
pub fn digest(secret: &str, token: &str) -> String {
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    h.update([0]);
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passwords() {
        let h = hash_password("long random password").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify("long random password", &h));
        assert!(!verify("wrong", &h));
    }
    #[test]
    fn tokens() {
        assert_ne!(token(), token());
        assert_ne!(digest("a", "b"), digest("b", "a"));
    }
}
