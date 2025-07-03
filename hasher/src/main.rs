use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use clap::Parser;

/// Simple CLI to hash a password using Argon2
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Password to hash
    password: String,
}

fn main() {
    let args = Args::parse();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(args.password.as_bytes(), &salt)
        .expect("Password hashing failed");
    println!("{}", password_hash.to_string());
}
