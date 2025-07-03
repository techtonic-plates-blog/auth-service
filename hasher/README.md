# Password Hasher CLI

A simple CLI tool to hash passwords using Argon2.

## Usage

Build the binary:

```sh
cargo build --release -p hasher
```

Run the CLI:

```sh
target/release/hasher "your_password_here"
```

The output will be the Argon2 hash of the password.
