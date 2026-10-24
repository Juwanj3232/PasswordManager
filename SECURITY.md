# Security Policy

## Project status

Keeper Vault is a personal project. It uses established primitives (Argon2 key
derivation and authenticated encryption), but it has **not been professionally
audited**. Do not rely on it as your only password manager for high-value
accounts without reviewing the code yourself.

## Your data

- Your vault (`vault.db`) is stored locally and is excluded from version control.
- Never commit your vault, backups or exported files to a public repository.
- The master password is the only thing protecting a stolen vault file. Use a
  long, unique passphrase.

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report privately through GitHub: go to the **Security** tab of this repository
and choose **Report a vulnerability**. Include steps to reproduce and the
affected version or commit.

I'll acknowledge reports as soon as I can and credit reporters who want it.
