# LocalVault — Secure, Local-First Password Manager

LocalVault is a modern, lightweight, **local-first** password manager designed from the ground up for zero-trust security on your local machine. It stores all credentials in an encrypted SQLite database on disk and **never makes network requests, syncs with cloud services, or transmits telemetry**.

---

## 🛡️ Security Architecture & Cryptography

LocalVault adheres to the highest industry standards for authenticated cryptography, key separation, and memory safety:

```
[ Master Password (RAM only) ]
              │
              ▼  Argon2id (t=3, m=64MB, p=4, 32-byte CSPRNG salt)
      [ 256-bit Master Key ]
              │
              ├── HKDF-SHA256 (info: "VAULT_STORAGE_ENCRYPTION_KEY")
              │     └── [ K_enc: 256-bit AES-GCM Key ] ──► Encrypts Credentials
              │
              └── HKDF-SHA256 (info: "VAULT_SESSION_AUTH_KEY")
                    └── [ K_auth: 256-bit Verification Key ] ──► Validates Unlock Token
```

### 1. Key Derivation: Argon2id
- **Algorithm**: Argon2id (RFC 9106), the winner of the Password Hashing Competition.
- **Parameters**: `time_cost = 3`, `memory_cost = 64 MiB (65536 KiB)`, `parallelism = 4`, `hash_len = 32 bytes`.
- **Salt**: 32 bytes (256 bits) of cryptographically secure random bytes generated via `os.urandom`.
- **Resistance**: High memory hardness resists GPU, ASIC, and FPGA offline dictionary attacks.

### 2. Domain Separation: HKDF-SHA256
- The Master Key is never used directly to encrypt data.
- Two distinct subkeys are derived via **HKDF-SHA256** (RFC 5869):
  1. `K_enc`: Dedicated strictly to authenticated credential encryption.
  2. `K_auth`: Dedicated strictly to session verifier token decryption and login validation.

### 3. Authenticated Encryption: AES-256-GCM
- **Algorithm**: AES-256 in Galois/Counter Mode (NIST SP 800-38D).
- **Nonce/IV**: 12 bytes (96 bits) fresh random nonce generated independently for every single record encryption.
- **Tag**: 16 bytes (128 bits) authentication tag.
- **Associated Authenticated Data (AAD)**: Each credential payload binds its own unique UUID as AAD, mathematically preventing record-swapping or database column manipulation attacks.
- **Zero Plaintext Leakage**: Titles, usernames, passwords, URLs, and notes are encrypted together inside the ciphertext. Nothing is visible in plaintext when inspecting the SQLite `.db` file.

### 4. Plaintext Master Password Never Stored
- The plaintext master password is never written to disk, caches, or swap files.
- The vault validates master password correctness by attempting to decrypt an authenticated session token encrypted with `K_auth`. If decryption succeeds and the authentication tag validates, the session is unlocked.

### 5. Secure In-Place Memory Zeroization
- All encryption keys and sensitive buffers are wrapped in `SecureBuffer` structures.
- When the vault is locked (manually or via auto-lock timer) or when the application closes:
  - Low-level memory buffers are overwritten with zeros (`0x00`) using `ctypes.memset`.
  - Python garbage collection is triggered explicitly (`gc.collect()`).

---

## ✨ Features

- **Master Password Setup & Login**:
  - Live entropy and strength meter with complexity feedback.
  - Progressive rate-limiting and delay on failed attempts to deter brute-force guessing.
- **Vault Management**:
  - Add, view, edit, and delete credentials.
  - Categories: `Logins`, `Cards/Financial`, `Secure Notes`, `Work`, `Personal`.
  - Favorite toggle (`⭐`) with quick filtering.
  - Clickable URL launcher (opens in default browser securely).
- **Secure Password & Passphrase Generator**:
  - **Random Password Mode**: Configurable length (8–64), uppercase, lowercase, numbers, symbols, and optional exclusion of ambiguous characters (`0`, `O`, `1`, `l`, `I`).
  - **Memorable Passphrase Mode**: Diceware-style multi-word passphrases with custom separators and capitalization.
  - Real-time Shannon/pool entropy calculations and crack time estimates.
- **Search & Filter**:
  - Real-time search across titles, usernames, domains, notes, and categories.
- **Clipboard Management with Auto-Clear**:
  - One-click copy for usernames and passwords.
  - Timed automatic clipboard clearing (default 30 seconds; configurable).
  - Visual status countdown badge in the toolbar.
- **Inactivity Auto-Lock**:
  - Tracks user mouse and keyboard activity.
  - Automatically locks the vault and wipes keys from RAM after configurable periods (1, 5, 10, 15, 30 minutes, or Never).
- **Local Backup & Export**:
  - **Encrypted Vault Backup**: Uses SQLite's online backup API to take an atomic snapshot of the encrypted database.
  - **Restore Vault**: Replaces and validates restored database files with automatic pre-restore safety backups.
  - **Decrypted JSON Export/Import**: Local data portability with explicit confirmation warnings.
- **CLI Utility**: Full-featured command-line interface (`run_cli.py`) for headless automation and terminal workflows.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+ (tested on Python 3.13 macOS ARM64 / Apple Silicon and Intel)
- macOS, Linux, or Windows

### Step 1: Clone & Setup Virtual Environment
```bash
cd PasswordManager

# Create a virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Run Automated Tests
Verify cryptographic primitives, tamper resistance, and vault integrity:
```bash
python3 run_tests.py
```
Expected output:
```
test_aes_gcm_encryption_roundtrip ... ok
test_argon2id_derivation_deterministic ... ok
test_tamper_detection_ciphertext ... ok
...
Ran 18 tests in 0.89s
OK
```

### Step 3: Launch the Desktop Application
```bash
python3 run.py
```
You can also specify a custom database location:
```bash
python3 run.py --vault ~/Documents/my_private_vault.db
```

---

## 💻 CLI Usage (`run_cli.py`)

For headless environments or quick terminal tasks, use `run_cli.py`:

```bash
# Generate a secure password (24 characters, full symbols)
python3 run_cli.py generate --length 24

# Inspect vault status
python3 run_cli.py status

# Initialize a new vault
python3 run_cli.py init

# List credentials
python3 run_cli.py list

# Add a credential
python3 run_cli.py add --title "GitHub" --username "octocat" --category "Work"

# Create an encrypted backup
python3 run_cli.py backup ~/Documents/vault_backup.db
```

---

## 📦 Building a Standalone macOS App (Daily Use)

To package LocalVault into a standalone macOS `.app` bundle:

```bash
pip install pyinstaller

pyinstaller --noconfirm --onedir --windowed \
  --name "LocalVault" \
  --add-data "src:src" \
  run.py
```
The compiled executable will be located in `dist/LocalVault.app`.

---

## 📁 Project Structure

```
PasswordManager/
├── src/
│   ├── crypto/
│   │   ├── cipher.py        # Argon2id, HKDF-SHA256, AES-256-GCM authenticated cipher
│   │   ├── memory.py        # ctypes.memset in-place memory zeroization & SecureBuffer
│   │   └── generator.py     # Cryptographically secure password/passphrase generator
│   ├── storage/
│   │   ├── database.py      # SQLite connection manager with WAL mode and pragmas
│   │   ├── vault.py         # Authenticated Vault CRUD, AAD domain binding, atomic re-keying
│   │   └── backup.py        # SQLite online backup API, validation, JSON import/export
│   ├── ui/
│   │   ├── app.py           # Application controller, activity tracker, auto-lock loop
│   │   ├── clipboard.py     # Clipboard manager with auto-clear timer & pbcopy integration
│   │   ├── styles.py        # Design tokens, color palette, typography
│   │   └── views/
│   │       ├── login_view.py       # Master password unlock view with brute-force delay
│   │       ├── setup_view.py       # First-time master password setup with strength meter
│   │       ├── vault_view.py       # Main explorer (sidebar, search, cards, detail inspector)
│   │       ├── entry_modal.py      # Add/edit credential popup dialog
│   │       ├── generator_modal.py  # Standalone password generator modal
│   │       └── settings_modal.py   # Security timeouts, backups, and password rotation
│   └── utils/
│       └── helpers.py       # Domain parsing, date formatting
├── tests/
│   ├── test_crypto.py       # Crypto primitives, AAD validation, tamper detection
│   ├── test_generator.py    # Password generator character pools and entropy tests
│   └── test_vault.py        # CRUD tests, disk zero-plaintext check, atomic re-keying
├── run.py                   # Desktop application launcher
├── run_cli.py               # Headless CLI utility
├── run_tests.py             # Automated test suite runner
├── requirements.txt         # Pinned production dependencies
└── README.md                # Documentation and architectural guide
```

---

## 🔒 Security Guarantees & Verification

1. **No External Network Requests**: The application makes 0 external network requests. There are no analytics libraries, external CDN stylesheets, or sync sockets.
2. **Zero Plaintext on Disk**: Inspected via binary search on SQLite database bytes; credential titles, usernames, passwords, URLs, and notes are authenticated and encrypted.
3. **Tamper Evident**: Modifying even 1 bit of database ciphertext or nonces causes AES-GCM tag validation to fail with `TamperedDataError`.
4. **RAM Protection**: Sensitive buffers are zeroed via `ctypes.memset` whenever the vault locks or the app quits.
