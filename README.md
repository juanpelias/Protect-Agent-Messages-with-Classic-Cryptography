This repository implements a secure secure communication channel in Python, featuring:
1. **Task 1 (`baseline_ctr.py`):** Demonstration of unauthenticated AES-CTR malleability (bit-flipping and replay attacks).
2. **Task 2 (`handshake.py`):** Authenticated FFDHE3072 Diffie–Hellman key exchange with RSA-PSS signatures and length-prefixed transcript hashing.
3. **Task 3 (`secure_record.py`):** Encrypt-then-MAC (AES-256-CTR + HMAC-SHA-256) record layer with bidirectional sequence and direction tracking.
4. **Task 4 (`test_adversarial.py`):** Automated test suite verifying fail-closed behavior against various adversarial attack vectors.

---

## Prerequisites

* **OS:** Linux or macOS (Windows supported via PowerShell)
* **Python:** Python 3.10+ (Tested on Python 3.12)
* **OpenSSL:** 3.0+

---

## Environment Setup

1. **Navigate to the project directory:**
   ```bash
   cd "$HOME/csce465-agentsec"
Create and activate a virtual environment:

Bash
python3 -m venv .venv
source .venv/bin/activate
(On Windows PowerShell, use .venv\Scripts\Activate.ps1)

Upgrade pip and install exact dependencies:

Bash
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
Verify environment installation:

Bash
python3 --version && openssl version && pip show cryptography pytest
Project Directory Structure
Plaintext
.
├── baseline_ctr.py        # Task 1: Unauthenticated AES-CTR bit-flipping & replay demo
├── secure_record.py       # Task 3: Encrypt-then-MAC (seal and open_record functions)
└── test_adversarial.py   # Task 4: Automated security test suite against attacks
Running Executables & Test Suites
Ensure your virtual environment is active ((.venv) prompt prefix) before running commands.

1. Run Baseline AES-CTR Demonstration (Task 1)
Demonstrates how unauthenticated AES-CTR allows an attacker to alter command payloads (READ to EXEC) without knowing the key, and replay ciphertexts.

Bash
python baseline_ctr.py
2. Run Record Layer Unit Tests (Task 3)
Verifies normal bidirectional message sending, sequence progression, and basic frame validation.

Bash
pytest test_secure_record.py -v
3. Run Adversarial Security Suite (Task 4)
Runs automated attacks (ciphertext tampering, header modification, frame replay, direction reflection, RSA signature forgery, and reflected handshake messages) to ensure all fail safely.

Bash
pytest test_adversarial.py -v
To run all test suites simultaneously:

Bash
pytest -v
