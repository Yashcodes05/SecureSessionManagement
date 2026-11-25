# 🛡️ Secure Session Management System with Cryptographic Tokens

[![Build & Tests](https://github.com/Yashcodes05/SecureSessionManagement/actions/workflows/ci.yml/badge.svg)](https://github.com/Yashcodes05/SecureSessionManagement/actions/workflows/ci.yml)
[![C++ Standard](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Tests Passing](https://img.shields.io/badge/Security_Tests-30%2F30_Passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-Academic-lightgrey.svg)]()

### 🎓 Academic Project Information
* **Course:** 24CYE551 — Secure Coding Using C/C++
* **Institution:** Department of Cyber Security
* **Guide:** Prof. Shankaramma
* **Authors:**
  * **Yash Raj Sinha** (USN: `1MS24CY071`)
  * **Shreyanshu Raj** (USN: `1MS24CY073`)

---

## 🌐  Live Interactive Demonstration

* **Live Web Dashboard (GitHub Pages):** [https://yashcodes05.github.io/SecureSessionManagement/](https://yashcodes05.github.io/SecureSessionManagement/)
* **Offline Local Web Demo:** Double-click `open_web_demo.bat` or open `docs/index.html` in any modern browser.

---

## 🚀 Ways to Run the Project for Evaluation

### 1. Interactive Web Dashboard (Visual Demo)
Double click `open_web_demo.bat` to test:
- User registration & NIST SP 800-63B password validation
- 256-bit CSPRNG token generation and active session tracking
- Real-time idle inactivity (5 min) & absolute lifetime (30 min) countdowns
- Cyber attack simulations (Token Replay, Brute-Force lockout, Session Fixation, Privilege Escalation)
- Live Security Audit Log (tokens masked, timing-attack resistant)

### 2. C++ Console Application (Interactive Terminal)
Double-click `run_app.bat` or run:
```cmd
.\run_app.bat
```

### 3. Automated 30 Security Test Suite
Double-click `run_tests.bat` or run:
```cmd
.\run_tests.bat
```

---

## 🧪 Automated Security Test Suite (30 Test Cases)

| Category | Test IDs | Security Concepts Verified | Status |
|---|---|---|---|
| **A. Registration & Password** | TC01 – TC06 | Salted SHA-256 hashing, complexity rules, buffer defenses, duplicate prevention | **PASS (6/6)** |
| **B. Authentication Security** | TC07 – TC12 | Timing-safe comparisons, 5-strike account lockout, disabled user rejection | **PASS (6/6)** |
| **C. Token Cryptography** | TC13 – TC22 | 256-bit entropy, token tampering checks, replay after logout rejection, log masking | **PASS (10/10)** |
| **D. Session Management** | TC23 – TC27 | Fixation defense, concurrent session caps, idle timeout (5m), absolute expiry (30m) | **PASS (5/5)** |
| **E. Authorization & RBAC** | TC28 – TC30 | Role-based resource protection, cross-user substitution blocks, account deactivation | **PASS (3/3)** |
| **Total** | **30 Cases** | **Comprehensive OWASP Session Security Coverage** | **100% PASS** |

---

## 🛠️ Security Engineering Highlights
* **CSPRNG Entropy:** Uses Windows Cryptography Next Generation (`BCryptGenRandom`) for cryptographically strong random tokens.
* **Constant-Time Verification:** Employs constant-time byte comparisons (`CryptoUtils::constantTimeCompare`) to defeat side-channel timing attacks.
* **Data Sanitization & Masking:** Sensitive data (passwords, plaintext tokens) are zeroized in memory and masked in logs (`abcd1234...`).
* **Exploit Mitigations:** Compiled with `/W4`, `/sdl`, `/GS` (stack protection), and `/guard:cf` (Control Flow Guard).
