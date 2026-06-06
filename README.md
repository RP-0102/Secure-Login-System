# 🔐 Secure Login System

A Python-based web application that manages user registration, secure authentication, and active session states. It mitigates critical web vulnerabilities like SQL Injection, session hijacking, and plain-text credential leaks using industry-standard cryptography and framework protections.

---

## 🚀 Features

* **Bcrypt Password Hashing:** Automatically hashes and salts passwords using the blowfish cipher before database storage.
* **SQL Injection Immunity:** Utilizes Object-Relational Mapping (ORM) parameterized statements to thoroughly separate user input execution from structural query patterns.
* **Signed Session Management:** Implements server-backed session state verification signed with highly randomized encryption keys.
* **Structural Data Validation:** Enforces baseline criteria checks (e.g., minimum string length limits) to drop malformed input vectors.

---

## ⚙️ Technical Blueprint & Engine Lifecycle

1. **Ingestion:** Receives web client text variables over encrypted channels.
2. **Transform:** Hashes registration vectors using `bcrypt.hashpw()` with dynamically embedded algorithmic salt matrices.
3. **Isolate:** Queries storage using isolated entity parameter abstraction layers to eliminate string concatenation SQL vulnerabilities.
4. **Persist:** Emits signed browser identity cookies to track session states across route endpoints.

---

## ⚡ Quick Start

### Installation
Ensure you install dependencies inside your environment before app launch:
```bash
pip install Flask Flask-SQLAlchemy bcrypt# Secure-Login-System

https://github.com/RP-0102/Secure-Login-System
