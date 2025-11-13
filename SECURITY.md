# Security Policy

Thank you for taking the time to report a potential vulnerability.

If you believe you have found a security issue in `oqs-safe`, please contact:

 **orlychikka@gmail.com**

Please **do not open a public GitHub issue** for security reports.

---

## Supported Versions

`oqs-safe` provides security support for:

- The **latest published crate release**, and  
- The **`main` branch**.

Older releases may not receive patches except for critical issues.

---

## Reporting Expectations

When reporting a vulnerability, please include:

- A description of the issue  
- Minimal reproduction steps (if possible)  
- Affected feature flags (`liboqs`, `mock`, algorithms, etc.)  
- Environment details (OS, Rust version, liboqs version)

You will receive an acknowledgement within **7 days**, and coordinated disclosure will be followed if required.

---

## Security Design Notes

`oqs-safe` includes several safeguards to minimize misuse:

- **Compile-time backend enforcement**  
  - Prevents use of the mock backend in release builds unless explicitly allowed.  
  - Ensures either `liboqs` or `mock` is intentionally selected.

- **Strict Rust safety lints**  
  - `#![deny(unsafe_op_in_unsafe_fn)]` is enforced to ensure all unsafe usage remains auditable and intentional.

- **Zeroization of secret material**  
  - Uses `zeroize` to securely wipe private keys and shared secrets.

- **Minimal API surface**  
  - Only exposes high-level KEM and signature operations.  
  - Avoids unnecessary footguns.

---

## Coordinated Disclosure

If a vulnerability is confirmed, we will:

1. Prepare a fix privately.  
2. Notify the reporter with the patch or mitigation.  
3. Publish a new crate release.  
4. Add a post-disclosure note to the changelog if appropriate.

Thank you for helping improve the security of this project.
