---
trigger: automatic
description: Enforce panic-free Rust code generation
---

When generating Rust code:

❌ Forbidden:
- .unwrap()
- .expect()
- panic!()
- .unwrap_err()
- .expect_err()

✅ Required instead:
- Use proper error handling with Result and Option
- Use the ? operator to propagate errors
- Return meaningful error types
- Use match, if let, ok_or, or ok_or_else
- Prefer custom error enums (e.g., with thiserror) when appropriate

Rules:
- Code must never intentionally crash at runtime
- All fallible operations must be handled safely and explicitly
- Avoid hidden panics (e.g., unchecked indexing like vec[i])

Enforcement Hint (optional for projects):
Add to crate root:

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

Tests may only use unwrap/expect if explicitly allowed by project policy.