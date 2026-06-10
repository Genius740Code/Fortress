# Contributing to Fortress

Thanks for contributing — it's appreciated. 

---

## 1. Fork the Repository

Fork the repo on GitHub, then:

```bash
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress
git checkout -b your-branch-name
```

---

## 2. Make Your Changes

Keep changes focused and the code clean. Run `cargo fmt` and `cargo clippy -- -D warnings` before committing.

---

## 3. Ensure Tests Pass

```bash
cargo test --all
```

If you're adding something new, add tests for it too.

---

## 4. Write a Good Commit Message

We use [Conventional Commits](https://www.conventionalcommits.org/). This keeps the history clean and makes it easy to understand what changed and why.

Format:
```
type(scope): short description

Optional longer explanation if needed.
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Examples:
```
feat(crypto): add ChaCha20-Poly1305 key derivation option
fix(auth): handle expired JWT tokens correctly
docs(api): clarify rate limiting behaviour in REST reference
```

Keep the subject line under 72 characters and write it in the imperative ("add", not "added" or "adds").

---

## 5. Open a Pull Request

Push your branch and open a PR against `master`:

```bash
git push origin your-branch-name
```

In your PR description, include:

- **What** the change does
- **Why** it's needed (link to an issue if one exists)
- **How** you tested it
- Any **breaking changes** or migration notes

A maintainer will review your PR. Be ready for feedback — we try to be constructive and specific. If you disagree with a suggestion, say so; good conversations make better code.

---

## Rules

### Code Quality

- Follow Rust best practices and standard naming conventions
- Keep code clean and readable — functions should do one thing
- Don't dump files into a single folder; keep the project structure logical and organised
- Document public APIs with doc comments
- No commented-out dead code

### AI Usage

You may use AI tools to help write code. Just read through everything before opening a PR and check for any bugs, vulnerabilities, or issues it may have introduced.