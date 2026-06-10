# Fortress Project TODO List

## Documentation & Community
- [ ] Rewrite `CONTRIBUTING.md`
- [ ] Rewrite `README.md`
- [ ] Make docs easier and simpler to read, organize, and understand
- [ ] Add more comprehensive code examples (especially for plugins)

## Language SDKs & Libraries (Published)
- [ ] **Python Library (`fortress-python`)**
  - [ ] Thoroughly test all published features
  - [ ] Ensure API parity with the core rust implementation
- [ ] **JS/TS Library (`fortress-js`)**
  - [ ] Thoroughly test all published features (WASM/NAPI)
  - [ ] Validate TypeScript definitions across edge cases
- [ ] **Go Library (`fortress-go`)**
  - [ ] Thoroughly test all published features
  - [ ] Validate cross-platform compilation of the client

## Deployment & Infrastructure
- [ ] **Docker**
  - [ ] Thoroughly test the published Docker image across all features
  - [ ] Validate multi-container deployments (docker-compose)
  - [ ] Verify image footprint and security vulnerabilities inside the container

## CI/CD & Automation
- [ ] **GitHub Actions Workflows**
  - [ ] Set up automated testing (`cargo test`) and linting (`cargo clippy`) on Pull Requests
  - [ ] Automate the build and push of Docker images to GitHub Container Registry (GHCR) / Docker Hub on release
  - [ ] Setup `cargo audit` to automatically check for dependency vulnerabilities on a schedule
  - [ ] Automate SDK publishing workflows (PyPI, npm)

## Codebase Refactoring & Quality
- [ ] Refactor large files in `fortress-core/src` by splitting them into smaller submodules (e.g. `hsm.rs`, `auth.rs`, `encryption.rs`)
- [ ] Increase testing coverage (add more Unit, Integration, and E2E tests)
- [ ] Address C++ build tools requirement on Windows (either document thoroughly or switch cryptography backends)

## Future / Long-Term Goals (Backlog)
- [ ] Build a Plugin Marketplace (e.g., for Node.js or WASM plugins)
- [ ] Develop a visual UI / Admin Dashboard to manage the database and visualize encrypted data
- [ ] Launch a dedicated documentation website (e.g., using mdBook or Docusaurus)