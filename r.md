Critical: HSM Integration Design Flaws

Related findings:

#1 Insecure SecureKey Handling in HsmKeyManager
#2 Insecure Placeholder Key Size in HsmKeyManager::get_active_key

Root cause:
HsmKeyManager is not actually returning or operating on HSM-backed keys. Instead it generates placeholder SecureKey objects locally.

Combined impact:

HSM security completely bypassed.
Incorrect key sizes possible.
Cryptographic operations may use the wrong key entirely.

Priority: Critical

Critical: Key Rotation / Transition State Management

Related findings:

#5 TRANSITION_LOCKS Concurrency Logic
#6 Redundant store_key() Call in perform_key_transition_initiation
Logic Bug #1 InMemoryKeyManager::rotate_key
Recommended Fixes #5, #6, #7

Root cause:
The rotation system appears to have inconsistent versioning and transition-state management.

Symptoms:

Concurrent rotations may occur.
Version history may be lost.
Active key state may become inconsistent.
Rotation may overwrite keys rather than create versions.
Intermediate transition states may become visible.

Combined impact:

Failed rotations.
Corrupted key state.
Wrong key served during rotation.
Potential outage during key transitions.

Priority: Critical / High

High: Audit Logging Reliability

Related findings:

#4 Logging Failure Strategy
Recommended Fix #4

Root cause:
Security-sensitive operations continue even if audit logging fails.

Symptoms:

Key creation not logged.
Key retrieval not logged.
Key deletion not logged.

Combined impact:

Missing forensic evidence.
Reduced compliance.
Easier attacker cover-up.

Priority: High

High: SecureKey Memory Safety

Related findings:

#3 Missing SecureKey Zeroization
Performance Issue #1 Frequent SecureKey Cloning

Root cause:
SecureKey handling may create multiple in-memory copies while also potentially lacking zeroization.

Symptoms:

Key material copied repeatedly.
Additional memory exposure.
Potential key remnants after drop.

Combined impact:

Increased attack surface.
Memory-forensics exposure.
Performance degradation.

Priority: High (if zeroization missing), Medium otherwise.

Medium: Policy / Configuration Fragility

Related findings:

Logic Bug #2 RotationPolicy::find_applicable_policy
Recommended Fix #8

Root cause:
Hardcoded string matching for key classification.

Symptoms:

Typos silently downgrade policy.
New purposes default unexpectedly.
Security policy drift.

Combined impact:

Incorrect rotation schedules.
Configuration mistakes become security issues.

Priority: Medium

Medium: Scheduler Performance Issues

Related findings:

Performance Issue #2 Rotation Cache Read Lock Contention
Performance Issue #3 Concurrent Error Logging

Root cause:
Inefficient lock acquisition and logging patterns.

Symptoms:

Excessive lock churn.
Logging bottlenecks under failure conditions.

Combined impact:

Reduced throughput.
Poor scaling under load.

Priority: Medium / Low

Actual Unique Issues Count

The report lists 8 major findings, but after deduplication it's closer to:

Group	Severity
HSM integration broken	Critical
Rotation/versioning/concurrency flaws	Critical
Audit logging fail-open	High
SecureKey memory handling	High
Policy mapping fragility	Medium
Scheduler performance issues	Medium

Real count: ~6 unique issue groups instead of ~12-15 separate findings.