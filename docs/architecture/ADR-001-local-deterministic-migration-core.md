# ADR-001: Local deterministic migration core with agent orchestration

- Status: Accepted for MVP
- Date: 2026-08-26

## Context

The product needs conversational guidance, resumable discovery, provider extensibility, explicit approvals, and strong control over customer-system side effects. The repository already has Codex skills, MCP configuration, and shell-based lab tooling, but it did not have a trusted migration workflow core.

## Options considered

| Option | Advantages | Disadvantages and security implications |
|---|---|---|
| Conversational CLI only | Small operational footprint; local-first | A free-form agent can blur reasoning and execution unless every side effect is separately constrained |
| Local web application | Rich review and visualization UX | Adds a listener, session security, browser attack surface, packaging, and lifecycle complexity before product fit is proven |
| Autonomous agent using MCP tools | Fast integration with vendor capabilities | Tool availability and model behavior are not sufficient authorization or deterministic policy enforcement |
| Plugin/adapters plus IR library | Extensible and testable provider boundaries | Does not itself provide workflow state, approvals, or customer interaction |
| Deterministic workflow engine only | Strong replay, approvals, and auditability | Poor conversational discovery and explanation without an orchestration layer |
| Combined local CLI, Codex skill, deterministic core, adapters, and state machine | Separates reasoning from effects while retaining conversational UX and provider extensibility | Requires explicit contracts and more disciplined integration work |

## Decision

Use the combined architecture. Codex supplies conversational orchestration through an umbrella `observability-migration-assessment` skill and six phase-specific skills. Four project-scoped read-only subagents perform independent evidence reviews without owning customer access or artifact writes. A dependency-free Python core owns configuration parsing, authorization validation, provider calls, normalization, rules, reports, checkpoints, and audit records. Provider adapters and declarative mappings extend the core.

The MVP ends at a hash-bound, non-executable migration plan and plan-review approval. Production target writes, browser automation, remediation, Terraform apply, Git commits, and pushes are separate future capabilities requiring new interfaces, tests, credentials, policy, and explicit authorization.

## Consequences

- The LLM receives only allowlisted pseudonymous context, not raw customer configuration.
- Narrow requests load one phase-specific skill; full-flow requests use the umbrella skill and may parallelize read-only review lanes.
- MCP may assist with approved discovery, but MCP tool presence never bypasses state or approval gates.
- Target selection is configuration-driven: Splunk Observability Cloud, Splunk Platform, or both.
- Compatibility behavior is versioned declarative data, while network and filesystem effects remain trusted code.
- A future local web UI can consume the same schemas and state machine without changing the core trust boundary.

## Evidence

- CLI and workflow: `.agents/skills/observability-migration-assessment/scripts/migration_assessment.py`
- State machine: `.agents/skills/observability-migration-assessment/scripts/assessment_core/state.py`
- Provider contracts: `.agents/skills/observability-migration-assessment/scripts/assessment_core/interfaces.py`
- Declarative rules: `.agents/skills/observability-migration-assessment/references/compatibility-rules.v1.json`
- Skill safety boundary: `.agents/skills/observability-migration-assessment/SKILL.md`
