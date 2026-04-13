# Developer Handoff & Ticket Export

## Product Boundary

SentinelCore **detects, explains, and provides remediation guidance** for
security findings. It does **not** manage tickets, sprints, assignments, or
discussions internally.

Instead, SentinelCore makes it easy to **export finding context** into whatever
ticketing system your team already uses (Jira, GitHub Issues, Azure DevOps,
Linear, email, Slack, etc.).

## How it works

### Copy for Ticket

Every finding detail page includes a **Developer Handoff** section with a
**Copy for Ticket** button. Clicking it copies a clean, structured plaintext
summary to the clipboard:

```
Finding: SQL Injection via Statement.executeQuery
Severity: High
Rule: SC-JAVA-SQL-001
Location: src/main/java/com/example/UserController.java:42

What happened:
User input reaches a SQL execution sink without parameterization.

How to fix:
- Use PreparedStatement with positional parameters
- Bind values via setString/setInt
- Validate numeric IDs where applicable

Verification:
- Query uses PreparedStatement
- No string concatenation with user input
- Tests cover the fixed query path

References:
- CWE-89: SQL Injection
- OWASP SQL Injection Prevention Cheat Sheet
```

This format is:
- **Deterministic** — same finding always produces the same output
- **Safe** — never includes raw secret values (hardcoded secret findings
  show only variable names, not actual values)
- **Self-contained** — a reviewer can understand the issue without opening
  SentinelCore

### Code Example Copy

The remediation panel's safe and unsafe code examples each have a
**copy-to-clipboard** button. The safe example is the recommended paste
target for code review comments.

## Redaction

For hardcoded secret findings (`SC-JAVA-SECRET-001`):
- The ticket handoff shows the **variable/field name** ("DB_PASSWORD")
- It does **not** include the actual secret value
- The remediation summary says "a password is hardcoded" without revealing it
- Safe examples show `System.getenv(...)` patterns, never real credentials

## Extending

The formatter (`web/features/findings/ticket-formatter.ts`) is a pure
function: `formatTicketHandoff(finding: Finding) → string`. Future extensions:
- Markdown export (`formatTicketHandoffMarkdown`)
- PDF report generation
- API-based ticket creation (Jira/GitHub integration)

None of these are implemented yet. The current scope is clipboard copy only.
