# Security Policy

## Supported versions

IDA Pilot is pre-1.0. Only the latest `main` is supported — fixes land there, and
there are no backported release branches yet.

## Reporting a vulnerability

Please report security issues **privately** rather than opening a public issue:

1. Go to the repository's **Security** tab → **Report a vulnerability** (GitHub
   private vulnerability reporting). This keeps the report confidential until a
   fix is available.
2. If private reporting is unavailable, open a regular issue that says only
   "security report — please enable a private channel" with no details, and a
   maintainer will follow up.

Include, where possible: affected version/commit, a description of the impact, and
the minimal steps or proof-of-concept to reproduce.

This is a community project with no formal SLA; expect a best-effort response.
Please give maintainers a reasonable window to ship a fix before any public
disclosure.

## Threat model — what is and isn't a vulnerability

IDA Pilot has **no built-in authentication**. The security posture is documented
in the README ([Security model](README.md#%EF%B8%8F-security-model--read-before-exposing-the-port)).
Read it before filing — some behaviors are intentional given the defaults.

In scope (please report):

- A bypass of the loopback `Origin`/`Host` guard that lets a browser page or a
  remote host reach the API when bound to `127.0.0.1`.
- A way to escape the `--allowed-roots` filesystem allowlist (path traversal,
  symlink escape, normalization bug) when it is configured.
- `py_eval` being reachable, or any RCE, **without** `--enable-py-eval` set.
- Any memory-safety / injection issue in the Go server or Python worker
  reachable from a normal (non-`py_eval`) tool call.

Out of scope (by design — these require an explicit operator opt-in):

- Arbitrary code execution via `py_eval` when it has been enabled with
  `--enable-py-eval`. It is an RCE primitive on purpose.
- Reading any file the server user can read via `open_binary` / `import_metadata`
  when `--allowed-roots` is **not** configured. Set the allowlist to restrict it.
- Reaching the port from another host when the operator has explicitly bound to a
  non-loopback interface (`--bind 0.0.0.0`). You are expected to put an
  authenticated proxy in front.
