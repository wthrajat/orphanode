# Security policy

## Supported versions

Security fixes are made on the default branch and the latest `0.1.x` release.

| Version | Supported |
| --- | --- |
| Latest `0.1.x` | Yes |
| Older releases | No |

## Report a vulnerability

Do not open a public issue with sensitive details. Use GitHub's private
[security advisory form](https://github.com/wthrajat/orphanode/security/advisories/new).
If private reporting is unavailable, open a public issue asking for a private
contact channel without including the vulnerability.

Please include:

- the affected version, operating system, and installation method;
- the security impact and attacker-controlled input;
- minimal reproduction steps or a private proof of concept; and
- any disclosure or mitigation constraints.

Path escapes, unintended code execution, denial of service, unsafe cleanup,
terminal/output injection, credential exposure, and distribution compromise are
security issues. Ordinary false positives or false negatives belong in the public
issue tracker.

## Security boundaries

An ordinary Orphanode scan:

- does not execute project source, package scripts, or dynamic configuration;
- makes no network requests and collects no telemetry;
- contains source paths within the physical project root;
- reports unresolved or unsupported behavior as a coverage gap; and
- does not modify the project.

Two features deliberately cross the no-code-loading boundary:

- `--mode deep` may load the project's TypeScript compiler; and
- a configured `exec:` plugin runs trusted workspace code.

Apply mode can also invoke the selected package manager. These child processes
have the current user's operating-system permissions; time, path, and protocol
limits are not a security sandbox.

Fixes require explicit item selection, eligibility, current content hashes, and
a complete post-change scan. Run Orphanode with least-privilege filesystem access
and review every proposed removal.
