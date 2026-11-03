# Security policy

Keyway runs a local proxy and handles server credentials, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private reporting instead:
[Report a vulnerability](https://github.com/arminsameti/Keyway/security/advisories/new).

Include what you found, how to reproduce it, and which Keyway version and macOS version you used.
You can expect a first reply within a week. Once a fix is released, the report is credited to you if you want that.

## Supported versions

Only the latest release gets security fixes.

## Scope

In scope: the Keyway app, `keywayd`, the privileged TUN helper, the local API (`127.0.0.1`, per-launch token),
and how Keyway downloads and verifies engines and its own updates.

Out of scope: vulnerabilities in the engines themselves (Xray, sing-box, V2Ray core, Mihomo, Tor). Report those
to their own projects.
