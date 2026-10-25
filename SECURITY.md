# Security

Version 0.1.x receives security fixes. Report vulnerabilities privately using
[GitHub private vulnerability reporting](https://github.com/KanadeK/man-alias-audit/security/advisories/new).
If that channel is unavailable, open an issue requesting a private reporting
channel without including exploit details or sensitive input.

The tool reads local inputs; it does not download, execute or upload their content.
Reports can contain paths or URLs from supplied inputs. Review them before sharing.
Use trusted, quiescent directories; concurrent filesystem replacement is outside
the threat model. Resource limits are safeguards, not a sandbox for arbitrary hostile data.
