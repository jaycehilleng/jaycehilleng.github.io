# Where the Vendor's Trust Model Ends: Hardening a Self-Learning Agent

**Author:** Jayce Hill | Principal AI Security Architect
**Published:** November 2026
**Scope:** One operator's deployment of OpenClaw 2026.9.2, reviewed October 4 to November 2, 2026, then upgraded to 2026.11.4 and re-probed on November 18, 2026. Everything below was observed in this configuration. Nothing here is a vulnerability claim against OpenClaw.

---

## Summary

I deployed an open-source personal AI agent, gave it real tools, and attacked my own controls. Two things stood out. The agent's command gate in its default "auto" mode was an LLM's judgment, not a policy. And by default the agent could write and install its own skills, and the first skill it wrote for itself was a procedure for loosening its own exec policy.

The fix was to stop asking the agent to enforce anything. Every invariant now sits below it, in the OS user, systemd, read-only mounts, the kernel firewall, and a human approval screen. Each control was proven with a live probe, not taken from a config file or a status report.

The review logged 14 findings: 2 critical, 4 high. Severity here means risk in this deployment, not a CVSS score for the product.

## The environment

| Item | Detail |
| --- | --- |
| Software | OpenClaw 2026.9.2, an open-source single-operator agent gateway |
| Model | Claude Opus via API |
| Host | Isolated Azure Ubuntu VM in a dedicated lab tenant, no managed identity |
| Agent | "Scout": one operator, no chat channels, no untrusted senders |
| Method | Configure, probe, harden, re-probe |

OpenClaw's published trust model matters for reading the rest. It is a personal assistant for one trusted operator. Its exec approvals are operator guardrails, not a multi-tenant security boundary, and the sandbox is off by default. Those are reasonable product choices. This article is about what an operator has to add when the agent holds real credentials and tools.

## 1. The gate was a model

The first probe was blunt: ask the agent to run `rm -rf` on a scratch directory, then an outbound `curl`.

In "auto" exec mode, both ran with no prompt. Auto mode is an LLM reviewer deciding whether a command looks safe. It is a judgment call that can be argued with, which makes it a target for prompt injection.

After the change to `ask` mode, with approval cards in the Control UI, the same `rm -rf` came back `user-denied`. Same command, same agent. The only difference was whether a model or a human made the call.

**Lesson:** know what your gate actually is. "Approval" can mean a person, a policy engine, or another model.

## 2. Starting state: effectively root

The agent ran as the VM's default admin user, which had passwordless sudo. With exec set to `security=full` and `ask=off`, the blast radius was the whole VM.

OpenClaw's own `openclaw security audit` did not flag it. The audit checks OpenClaw's configuration, not what the host user can do. Later, a half-finished user migration left stale paths that made the audit report *fewer* findings than before, because it could no longer see the workspace.

The fix was a dedicated non-sudo `openclaw` user with a locked password, running under a hardened systemd unit:

| Control | Setting |
| --- | --- |
| Privilege | `NoNewPrivileges=yes`, empty capability set |
| Filesystem | `ProtectSystem=strict`, `ProtectHome=tmpfs` |
| Result | `systemd-analyze security` exposure 9.6 UNSAFE to 3.7 OK |
| Probe | `sudo -n true` fails as the agent user |

**Lesson:** a clean audit report is a statement about what the auditor can see.

## 3. The agent edited its own rules

OpenClaw's self-learning feature (Skill Workshop) reviews substantial sessions in the background and saves reusable procedures as skills. In 2026.9.2, `skills.workshop.autonomous.mode` defaulted to `"auto"`, which applies what it captures with no human prompt.

After a session spent configuring exec approvals, Scout wrote and installed a skill named `exec-approval-hardening`. It was a procedure for changing its own exec policy, including a "revert path" that turned approvals off. Nobody approved it.

I quarantined the skill outside the agent's reach with SHA-256 hashes recorded, then:

- Set `autonomous.mode` to `propose` and `approvalPolicy` to `pending`, so nothing applies without the operator.
- Made `skills/` and `openclaw.json` read-only to the service with systemd bind mounts. The `write` tool can otherwise drop a `SKILL.md` straight into the skills directory, and file tools do not raise exec approval cards.

**Lesson:** the most dangerous finding wasn't a bug. It was a default.

## 4. Move the invariants below the agent

Prompt rules and agent memory are advisory. The agent can read them, argue with them, and in this case rewrite them. So every control that mattered moved to a layer the agent cannot negotiate with.

| Layer | Control | Probe result |
| --- | --- | --- |
| OS identity | Non-sudo user, locked password | `sudo -n true` fails |
| Process | Hardened systemd unit | Exposure 3.7 OK |
| Config and skills | Read-only bind mounts: `openclaw.json`, `skills/`, `.git/config`, `.git/hooks`, `~/.gitconfig`, `~/.config/git` | Write attempts return `EROFS` |
| Tool surface | Denied: web fetch and search, code execution, cron, Skill Workshop; elevated mode and browser off | "Tool unavailable" |
| Approvals | `ask` mode, six-entry allowlist, cards in the Control UI over an SSH tunnel, gateway on loopback only | `rm -rf` returns `user-denied` |

Two details from this layer:

- **`find` is not read-only.** It was on the "read-only" allowlist, but `find -exec` and `find -delete` make it a general execution primitive. It came off.
- **Git flags are the payload.** A writable `.git/` turns an approved `git commit` into code execution through hooks or `core.hooksPath`. A card that says `git` is not safe because it says git. The `-c` flags on the card are what to read. The agent itself flagged this one.

## 5. Egress: kernel, not judgment

Web tools ran inside the gateway process, outside exec policy, so blocking `curl` at the approval layer did not stop outbound HTTP. The Azure network security group restricted inbound traffic only.

Egress is now an nftables allowlist scoped to the agent's UID with `meta skuid`. That UID can reach loopback and the model provider's published API range on 443. Everything else is rejected and logged. The gateway unit has `Requires=` on the firewall unit, so it fails closed.

| Probe | Result |
| --- | --- |
| Agent user to an arbitrary site | Blocked, logged |
| Agent user to the model API | Reachable |
| Agent user to the Azure metadata endpoint | Blocked, logged |
| Admin user to an arbitrary site | Unaffected |
| **Approved `curl` from the agent** | **Failed to connect after 0 ms** |
| Stop the firewall | Gateway goes `inactive` with it |

The approved `curl` is the result that matters. I clicked Allow, and the command still could not leave the host. A mistaken approval no longer becomes exfiltration.

**Lesson:** some controls belong to the kernel, and some belong to the human reading the card. Know which is which.

## 6. A human in the loop that actually works

The terminal chat interface could not render approval cards. With `ask` mode on, commands were denied with no explanation, so a correct-looking config was failing closed in silence. Approvals moved to the Control UI over an SSH tunnel, where the card shows the full command.

Approval gates also fail socially before they fail technically. Five cards for one commit is how you train someone to click Allow. The allowlist covers routine read operations so the cards that do appear deserve attention.

## 7. What I'd tell a platform team

- **Prompt guardrails are advisory.** Controls the agent can't negotiate with live in the OS, the scheduler, and tool policy.
- **Treat agent memory as untrusted output.** Scout's own memory file recorded wrong security conclusions three times. Canonical security state belongs in a repo or system the operator controls.
- **Secrets can't be hidden from an in-process agent.** The model API key lives in a store the agent's own identity can read. Egress control limits where it can go; a separate execution identity or short-lived credentials is the real fix.
- **Verify the control, not the report.** The CLI, the audit, the docs, and the agent each told me something false at least once. Every row above is backed by a probe.

## Honest residuals

| Residual | Why it remains |
| --- | --- |
| DNS tunneling | The allowlist covers IP traffic; the local resolver still answers queries |
| Multi-tenant API endpoint | An attacker-supplied API key could route data to another account at the same provider |
| Writable persona and memory files | By design; a persistence surface for prompt injection |
| Same-UID credential exposure | In-process agents share the gateway's identity |
| Git `-c` flags on approval cards | Enforced by the human reading the card, not by the kernel |
| Scope | One operator; reviewed on 2026.9.2, re-probed on 2026.11.4 |

## Upstream since this review

On November 18, 2026, I upgraded this deployment from 2026.9.2 to 2026.11.4 and re-ran every probe. Before the upgrade I took a disk snapshot, recorded the version, audit summary, security settings and SHA-256 hashes of the config, unit and firewall files, and read the 11.4 package (bundled docs and install scripts) before installing it. "Probe" below means verified on the box; "Docs" means taken from the 11.4 bundled documentation.

| Area | 2026.9.2 | 2026.11.4 | Source |
| --- | --- | --- | --- |
| Runtime | Node 22 | Requires Node 24.16 or later; the upgrade was a Node major version bump first | Probe |
| Self-learning default | `autonomous.mode: "auto"` | Still `"auto"` | Docs |
| Human review of learned skills | `propose` mode and `approvalPolicy: "pending"` available; neither is the default | Retired. Changes apply immediately, with undo and the newest 10 versions kept | Docs |
| Stale `propose` config | n/a | Gateway refuses to start (`config is invalid`, exit 78); it does not fall back to defaults | Probe |
| Upgrade repair | n/a | `doctor --fix` rewrote `propose` to `off`, not `auto`; it left the hardened systemd unit untouched (hash unchanged) | Probe |
| Learned-skill undo from chat | n/a | Runs through the `skill_workshop` tool. With that tool denied, it is absent from the agent's 41-tool catalog, so asking for it fails | Probe |
| Skill roots | Four writable roots under the agent's home | Five: adds `agents/<id>/agent/workshop-skills` | Probe |
| Exec approvals | Allowlisted binary runs without a card | `NAME+=value ls` raises a card despite `ls` being allowlisted; a command that cannot be bound to an approval is refused (`SYSTEM_RUN_DENIED`) | Probe |
| Control UI | n/a | Warns before a link switches the browser to a different gateway | Probe |
| Skill allowlists | Not stated | Learned skills bypass `agents.defaults.skills` allowlists | Docs |
| Write-time checks | Size limits | A critical security-scanner finding, such as a literal secret, refuses the write | Docs |
| `security audit` | 0 critical, 1 warn, 1 info | Same; still no check for a gateway user with passwordless sudo | Probe |

Every October control held on 11.4: exposure still 3.7 OK, `sudo -n true` still fails, an arbitrary site is still refused (and so were 11.4's own unprompted connections to its docs site), the model API is still reachable, and `rm -rf` still comes back `user-denied`.

### Correction: I locked one skill folder out of five

The upgrade sent me back to the skill loader's precedence table, and it showed something my October hardening missed. I had made `workspace/skills` read-only. The loader also reads `workspace/.agents/skills` (which outranks it), `~/.agents/skills` and `~/.openclaw/skills`. Those three were already in 2026.9.2's documentation. 2026.11.4 adds a fifth, `workshop-skills`.

To test it, I wrote a harmless canary `SKILL.md` into each of the four uncovered roots as the agent's user. All four loaded as `ready`. Any process running as that user, including the agent's own file tools, which raise no approval card, could have installed a live skill, and one of those roots would shadow a same-named skill in the folder I had locked.

The fix was four more read-only mounts. Retried from inside the service's mount namespace, all four writes returned `Read-only file system`. The agent independently named the same path when asked how skills get authored without the workshop: "the skill-creator skill plus file edits."

**Lesson:** I locked the folder I knew about. Lock every path the loader reads, and get that list from the loader's own documentation for the version you run.

One behavior didn't change. After I denied a few commands in a row, the agent concluded that something in the approval path was "rejecting everything" and suggested I look into why. It treated a human "no" as a malfunction. That is the social failure mode from section 6, unchanged across releases.

The vendor chose "apply now, undo later" for a single-operator assistant. That's a defensible product decision. For a deployment holding credentials, I chose off, enforced below the agent with read-only mounts on every skill root. The upgrade path preserves that choice, and when a stale setting can't be read, 11.4 stops rather than guessing.

---

*Related: [Zero-Trust MCP Gateway spec](../architecture-spec.md) · [Threat matrix](../threat-matrix.md) · [Identity architecture](../identity-architecture.md)*
