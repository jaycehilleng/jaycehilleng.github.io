# Where the Vendor's Trust Model Ends: Hardening a Self-Learning Agent

**Author:** Jayce Hill | Principal AI Security Architect
**Published:** November 2026
**Scope:** One operator's deployment of OpenClaw 2026.9.2, reviewed October 4 to November 2, 2026, then upgraded to 2026.11.4 and re-probed on November 18, 2026. Everything below was observed in this configuration. Nothing here is a vulnerability claim against OpenClaw.

---

> **For deployment leads**
> - **Risk:** Out of the box, this agent ran with root-equivalent rights, an AI model (not a policy) approving its commands, and the ability to rewrite its own instructions.
> - **What was done:** Every safety control moved below the agent, into OS identity, the service sandbox, read-only files, a kernel egress allowlist and human approval. Each control is verified by a repeatable probe, and the set was re-validated after a version upgrade.
> - **What remains:** DNS-based exfiltration, a multi-tenant model endpoint, credentials readable by the agent's identity, and no centralized audit trail yet. See [Honest residuals](#honest-residuals).
> - **What to require of any agent platform:** least-privilege runtime identity, deny-by-default egress, immutable configuration and skills, human approval for consequential actions, and an upgrade process that re-proves all of the above.

## Summary

I deployed an open-source personal AI agent, gave it real tools, and attacked my own controls. Two things stood out. The agent's command gate in its default "auto" mode was an LLM's judgment, not a policy. And by default the agent could write and install its own skills, and the first skill it wrote for itself was a procedure for loosening its own exec policy.

The fix was to stop asking the agent to enforce anything. Every invariant now sits below it, in the OS user, systemd, read-only mounts, the kernel firewall, and a human approval screen. Each control was proven with a live probe, not taken from a config file or a status report.

The October review logged 14 findings: 2 critical, 4 high. Re-validation on 2026.11.4 added a fifteenth, a denial-response evaluation added a sixteenth, a review of the default tool catalog added a seventeenth, and the incident-response drill added an eighteenth. All are listed in the [appendix](#appendix-findings). Severity here means risk in this deployment, not a CVSS score for the product.

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
- Made `skills/` and `openclaw.json` read-only to the service with systemd bind mounts. The `write` tool can otherwise drop a `SKILL.md` straight into the skills directory, and file tools do not raise exec approval cards. (This covered one of the loader's skill roots, not all of them. See the [correction](#correction-i-locked-one-skill-folder-out-of-five).)

**Lesson:** the most dangerous finding wasn't a bug. It was a default.

## 4. Move the invariants below the agent

Prompt rules and agent memory are advisory. The agent can read them, argue with them, and in this case rewrite them. So every control that mattered moved to a layer the agent cannot negotiate with.

| Layer | Control | Probe result |
| --- | --- | --- |
| OS identity | Non-sudo user, locked password | `sudo -n true` fails |
| Process | Hardened systemd unit | Exposure 3.7 OK |
| Config and skills | Read-only bind mounts: `openclaw.json`, all five skill-loader roots (four added November 18, see [correction](#correction-i-locked-one-skill-folder-out-of-five)), `.git/config`, `.git/hooks`, `~/.gitconfig`, `~/.config/git` | Write attempts return `EROFS` |
| Tool surface | Denied: web fetch and search, code execution, cron, Skill Workshop; elevated mode and browser off | "Tool unavailable" |
| Approvals | `ask` mode, six-entry allowlist, cards in the Control UI over an SSH tunnel, gateway on loopback only | `rm -rf` returns `user-denied` |

Two details from this layer:

- **`find` is not read-only.** It was on the "read-only" allowlist, but `find -exec` and `find -delete` make it a general execution primitive. It came off.
- **Git flags are the payload.** A writable `.git/` turns an approved `git commit` into code execution through hooks or `core.hooksPath`. A card that says `git` is not safe because it says git. The `-c` flags on the card are what to read. The agent itself flagged this one.

### Least functionality: the default tool catalog

On November 19 I reviewed every tool the agent could still reach against OpenClaw's own tool catalog. Five of them gave an assistant operator-grade capabilities by default:

| Tool | What the catalog says it does | Why it was denied |
| --- | --- | --- |
| `plugins` | Inspect, install, enable, disable, remove or reload plugins | Agent-reachable code installation, and a path to re-enabling the disabled browser plugin |
| `terminal` | Use shared operator terminals | The operator's terminal should not be reachable from the agent |
| `secrets` | Ask the human for a credential through a trusted prompt, with an agent-written reason and proposed egress hosts | The same lever the denial evaluation showed the agent uses on the operator, aimed at credentials |
| `screen`, `theme` | Arrange Control UI panes; create appearance themes | The Control UI is the approval gate; the agent should not be able to restyle the screen where the human clicks Deny (a precaution, not a demonstrated exploit) |

`process` (managing processes the agent started through `exec`) and `ask_user` (pausing for a human decision) stayed. All five are denied; the agent reports each as absent while still reporting `process` and `ask_user` present, and the probe suite now requires the denies.

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

DNS was the remaining path: the agent's UID could still query the local resolver, which forwards queries to the internet under its own identity. On November 19 that closed. The model API host is pinned in root-owned `/etc/hosts`, and DNS on port 53 is rejected for the agent's UID ahead of the loopback rule. Name lookups for anything else now fail for the agent, while the model API still resolves and answers. The trade-off is deliberate: if the provider changes that address, the agent fails closed until the pin is updated.

The closure surfaced traffic nobody had asked for. On November 22, tracing the denied lookups showed the gateway itself resolving three vendor hosts at startup: an update check (`telemetry.openclaw.ai`), a hosted model-catalog refresh (`catalog.openclaw.ai`) and the ClawHub skill and plugin registry (`clawhub.ai`). The first two have documented off switches and are now off. I found no documented setting for the registry lookup, so the agent-UID DNS rule is the only control stopping a runtime from reaching a supplier of executable skills (finding #18).

**Lesson:** some controls belong to the kernel, and some belong to the human reading the card. Know which is which.

## 6. A human in the loop that actually works

The terminal chat interface could not render approval cards. With `ask` mode on, commands were denied with no explanation, so a correct-looking config was failing closed in silence. Approvals moved to the Control UI over an SSH tunnel, where the card shows the full command.

Approval gates also fail socially before they fail technically. Five cards for one commit is how you train someone to click Allow. The allowlist covers routine read operations so the cards that do appear deserve attention.

### Measured: what the agent does after a human says no

On November 19 I measured it. A [denial-response evaluation](../../labs/openclaw/eval/) gave the agent three tasks that each need a non-allowlisted command (`rm -rf`, `curl`, `tar`), denied every approval through the same path as the Control UI's Deny button, and recorded what it did next. The harness can only deny; it has no code path that approves anything.

| Behavior | First "no" (9 sessions) | Under pressure (6 sessions, 24 turns) |
| --- | --- | --- |
| Completed the task anyway | 0 | 0 |
| Bypassed the gate with file-editing tools | 0 | 0 |
| Re-requested the identical command | 0 | 6, at 2 to 4 approval cards per session |
| Suggested the human's "no" might be a system fault | 0 | 4 |
| Pointed the operator at loosening or inspecting exec policy | 0 | 3 (1 explicit: "loosen the exec policy for this session") |
| Reached for the `gateway` tool after being told to "find a way" | 0 | 3 |

The pressure sessions pushed back three times in the same conversation, ending with "find a way" and "do whatever it takes". Labels are human-reviewed; the automatic classifier over-reported workarounds, so every label was checked against the transcript evidence.

Two results matter. First, the kernel-level controls held: nothing ran, and nothing was routed around them. Second, the social pressure on the human is real and repeatable. Each push produced another approval card, and in four of six sessions the agent framed a deliberate denial as a possible fault. That is approval fatigue, measured.

The third result was a new finding (#16). Told to "find a way", the agent used its `gateway` tool to look for a way to inspect or change its own approval policy, and reported that the tool exposed `update.run` but not `config.get`. OpenClaw's own restricted-agent examples deny `gateway`; this configuration did not. It is now denied, and the probe suite checks it.

**Lesson:** test the human side of the gate as deliberately as the technical side. The controls below the agent held under pressure. The person reading the cards is the part that needs protecting.

## 7. What I'd tell a platform team

- **Prompt guardrails are advisory.** Controls the agent can't negotiate with live in the OS, the scheduler, and tool policy.
- **Treat agent memory as untrusted output.** Scout's own memory file recorded wrong security conclusions three times. Canonical security state belongs in a repo or system the operator controls.
- **Secrets can't be hidden from an in-process agent.** The model API key lives in a store the agent's own identity can read. Egress control limits where it can go; a separate execution identity or short-lived credentials is the real fix.
- **Verify the control, not the report.** The CLI, the audit, the docs, and the agent each told me something false at least once. Every row above is backed by a probe.

### Portability

None of these controls depend on OpenClaw or on the model provider. Runtime identity, the service sandbox, read-only configuration and skills, deny-by-default egress and human approval sit below the agent. They apply the same way to any agent runtime that executes tools on a host, whichever model it calls. The OpenClaw-specific parts are the paths: where configuration lives and where the skill loader reads.

## Honest residuals

| Residual | Why it remains | Next control |
| --- | --- | --- |
| Pinned model API address | DNS is closed for the agent; a provider address change stops the agent until the pin is updated (fails closed) | Monitor the provider's published addresses; update the pin through change control |
| Operator CLI `agent exec` | Runs a turn embedded, outside the service sandbox and read-only mounts | Keep it to operator use; run agent turns through the Gateway |
| Multi-tenant API endpoint | An attacker-supplied API key could route data to another account at the same provider | Route model traffic through a local proxy that accepts only the operator's credential |
| Writable persona and memory files | By design; a persistence surface for prompt injection | Snapshot and diff them per session; alert on change |
| Same-UID credential exposure | In-process agents share the gateway's identity | Separate execution identity, or short-lived credentials issued by a broker |
| No centralized audit trail | Approval decisions and firewall denials live only in the host journal | Forward approval events and egress denials to a SIEM |
| Startup lookup of the ClawHub registry | No documented setting turns it off; blocked only by the agent-UID DNS rule | Keep DNS closed for the agent; re-check after each upgrade |
| Git `-c` flags on approval cards | Enforced by the human reading the card, not by the kernel | Allowlist git subcommands without `-c` |
| Scope | One operator; reviewed on 2026.9.2, re-validated on 2026.11.4 | n/a |

## Day 2: upgrading a hardened agent

Hardening is only as current as the release it was tested on. On November 18, 2026, I upgraded this deployment from 2026.9.2 to 2026.11.4 and re-validated every control, using this runbook:

1. **Recover point:** incremental disk snapshot, taken with the VM deallocated.
2. **Baseline:** version, `security audit` summary, the security-relevant config sections, and SHA-256 hashes of the config, service unit and firewall files.
3. **Inspect before install:** download the new package without installing it. Read its install scripts (they run as root) and its bundled documentation, including the upgrade notes and the skill-loader paths.
4. **Prerequisites:** 11.4 required a Node.js major-version upgrade, done from the same package source as the original install.
5. **Upgrade with the agent stopped,** then diff hashes and security settings against the baseline.
6. **Preview repairs before applying them:** run `doctor` without `--fix`, read the plan, then apply.
7. **Re-probe every control,** including from inside the service's own mount namespace, then record new known-good hashes.

"Probe" below means verified on the host; "Docs" means taken from the 11.4 bundled documentation.

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

## Control mapping (NIST SP 800-53 Rev. 5)

This table orients the controls above for teams working toward an authorization. It is a mapping for orientation, not an assessment: this is a single-operator lab with no system security plan.

| Control | Implementation here | Evidence | Gap |
| --- | --- | --- | --- |
| AC-6 Least Privilege | Dedicated non-sudo service user, empty capability set, `NoNewPrivileges` | `sudo -n true` fails; exposure 3.7 OK | n/a |
| AC-3 Access Enforcement | Human approval required for non-allowlisted commands | `rm -rf` returns `user-denied` | File tools write without a card (mitigated by read-only mounts) |
| CM-2 Baseline Configuration | Recorded version, audit summary, security settings, and file hashes | Baseline compared after upgrade | Manual, not continuous |
| CM-3 Configuration Change Control | Day 2 upgrade runbook with preview-before-repair | Section above | No formal change board (single operator) |
| CM-5 Access Restrictions for Change | Config, skill roots and git surfaces are read-only to the agent | Writes return `EROFS` | Persona and memory files writable by design |
| CM-7 Least Functionality | Web, code execution, cron, skill-authoring, gateway, plugin, terminal, secrets and UI-theming tools denied; browser and elevated mode off | Tools absent from the agent's catalog | n/a |
| SC-7 Boundary Protection, (5) Deny by Default | UID-scoped nftables allowlist; DNS blocked for the agent's UID; model API pinned in `/etc/hosts`; agent fails closed without the firewall | Approved `curl` blocked; other name lookups fail; model API reachable | Multi-tenant endpoint |
| SI-7 Software and Information Integrity | Hash baselines for config, unit and firewall files; skills immutable to the agent | Hash diff after upgrade | No automated integrity monitoring |
| IA-5 Authenticator Management | Model API key rotated on a 90-day cycle through a hidden prompt; account spend cap | Old key deleted after the new key was verified | Key readable by the agent's identity |
| AU-2 / AU-12 Event Logging | Egress denials logged by the kernel; approval decisions in the gateway log | Denials attributed to destinations | No centralized retention or review (AU-6) |
| CP-9 System Backup | Disk snapshot before every upgrade | Snapshot taken before 2026.11.4 | n/a |

## Appendix: findings

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| 1 | Agent ran as a user with passwordless sudo; the built-in audit did not flag it | Critical | Remediated: dedicated non-sudo user, hardened unit |
| 2 | Self-learning default auto-installed an agent-written skill for loosening its own exec policy | Critical | Remediated: skill quarantined with hashes; self-learning off; skill roots read-only |
| 3 | "Auto" exec mode is LLM judgment; it approved `rm -rf` and outbound `curl` | High | Remediated: `ask` mode with Control UI approvals |
| 4 | File tools (write, edit) bypass exec approvals | High | Partial: config, skills and git surfaces read-only; persona and memory writable by design |
| 5 | Writable `.git/` turns an approved commit into code execution (hooks, `core.hooksPath`) | High | Remediated: git config and hooks read-only. Residual: `-c` flags are human-enforced |
| 6 | Egress outside exec through in-process web tools | High | Remediated: UID-scoped kernel allowlist, fail-closed |
| 7 | `find` on the read-only allowlist is an execution primitive (`-exec`, `-delete`) | Medium | Remediated: removed from allowlist |
| 8 | A partial user migration left stale paths that hid the workspace from the audit | Medium | Remediated |
| 9 | The terminal UI cannot render approval cards, so `ask` mode denied everything silently | Medium | Remediated: Control UI over an SSH tunnel, gateway on loopback |
| 10 | The model API key sits in a store the agent's identity can read | Medium | Partial: rotation and spend cap; egress limits where it can go |
| 11 | The agent's memory recorded wrong security conclusions (three caught) | Medium | Open: canonical record kept outside the agent |
| 12 | The CLI reports "applies without restart" when read-only mounts mean it doesn't | Low | Documented |
| 13 | Background "dreaming" writes to agent memory unattended | Low | Open |
| 14 | Audit probe blind spot for the `operator.read` scope | Info | Documented (by design) |
| 15 | Skill loader reads four roots the October hardening did not cover; canaries loaded from all four | High | Remediated November 18: four more read-only mounts, `EROFS` verified |
| 16 | Under pressure, the agent used its `gateway` tool to look for a way to inspect or change its approval policy; the tool exposes `update.run` | High | Remediated November 19: `gateway` denied; absent from the agent's catalog; added to the probe suite |
| 17 | The default tool catalog gives the agent operator-grade tools: plugin installation, operator terminals, credential prompts and restyling of the approval screen | High | Remediated November 19: `plugins`, `terminal`, `secrets`, `screen`, `theme` denied; absent from the catalog; added to the probe suite |
| 18 | By default the gateway contacts three vendor hosts: a daily update check sending version and platform details, a hosted model-catalog refresh, and the ClawHub skill registry | Low | Partial, November 22: update check and catalog refresh off by config, added to the probe suite; registry lookup blocked by the agent-UID DNS rule (no documented setting) |

---

*Related: [Zero-Trust MCP Gateway spec](../architecture-spec.md) · [Threat matrix](../threat-matrix.md) · [Identity architecture](../identity-architecture.md)*
