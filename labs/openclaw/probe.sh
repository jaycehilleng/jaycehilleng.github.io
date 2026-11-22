#!/usr/bin/env bash
# OpenClaw hardening probe suite.
#
# Verifies, on a running host, every control that does not need a human at the
# approval screen. Run before and after every upgrade; any FAIL blocks the change.
#
# Usage:  sudo ./probe.sh
# Exit:   0 if every probe passes, 1 otherwise.
#
# Read-only by design: write probes target paths that must reject writes, run
# inside the gateway's own mount namespace, and clean up if a write unexpectedly
# succeeds. No configuration is changed.

set -uo pipefail

AGENT_USER="${AGENT_USER:-openclaw}"
UNIT="${UNIT:-openclaw-gateway.service}"
EGRESS_UNIT="${EGRESS_UNIT:-openclaw-egress.service}"
MAX_EXPOSURE="${MAX_EXPOSURE:-4.0}"
DENIED_URL="${DENIED_URL:-https://example.com}"
MODEL_API_URL="${MODEL_API_URL:-https://api.anthropic.com/v1/messages}"
EXPECTED_DENIES=(web_fetch web_search x_search code_execution cron skill_workshop gateway plugins terminal secrets screen theme)

H="/home/${AGENT_USER}"
READONLY_DIRS=(
  "$H/.openclaw/workspace/skills"
  "$H/.openclaw/workspace/.agents/skills"
  "$H/.agents/skills"
  "$H/.openclaw/skills"
  "$H/.openclaw/agents/main/agent/workshop-skills"
  "$H/.openclaw/workspace/.git/hooks"
  "$H/.config/git"
)
READONLY_FILES=(
  "$H/.openclaw/openclaw.json"
  "$H/.openclaw/workspace/.git/config"
  "$H/.gitconfig"
)

pass=0; fail=0
ok()  { printf 'PASS  %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf 'FAIL  %s\n' "$1"; fail=$((fail + 1)); }

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)."; exit 2; }
AGENT_UID="$(id -u "$AGENT_USER")" || { echo "No user $AGENT_USER"; exit 2; }

echo "== Runtime"
systemctl is-active --quiet "$UNIT" && ok "gateway active" || bad "gateway not active"
ver="$(sudo -u "$AGENT_USER" -H sh -c 'cd ~ && openclaw --version' 2>/dev/null)"
echo "INFO  ${ver:-version unknown}"

echo "== Identity (AC-6)"
if sudo -u "$AGENT_USER" sudo -n true 2>/dev/null; then
  bad "agent user can sudo without a password"
else
  ok "agent user has no passwordless sudo"
fi

echo "== Sandbox"
score="$(systemd-analyze security "$UNIT" 2>/dev/null | awk '/Overall exposure level/ {print $(NF-2)}')"
if [[ -n "$score" ]] && awk -v s="$score" -v m="$MAX_EXPOSURE" 'BEGIN { exit !(s <= m) }'; then
  ok "systemd exposure $score <= $MAX_EXPOSURE"
else
  bad "systemd exposure ${score:-unknown} (max $MAX_EXPOSURE)"
fi
if systemctl show -p Requires --value "$UNIT" | grep -qw "$EGRESS_UNIT"; then
  ok "gateway Requires= $EGRESS_UNIT (fail-closed)"
else
  bad "gateway does not require $EGRESS_UNIT"
fi

echo "== Immutable config and skills (CM-5), inside the gateway's mount namespace"
pid="$(systemctl show -p MainPID --value "$UNIT")"
if [[ -z "$pid" || "$pid" == "0" ]]; then
  bad "no gateway PID; skipping namespace write probes"
else
  ns() { nsenter -t "$pid" -m -S "$AGENT_UID" -G "$AGENT_UID" sh -c "$1" 2>&1; }
  for d in "${READONLY_DIRS[@]}"; do
    probe="$d/.probe-$$"
    out="$(ns "touch '$probe'")"
    if [[ "$out" == *"Read-only file system"* ]]; then
      ok "read-only: $d"
    else
      nsenter -t "$pid" -m rm -f "$probe" 2>/dev/null
      bad "writable or missing: $d (${out:-write succeeded})"
    fi
  done
  for f in "${READONLY_FILES[@]}"; do
    # Opening for append on a read-only mount fails before any byte is written.
    out="$(ns ": >> '$f'")"
    if [[ "$out" == *"Read-only file system"* ]]; then
      ok "read-only: $f"
    else
      bad "writable or missing: $f (${out:-open succeeded})"
    fi
  done
fi

echo "== Egress (SC-7(5))"
code="$(sudo -u "$AGENT_USER" curl -s -m 5 -o /dev/null -w '%{http_code}' "$DENIED_URL" 2>/dev/null)"
[[ "$code" == "000" ]] && ok "agent blocked from $DENIED_URL" || bad "agent reached $DENIED_URL (HTTP $code)"
code="$(sudo -u "$AGENT_USER" curl -s -m 5 -o /dev/null -w '%{http_code}' "$MODEL_API_URL" 2>/dev/null)"
[[ "$code" != "000" ]] && ok "model API reachable (HTTP $code)" || bad "model API unreachable"
if sudo -u "$AGENT_USER" getent hosts example.com >/dev/null 2>&1; then
  bad "agent can resolve arbitrary names (DNS open)"
else
  ok "agent DNS blocked"
fi
if sudo -u "$AGENT_USER" getent hosts "$(printf '%s' "$MODEL_API_URL" | awk -F/ '{print $3}')" >/dev/null 2>&1; then
  ok "model API host resolves for the agent (pinned)"
else
  bad "model API host does not resolve for the agent"
fi
if nft list table inet openclaw_egress >/dev/null 2>&1; then
  ok "egress table loaded"
else
  bad "egress table missing"
fi

echo "== Agent policy (CM-7)"
cfg="$(sudo -u "$AGENT_USER" -H sh -c 'cd ~ && openclaw config validate' 2>&1)"
[[ "$cfg" == *"Config valid"* ]] && ok "config validates" || bad "config invalid: ${cfg%%$'\n'*}"
policy="$(sudo -u "$AGENT_USER" -H python3 - "$H/.openclaw/openclaw.json" "${EXPECTED_DENIES[@]}" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
t = c.get("tools", {})
deny = set(t.get("deny", []))
checks = {
    "exec mode is ask": t.get("exec", {}).get("mode") == "ask",
    "elevated mode off": t.get("elevated", {}).get("enabled") is False,
    "browser plugin off": c.get("plugins", {}).get("entries", {}).get("browser", {}).get("enabled") is False,
    "self-learning off": c.get("skills", {}).get("workshop", {}).get("autonomous", {}).get("mode") == "off",
    "required tools denied": set(sys.argv[2:]) <= deny,
    # Finding #18: vendor traffic the runtime starts on its own.
    "update check off": c.get("update", {}).get("checkOnStart") is False,
    "hosted model catalog refresh off": c.get("models", {}).get("catalogRefresh", {}).get("enabled") is False,
}
for name, passed in checks.items():
    print(("PASS" if passed else "FAIL") + "|" + name)
PY
)"
while IFS='|' read -r result name; do
  [[ "$result" == "PASS" ]] && ok "$name" || bad "$name"
done <<< "$policy"

echo "== Built-in audit"
audit="$(sudo -u "$AGENT_USER" -H sh -c 'cd ~ && openclaw security audit' 2>&1 | grep -m1 '^Summary:')"
[[ "$audit" == *"0 critical"* ]] && ok "${audit}" || bad "audit: ${audit:-no summary}"

echo
echo "Result: $pass passed, $fail failed"
echo "Manual probes (need the approval screen): see README.md"
[[ $fail -eq 0 ]]
