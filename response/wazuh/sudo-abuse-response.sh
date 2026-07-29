#!/bin/bash
# ---------------------------------------------------------------------------
# Custom Wazuh Active-Response: local sudo abuse (rule 100011, T1548.003)
#
# WHY THIS EXISTS:
#   A sudo failure is a LOCAL event with no source IP, so the built-in
#   firewall-drop cannot respond to it. The matched host action here is to
#   flag (and optionally lock) the offending account and record evidence.
#
# SAFETY:
#   Defaults to LOG-ONLY (LOCK_ACCOUNT=0). Locking a real user is disruptive,
#   so account locking is opt-in. Even when enabled, root and a whitelist of
#   protected accounts are never touched.
#
# DEPLOY (on the AGENT):
#   cp sudo-abuse-response.sh /var/ossec/active-response/bin/
#   chown root:wazuh /var/ossec/active-response/bin/sudo-abuse-response.sh
#   chmod 750       /var/ossec/active-response/bin/sudo-abuse-response.sh
# ---------------------------------------------------------------------------

LOG="/var/ossec/logs/active-responses.log"
LOCK_ACCOUNT=0                      # 0 = log only (safe default), 1 = also lock
PROTECTED="root ubuntu wazuh"       # never lock these

# Wazuh passes the alert as JSON on stdin (AR v4). Read it.
read -r INPUT_JSON

# Pull the offending user from the alert (srcuser). Fall back to "unknown".
SRCUSER=$(echo "$INPUT_JSON" | grep -oE '"srcuser"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"srcuser"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
[ -z "$SRCUSER" ] && SRCUSER="unknown"

TS=$(date '+%Y-%m-%d %H:%M:%S')

# --- Collect-then-contain: record evidence BEFORE any action ---------------
{
  echo "[$TS] sudo-abuse-response: triggered for user='$SRCUSER'"
  echo "[$TS]   active sessions:"
  who | sed 's/^/[evidence] /'
  echo "[$TS]   recent auth (tail):"
  tail -n 5 /var/log/auth.log 2>/dev/null | sed 's/^/[evidence] /'
} >> "$LOG" 2>&1

# --- Decide on containment -------------------------------------------------
if [ "$LOCK_ACCOUNT" -eq 1 ]; then
  if echo " $PROTECTED " | grep -q " $SRCUSER "; then
    echo "[$TS]   SKIP lock: '$SRCUSER' is protected" >> "$LOG"
  elif id "$SRCUSER" >/dev/null 2>&1; then
    passwd -l "$SRCUSER" >/dev/null 2>&1 \
      && echo "[$TS]   ACTION: locked account '$SRCUSER'" >> "$LOG" \
      || echo "[$TS]   ERROR: failed to lock '$SRCUSER'" >> "$LOG"
  else
    echo "[$TS]   SKIP lock: user '$SRCUSER' not found" >> "$LOG"
  fi
else
  echo "[$TS]   LOG-ONLY mode (LOCK_ACCOUNT=0); no account locked" >> "$LOG"
fi

exit 0
