# Interactive root Bash supplement: PS0 records input, PROMPT_COMMAND its result.
# Auditd remains independent of these removable shell hooks.
[ -n "${BASH_VERSION:-}" ] || return 0
[[ $- == *i* && $EUID == 0 ]] || return 0
[[ ${__incidentsim_hook_loaded:-} != 1 ]] || return 0
__incidentsim_hook_loaded=1

# Include commands beginning with spaces and repeated commands in this session.
HISTCONTROL=
HISTIGNORE=
set -o history
__incidentsim_last_finished=
__incidentsim_prompt_ready=0

__incidentsim_preexec() {
  /usr/local/sbin/incident-audit shell --phase start \
    --history "$(HISTTIMEFORMAT= builtin history 1)" \
    --shell-pid "$$" --cwd "$PWD" --tty "${SSH_TTY:-}" \
    </dev/null 2>/dev/null || true
}

__incidentsim_prompt() {
  local command_status=$? entry
  entry=$(HISTTIMEFORMAT= builtin history 1)
  # The hook's own installation changes history before the first prompt.
  if [[ $__incidentsim_prompt_ready != 1 ]]; then
    __incidentsim_last_finished=$entry
    __incidentsim_prompt_ready=1
    return "$command_status"
  fi
  if [[ $entry != "$__incidentsim_last_finished" ]]; then
    /usr/local/sbin/incident-audit shell --phase finish \
      --history "$entry" --status "$command_status" \
      --shell-pid "$$" --cwd "$PWD" --tty "${SSH_TTY:-}" \
      </dev/null 2>/dev/null || true
    __incidentsim_last_finished=$entry
  fi
  return "$command_status"
}

PS0='$(__incidentsim_preexec)'"${PS0:-}"
if [[ ${PROMPT_COMMAND@a} == *a* ]]; then
  PROMPT_COMMAND=(__incidentsim_prompt "${PROMPT_COMMAND[@]}")
else
  PROMPT_COMMAND=(__incidentsim_prompt "${PROMPT_COMMAND:-}")
fi
