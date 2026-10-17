"""
core/ssh_utils.py — shared SSH subprocess helper.

Factored out of telemetry/broadband_adapter.py so both the Fixed
Broadband domain's telemetry adapter (is_connected()'s own health check)
and its mitigation backend (mitigation/broadband_mitigator.py — accel-cmd,
FreeRADIUS reject markers, the suscriptor kick) can issue SSH commands
without either module importing from the other.
"""
import shlex
import subprocess

from eventlet import tpool

_SSH_TIMEOUT_S = 10


def run_ssh(user: str, host: str, args: list, timeout: int = _SSH_TIMEOUT_S,
            input_text: str = None) -> subprocess.CompletedProcess:
    """Same BatchMode/accept-new convention as the former lab tooling
    _ssh_br -- see that function's docstring.

    shlex.join(args), NOT *args -- confirmed on a real run: the ssh
    CLIENT itself concatenates every argument after user@host with a
    single plain space to build the command line it sends to the
    remote shell, with NO extra quoting of its own. Passing
    ["sudo", "-n", "sh", "-c", script] as separate argv elements (as
    this used to) works fine for a plain multi-word command, but the
    moment `script` itself contains shell metacharacters (quotes, `|`,
    `;`, `$(...)`  -- any inline `sh -c` script), the remote shell parses ONLY script's first word as -c's
    actual argument and treats the rest as separate, unrelated words on
    the OUTER login shell's own command line -- broken syntax, or at
    best silently wrong behavior, with no error surfaced anywhere (this
    module's callers degrade a failed SSH call to a quiet return, so
    this was invisible until traced by hand against a live run).
    shlex.join() re-quotes the whole args list into ONE shell-safe
    string first, so ssh's own space-joining (a no-op on a single
    already-complete argv element) can't split it apart again.

    tpool.execute(), NOT a direct call -- confirmed on a real run:
    ryu-manager's whole process is one eventlet-cooperative reactor
    (its own startup warning, "1 RLock(s) were not greened", is the
    tell), and subprocess.run() is a genuinely blocking OS-level call
    (fork/exec/waitpid) that eventlet's monkey-patching does not make
    cooperative the way it does plain sockets. A single slow/stuck SSH
    call (observed: minutes, once even ~6.5 hours behind a large nfdump
    backlog on a different domain) freezes the ENTIRE controller --
    every domain's collect()/detect()/mitigate(), not just this one's --
    since nothing yields back to the reactor until it returns.
    tpool.execute() runs the call in a real OS thread from eventlet's
    own thread pool instead, so the reactor keeps servicing every other
    greenthread while this blocks.

    ControlMaster/ControlPersist -- confirmed on a real run: a bare SSH
    call here costs ~0.5s just for the fresh TCP+key-exchange+auth
    handshake, every single time, since this runs on EVERY collect()
    cycle (COLLECT_INTERVAL, nominally 0.5s). That's the dominant cost
    behind this domain's real-world cycle time being ~6x its nominal
    interval, which directly inflates UNBLOCK_CONFIRM_CYCLES's wall-clock
    duration (orchestration/controller.py) -- measured ~5min for a
    recovery that should only need ~50s at the nominal interval. Reusing
    one multiplexed connection (opened once, kept warm for
    ControlPersist seconds) turns every subsequent call here into a
    single round-trip over an already-authenticated session -- tens of
    ms instead of ~0.5s. /run is root-writable and cleared on reboot,
    matching this socket's own lifetime (this process runs as root via
    systemd). %C is ssh's own hash of user/host/port -- keeps the path
    short and collision-free without hand-rolling one per call site."""
    return tpool.execute(
        subprocess.run,
        ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={min(timeout, 5)}",
         "-o", "StrictHostKeyChecking=accept-new",
         "-o", "ControlMaster=auto", "-o", "ControlPersist=600",
         "-o", "ControlPath=/run/ssh-mux-%C",
         f"{user}@{host}", shlex.join(args)],
        input=input_text, capture_output=True, text=True, timeout=timeout,
    )
