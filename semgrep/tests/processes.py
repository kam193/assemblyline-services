import os
import signal
import threading
from collections import defaultdict
from contextlib import suppress


def _children_by_parent():
    children = defaultdict(list)
    for entry in filter(str.isdigit, os.listdir("/proc")):
        with suppress(OSError):
            with open(f"/proc/{entry}/stat") as f:
                ppid = int(f.read().rsplit(")", 1)[1].split()[1])
            children[ppid].append(int(entry))
    return children


def descendants(pid):
    children = _children_by_parent()
    found, pending = [], [pid]
    while pending:
        current = pending.pop()
        found.append(current)
        pending.extend(children[current])
    return found


def is_running(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def kill_all(pids):
    for pid in pids:
        with suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


def run_within(func, seconds):
    outcome = {}

    def target():
        try:
            func()
        except Exception as e:
            outcome["error"] = e

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(seconds)
    return not thread.is_alive(), outcome.get("error")
