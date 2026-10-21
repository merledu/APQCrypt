"""
Debug event log (the data behind the Debug page).

Each processing step writes small structured events, one JSON object per line, to
data/debug_events.jsonl:   {"seq":12,"ts":1760000000.1,"stage":"sensitivity","level":"info","msg":"...","data":{...}}
The Debug page reads them with /api/debug/events.
"""
import contextlib
import json
import os
import threading
import time

EVENTS_FILE = "data/debug_events.jsonl"
MAX_BYTES = 4_000_000
_lock = threading.Lock()
_state = {"seq": None, "enabled": True}


def _last_seq():
    try:
        last = 0
        with open(EVENTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    last = json.loads(line).get("seq", last)
                except ValueError:
                    pass
        return last
    except OSError:
        return 0


def clear():
    with _lock:
        os.makedirs(os.path.dirname(EVENTS_FILE) or ".", exist_ok=True)
        open(EVENTS_FILE, "w").close()
        _state["seq"] = 0


def log(stage, msg, level="info", **data):
    if not _state["enabled"]:
        return
    with _lock:
        try:
            os.makedirs(os.path.dirname(EVENTS_FILE) or ".", exist_ok=True)
            if _state["seq"] is None:
                _state["seq"] = _last_seq()
            if os.path.exists(EVENTS_FILE) and os.path.getsize(EVENTS_FILE) > MAX_BYTES:
                with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                    keep = f.readlines()[-2000:]
                with open(EVENTS_FILE, "w", encoding="utf-8") as f:
                    f.writelines(keep)
            _state["seq"] += 1
            rec = {"seq": _state["seq"], "ts": round(time.time(), 3), "stage": stage, "level": level, "msg": msg, "data": data}
            with open(EVENTS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, default=str) + "\n")
        except Exception:
            pass          # debugging must never break the pipeline


def read(since=0, stage=None, level=None, limit=500):
    out = []
    try:
        with open(EVENTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get("seq", 0) <= since:
                    continue
                if stage and r.get("stage") != stage:
                    continue
                if level and r.get("level") != level:
                    continue
                out.append(r)
    except OSError:
        return []
    return out[-limit:]


@contextlib.contextmanager
def suspended():
    """Temporarily stop writing events (used by the comparison and the API jobs)."""
    old = _state["enabled"]
    _state["enabled"] = False
    try:
        yield
    finally:
        _state["enabled"] = old
