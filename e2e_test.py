#!/usr/bin/env python3
# End-to-end test suite for vmonitor: builds the current source, runs real
# client/server processes against each other over loopback UDP, and asserts
# on their log output. Some cases route one link through a lossy relay (a
# small UDP proxy with a runtime-adjustable drop probability) to simulate a
# dead or degraded link without restarting vmonitor.
#
# Usage: ./e2e_test.py [--keep] [--only NAME,...]

import argparse
import random
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOCALHOST = "127.0.0.1"
SECRET = "e2e-test-secret-key-not-for-prod"

CONFIG_TEMPLATE = """[vmonitor]
link1_server = {link1_server}
link2_server = {link2_server}
link1_client = {link1_client}
link2_client = {link2_client}

pingavg = {pingavg}
pingvar = {pingvar}
timeout = {timeout}
ctimeout = {ctimeout}
debounce = {debounce}
hysteresis = {hysteresis}
heartbeat = {heartbeat}

slo_pct = {slo_pct}
slo_window = {slo_window}

initial_hysteresis = {initial_hysteresis}

link1_link2_script = None
link2_script = None
link1_script = None
nolink_script = None

hard_heartbeat = {hard_heartbeat}

secret = {secret}

loglevel = 3
"""

DEFAULTS = dict(
    pingavg=2, pingvar=1, timeout=6, ctimeout=8, debounce=2,
    hysteresis=15, heartbeat=30, initial_hysteresis=1,
    slo_pct=0, slo_window=0, hard_heartbeat=0, secret=SECRET,
)


class TestFailure(Exception):
    pass


def build_binary(tmpdir: Path) -> Path:
    binpath = tmpdir / "vmonitor_e2e"
    subprocess.run(["go", "build", "-o", str(binpath), "."], cwd=ROOT, check=True)
    return binpath


def write_config(path: Path, **overrides) -> None:
    cfg = dict(DEFAULTS, **overrides)
    path.write_text(CONFIG_TEMPLATE.format(**cfg))


class LossyRelay(threading.Thread):
    # Forwards UDP traffic between whoever first talks to us and
    # target_addr, dropping packets with probability drop_pct (adjustable
    # at runtime by the test, so a link can be degraded and healed again
    # without restarting vmonitor).
    def __init__(self, listen_port: int, target_port: int):
        super().__init__(daemon=True)
        self.target_addr = (LOCALHOST, target_port)
        self.drop_pct = 0.0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((LOCALHOST, listen_port))
        self._sock.settimeout(0.5)
        self._peer_addr = None
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if addr == self.target_addr:
                dest = self._peer_addr
            else:
                self._peer_addr = addr
                dest = self.target_addr
            if dest is None or random.random() < self.drop_pct:
                continue
            try:
                self._sock.sendto(data, dest)
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        self._sock.close()
        self.join(timeout=2)


class VMonitorProcess:
    def __init__(self, binpath: Path, config_path: Path, persona: str, log_path: Path):
        self.log_path = log_path
        self._log_file = open(log_path, "w")
        self.proc = subprocess.Popen(
            [str(binpath), str(config_path), persona],
            stdout=self._log_file, stderr=subprocess.STDOUT,
        )

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self._log_file.close()

    def text(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except FileNotFoundError:
            return ""


def wait_until(predicate, timeout: float, interval: float = 0.25) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def wait_for_applied_state(proc: VMonitorProcess, state: str, timeout: float, since_len: int = 0) -> bool:
    # since_len restricts the search to log content appended after a given
    # offset, to skip a stale match from an earlier phase (e.g. baseline
    # LINK1_LINK2 before a later recovery to LINK1_LINK2). Callers must
    # snapshot that offset at the causally correct point themselves -- right
    # when the *preceding* phase completed -- rather than here, since the
    # target event can legitimately race ahead of this call.
    pattern = f"New state applied: {state}"
    if not wait_until(lambda: pattern in proc.text()[since_len:], timeout):
        return False
    # Give it a moment to settle and confirm it didn't immediately flap away.
    time.sleep(1.0)
    return current_state(proc) == state


STATE_LINE_RE = re.compile(
    r"^State (\S+) to1 (\d+)/(\d+) to2 (\d+)/(\d+) hys (\d+)", re.M
)


def current_state(proc: VMonitorProcess):
    matches = STATE_LINE_RE.findall(proc.text())
    return matches[-1][0] if matches else None


def min_sli(proc: VMonitorProcess, link: int):
    vals = [float(v) for v in re.findall(rf"sli{link} ([0-9.]+)%", proc.text())]
    return min(vals) if vals else None


def remaining_at_last_applied(proc: VMonitorProcess, state: str):
    # Returns (to1, cto1, to2, cto2) remaining seconds from the last State
    # line before "New state applied: <state>", to check whether the
    # transition happened while the old-style timeout/ctimeout timers were
    # still alive (i.e. it must have been the SLO/SLI check that fired).
    lines = proc.text().splitlines()
    target = f"New state applied: {state}"
    for i, line in enumerate(lines):
        if line == target:
            for j in range(i - 1, -1, -1):
                m = STATE_LINE_RE.match(lines[j])
                if m:
                    return tuple(int(x) for x in m.groups()[1:5])
    return None


def case_basic_connectivity(binpath: Path, workdir: Path) -> str:
    base = 57100
    cfg = dict(
        link1_server=f"{LOCALHOST}:{base}", link2_server=f"{LOCALHOST}:{base+1}",
        link1_client=f"{LOCALHOST}:{base+2}", link2_client=f"{LOCALHOST}:{base+3}",
    )
    server_cfg = workdir / "a_server.txt"
    client_cfg = workdir / "a_client.txt"
    write_config(server_cfg, **cfg)
    write_config(client_cfg, **cfg)

    server = VMonitorProcess(binpath, server_cfg, "server", workdir / "a_server.log")
    client = VMonitorProcess(binpath, client_cfg, "client", workdir / "a_client.log")
    try:
        if not wait_for_applied_state(client, "LINK1_LINK2", 20):
            raise TestFailure(f"client never reached LINK1_LINK2 (last state: {current_state(client)})")
        if not wait_for_applied_state(server, "LINK1_LINK2", 20):
            raise TestFailure(f"server never reached LINK1_LINK2 (last state: {current_state(server)})")
    finally:
        client.stop()
        server.stop()
    return "both sides reached LINK1_LINK2"


def case_hard_failure_and_recovery(binpath: Path, workdir: Path) -> str:
    base = 57110
    relay_port = base + 9
    real_link1_server = base
    cfg = dict(
        link1_server=f"{LOCALHOST}:{relay_port}", link2_server=f"{LOCALHOST}:{base+1}",
        link1_client=f"{LOCALHOST}:{base+2}", link2_client=f"{LOCALHOST}:{base+3}",
    )
    server_cfg_values = dict(cfg, link1_server=f"{LOCALHOST}:{real_link1_server}")
    server_cfg = workdir / "b_server.txt"
    client_cfg = workdir / "b_client.txt"
    write_config(server_cfg, **server_cfg_values)
    write_config(client_cfg, **cfg)

    relay = LossyRelay(relay_port, real_link1_server)
    relay.start()
    server = VMonitorProcess(binpath, server_cfg, "server", workdir / "b_server.log")
    client = VMonitorProcess(binpath, client_cfg, "client", workdir / "b_client.log")
    try:
        if not wait_for_applied_state(client, "LINK1_LINK2", 20):
            raise TestFailure(f"never reached LINK1_LINK2 baseline (last state: {current_state(client)})")

        relay.drop_pct = 1.0
        if not wait_for_applied_state(client, "LINK2", 35):
            raise TestFailure(f"link1 outage not detected via timeout/ctimeout (last state: {current_state(client)})")
        since_recovery = len(client.text())

        relay.drop_pct = 0.0
        if not wait_for_applied_state(client, "LINK1_LINK2", 40, since_len=since_recovery):
            raise TestFailure(f"did not recover to LINK1_LINK2 after restoring link1 (last state: {current_state(client)})")
    finally:
        client.stop()
        server.stop()
        relay.stop()
    return "legacy timeout/ctimeout mechanism: outage and recovery detected correctly"


def case_slo_degraded_link(binpath: Path, workdir: Path) -> str:
    base = 57130
    relay_port = base + 9
    real_link1_server = base
    # timeout/ctimeout are set comfortably longer than the ~20-25s the SLI
    # is expected to take to cross the slo_pct threshold under sustained
    # loss, so they provably cannot be what triggers the LINK2 state below
    # -- confirmed directly via remaining_at_last_applied() further down,
    # not just by picking generous values. hysteresis must be > timeout.
    cfg = dict(
        link1_server=f"{LOCALHOST}:{relay_port}", link2_server=f"{LOCALHOST}:{base+1}",
        link1_client=f"{LOCALHOST}:{base+2}", link2_client=f"{LOCALHOST}:{base+3}",
        timeout=30, ctimeout=35, hysteresis=32, slo_pct=90, slo_window=210,
    )
    server_cfg_values = dict(cfg, link1_server=f"{LOCALHOST}:{real_link1_server}")
    server_cfg = workdir / "c_server.txt"
    client_cfg = workdir / "c_client.txt"
    write_config(server_cfg, **server_cfg_values)
    write_config(client_cfg, **cfg)

    relay = LossyRelay(relay_port, real_link1_server)
    relay.start()
    server = VMonitorProcess(binpath, server_cfg, "server", workdir / "c_server.log")
    client = VMonitorProcess(binpath, client_cfg, "client", workdir / "c_client.log")
    try:
        if not wait_for_applied_state(client, "LINK1_LINK2", 20):
            raise TestFailure(f"never reached LINK1_LINK2 baseline (last state: {current_state(client)})")

        relay.drop_pct = 0.6
        if not wait_for_applied_state(client, "LINK2", 90):
            raise TestFailure(f"sustained 60% loss on link1 never tripped the SLO check (last state: {current_state(client)})")

        remaining = remaining_at_last_applied(client, "LINK2")
        if remaining is None:
            raise TestFailure("could not find the State line preceding the LINK2 transition")
        to1, cto1, _, _ = remaining
        if to1 <= 0 or cto1 <= 0:
            raise TestFailure(
                f"link1 was marked down with to1={to1} cto1={cto1}: looks like a timeout, not an SLO trip"
            )

        sli2_floor = min_sli(client, 2)
        if sli2_floor is None or sli2_floor < 90.0:
            raise TestFailure(f"link2's SLI was affected by link1's loss (min sli2={sli2_floor})")
        since_recovery = len(client.text())

        relay.drop_pct = 0.0
        if not wait_for_applied_state(client, "LINK1_LINK2", 150, since_len=since_recovery):
            raise TestFailure(f"did not recover to LINK1_LINK2 after restoring link1 (last state: {current_state(client)})")
    finally:
        client.stop()
        server.stop()
        relay.stop()
    return f"SLO-only trip confirmed (to1={to1}s cto1={cto1}s still alive), link2 unaffected (min sli2={sli2_floor:.1f}%), recovered"


CASES = [
    ("basic_connectivity", case_basic_connectivity),
    ("hard_failure_and_recovery", case_hard_failure_and_recovery),
    ("slo_degraded_link", case_slo_degraded_link),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the temp workdir (configs/logs) for debugging")
    parser.add_argument("--only", help="comma-separated list of case names to run")
    parser.add_argument(
        "--retries", type=int, default=1,
        help="extra attempts for a case that fails, to absorb real-world timing jitter (default: 1)",
    )
    args = parser.parse_args()

    names = {n for n, _ in CASES}
    selected = CASES
    if args.only:
        wanted = set(args.only.split(","))
        unknown = wanted - names
        if unknown:
            print(f"unknown case(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            print(f"available: {', '.join(sorted(names))}", file=sys.stderr)
            sys.exit(2)
        selected = [(n, f) for n, f in CASES if n in wanted]

    workdir = Path(tempfile.mkdtemp(prefix="vmonitor_e2e_"))
    print(f"workdir: {workdir}")
    binpath = build_binary(workdir)

    results = []
    for name, fn in selected:
        outcome = None
        for attempt in range(1, args.retries + 2):
            label = f"{name} (attempt {attempt})" if attempt > 1 else name
            print(f"\n=== {label} ===")
            start = time.monotonic()
            try:
                detail = fn(binpath, workdir)
                elapsed = time.monotonic() - start
                print(f"PASS ({elapsed:.1f}s): {detail}")
                outcome = (name, True, detail)
                break
            except TestFailure as e:
                elapsed = time.monotonic() - start
                print(f"FAIL ({elapsed:.1f}s): {e}")
                outcome = (name, False, str(e))
            except Exception as e:
                elapsed = time.monotonic() - start
                print(f"ERROR ({elapsed:.1f}s): {e!r}")
                outcome = (name, False, repr(e))
        results.append(outcome)

    print("\n=== summary ===")
    ok = True
    for name, passed, detail in results:
        print(f"{'PASS' if passed else 'FAIL'}  {name}")
        ok = ok and passed

    if args.keep:
        print(f"\nlogs kept at: {workdir}")
    else:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
