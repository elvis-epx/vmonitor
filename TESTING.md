# Testing vmonitor

vmonitor has no unit tests. Its behaviour depends on real timers, real UDP
sockets, and the interaction between a client and a server, so it is tested
end-to-end by `e2e_test.py`: the script runs the actual binary as a client and
a server on loopback and checks what they write to their logs.

## Running it

```
./e2e_test.py                      # all cases, about 6-7 minutes
make e2e                           # same thing
./e2e_test.py --only slo_degraded_link
./e2e_test.py --only basic_connectivity,hard_failure_and_recovery
./e2e_test.py --keep               # keep configs and logs for inspection
./e2e_test.py --retries 0          # fail on the first attempt (default: 1 retry)
```

Requirements: Go (the script builds the current source itself with
`go build`) and Python 3 with only the standard library. Nothing needs to be
installed or configured, and no root privileges are needed.

The exit code is 0 when every case passes. A summary is printed at the end:

```
=== summary ===
PASS  basic_connectivity
PASS  hard_failure_and_recovery
PASS  slo_degraded_link
PASS  slo_report_script
```

## How a test case is set up

Each case does the following:

1. **Build.** At startup, the script compiles the source into a temporary
   working directory (`/tmp/vmonitor_e2e_*` or similar). All cases share this
   one binary.
2. **Write two config files**, one for the server and one for the client, from
   `CONFIG_TEMPLATE`, using the values in `DEFAULTS` plus the case's own
   overrides. The defaults use short timings (pingavg 2s, timeout 6s,
   hysteresis 15s, ...) so cases finish in seconds or minutes. All state
   scripts are `None`, and `loglevel` is 3 so every event is logged.
3. **Start the processes.** `vmonitor <config> server` and
   `vmonitor <config> client` run as real subprocesses. Their stdout/stderr
   goes to `<case>_server.log` and `<case>_client.log` in the working
   directory.
4. **Observe the logs.** The script polls the client log until an expected
   state appears or a deadline passes.
5. **Tear down.** It stops both processes and the relay, even if the case
   failed.

### Simulating a bad link: `LossyRelay`

To break or degrade a link without touching the network configuration, some
cases put a small UDP proxy in front of link1:

```
  client (link1_client) ──► relay (link1_server port + 9) ──► server (real link1_server)
                       ◄──                                ◄──
```

- The **client** config sets `link1_server` to the relay port, so the client
  thinks the relay is the server.
- The **server** config binds the real `link1_server` port.
- The relay forwards packets in both directions and drops each one with
  probability `relay.drop_pct`. The test can change that value at any time,
  e.g. `relay.drop_pct = 1.0` for a dead link or `0.6` for a degraded one,
  and set it back to `0.0` to heal the link, all without restarting vmonitor.

Because packets are dropped in both directions, a round trip succeeds with
probability `(1 - drop_pct)²`. At `drop_pct = 0.6`, only 16% of exchanges
succeed.

Link2 never goes through the relay. It is the **control link**: whatever is
done to link1, link2 has to stay healthy, which shows that the two links are
monitored independently.

### Ports

Each case uses its own block of loopback UDP ports, so a leftover process from
one case can't interfere with another:

| Case | Ports |
|---|---|
| basic_connectivity | 57100–57103 |
| hard_failure_and_recovery | 57110–57113, relay 57119 |
| slo_degraded_link | 57130–57133, relay 57139 |
| slo_report_script | 57140–57143, relay 57149 |

Use a new block (e.g. 57150) for a new case.

## The test cases

### `basic_connectivity` (about 6s)

Starts a client and a server with no relay and checks that both reach
`LINK1_LINK2`. This is a smoke test: if it fails, nothing else will work
either (build problem, port in use, protocol or HMAC broken).

### `hard_failure_and_recovery` (about 40s)

Tests the original, non-SLO detection (`timeout` / `ctimeout`):

1. Wait for the `LINK1_LINK2` baseline.
2. Drop 100% of link1 packets and expect `LINK2` once the timeouts expire.
3. Restore link1 and expect `LINK1_LINK2` again.

SLO is disabled here (`slo_pct = 0`).

### `slo_degraded_link` (about 3.5 minutes)

Tests SLO-based detection: a link that still passes some traffic, but too
little. It uses `slo_pct = 90` and `slo_window = 210`.

1. Wait for the `LINK1_LINK2` baseline.
2. Drop 60% of link1 packets and expect `LINK2`.
3. **Check that it was the SLO that took link1 down**, not a timeout. The case
   sets `timeout`/`ctimeout` (30s/35s) much longer than SLI needs to fall
   below 90%. It then reads the last `State` log line before the transition
   and checks that link1's `to1`/`cto1` timers still had time left.
4. **Check that link2 was not affected**: its lowest SLI during the test must
   stay ≥ 90%.
5. Restore link1 and expect `LINK1_LINK2`.
6. **Check the recovery threshold.** A link taken down by SLO only comes back
   once its SLI reaches `slo_up`, halfway between `slo_pct` and 100% (95% in
   this case; see the README). The case looks for log lines where link1 was
   still down, the hysteresis timer had expired, and SLI was already ≥ 90%.
   Those lines show the link being held down by the recovery threshold. It
   also checks for the `recovered above 95.0%` log line.

This is the slowest case because SLI is a moving average: falling below 90%
under loss and climbing back to 95% each take on the order of
`slo_window`.

### `slo_report_script` (about 2 minutes)

Tests `slo_report_script`, which vmonitor runs every 60 seconds with the
current SLI of each link as arguments (`script <sli1> <sli2>`). This period is
hard-coded, which is why the case takes at least two minutes.

The case installs a small script that appends its arguments to a file. Only
the client's config sets it, so the server's reports don't mix into the same
file.

1. Wait for the first report and check that both SLIs are ≥ 90%.
2. Drop 100% of link1 packets.
3. Wait for the next report and check that link1's SLI went down while
   link2's stayed ≥ 90%.

## What the script reads from the logs

The cases only check vmonitor's log output, so they depend on its exact
wording. **If you change one of these log messages in `vmonitor.go`, update
`e2e_test.py` too**, or the tests will fail or, worse, pass without checking
anything:

| Log line | Used for |
|---|---|
| `New state applied: <STATE>` | detecting state transitions (`wait_for_applied_state`) |
| `State <STATE> to1 <a>/<b> to2 <c>/<d> hys <n> sli1 <x>% sli2 <y>% event <e>` | current state, remaining timers, SLI values (`STATE_LINE_RE`, `min_sli`, `remaining_at_last_applied`, `held_down_above_slo`) |
| `Link 1 SLI ... recovered above 95.0%` | SLO recovery threshold check |

`State` lines are only written at `loglevel` 3, which is what the test
configs use.

## Debugging a failure

- **Run the failing case alone, with `--keep`:**
  `./e2e_test.py --only slo_degraded_link --retries 0 --keep`.
  The script prints the working directory, which contains the generated
  configs (`c_client.txt`, `c_server.txt`) and logs (`c_client.log`,
  `c_server.log`). The letter is the case's prefix: a = basic, b = hard
  failure, c = SLO degraded, d = SLO report.
- **Useful greps on a client log:**
  ```
  grep -E "New state|debounce|Link 1 SLI" c_client.log      # transitions
  grep "^State" c_client.log | awk '{print $2, $10, $12}'   # state, sli1, sli2
  ```
- **Timing jitter.** These tests run in real time on a real OS, and a busy
  machine can delay timers enough to make a case fail. `--retries 1` (the
  default) absorbs most of this. A case that fails within a few seconds of
  starting, before any loss is induced, is usually environmental (a port
  still in use, slow startup) rather than a vmonitor bug. Run it again alone
  before investigating.

### Things that look like bugs but aren't

- **The SLO trips well below `slo_pct`.** While the `hysteresis` timer is
  running, vmonitor doesn't evaluate link state at all, so SLI can sink well
  below `slo_pct` (e.g. to 77%) before the check runs.
- **A `State LINK2 ... sli1 95.1%` line appears just before recovery.** The
  `State` line is logged *before* the SLO check runs for that same event, so
  the last LINK2 line can show the value that triggers recovery.
- **The state is still LINK2 after `recovered above` is logged.** The
  `debounce` timer still has to expire before the new state is applied.

## Adding a test case

1. Write a `case_<name>(binpath, workdir) -> str` function. It returns a
   short summary when the case passes and raises `TestFailure` when it
   fails.
2. Give it its own port block and a unique log/config file prefix.
3. Copy the structure of an existing case: build `cfg`, derive the
   server/client values (with a relay if needed), start the processes, and put
   the assertions inside `try:` with all teardown in `finally:`.
4. Wait for conditions with `wait_until` / `wait_for_applied_state` instead
   of fixed sleeps. When a case goes through several phases, pass
   `since_len=len(client.text())` so that an earlier phase's log line doesn't
   satisfy a later wait.
5. Add the case to the `CASES` list.
