# vmonitor

A dual-link monitor written in Go. A client and a server exchange
HMAC-authenticated UDP pings over two links, and each side runs a script when
the set of working links changes (LINK1_LINK2, LINK1, LINK2, NOLINK). See
README.md for the configuration and the algorithm.

## Layout

- `vmonitor.go`: the whole program: config parsing and validation
  (`parse()`), protocol, and the main event loop in `main()`.
- `goalarmeitbl/`: a small timer and UDP server library that turns timer
  expiries and received packets into events on one channel.
- `e2e_test.py`: end-to-end tests. See TESTING.md.
- `builds/`: cross-compiled Linux binaries, committed to the repo
  (`make` rebuilds them).

## Build and test

```
go build -o vmonitor .
./e2e_test.py                      # about 6-7 minutes, real time
./e2e_test.py --only <case> --keep
```

There are no unit tests. Verify behaviour changes with `e2e_test.py` and run
the relevant case after changing any detection logic. TESTING.md explains
what each case does and how to debug failures.

## Things to know before changing code

- **Log messages are part of the test contract.** `e2e_test.py` parses
  `New state applied: ...`, the loglevel-3 `State ...` line, and the
  `Link N SLI ...` lines. If you change their wording, update the test too.
  TESTING.md lists the exact formats.
- **Two ways a link goes down:** no packets or no challenge response within
  `timeout`/`ctimeout`, or (if `slo_pct > 0`) its SLI, an EWMA of exchange
  success, falling below `slo_pct`. After an SLO trip, the link only comes
  back at `slo_up = slo + (1 - slo) / 2`.
- **Event loop order:** link state is only evaluated after the `hysteresis`
  timer has expired, and a new state is only applied after `debounce`.
- **In SLO mode the server only replies:** it sends a packet only in response
  to a received one, and its `send1`/`send2` timers just decay the SLI when an
  expected packet didn't arrive.
- **Code style:** 4-space indentation and snake_case, not gofmt style. Match
  the surrounding code and don't reformat files.
