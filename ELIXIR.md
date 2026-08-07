# A tour of exmonitor's Elixir source, for Elixir newcomers

This walks through `mix.exs` and every file under `lib/exmonitor/`, in the
order you'd naturally read them (small helpers first, then the pieces that
use them), explaining both *what the code does* and *which Elixir concept
it's demonstrating*. It assumes you're comfortable with the `vmonitor`
(Python) / `gomonitor` (Go) implementations already and are looking for a
"what's different / what's this syntax" guide, not a full language course.

## A few concepts you'll see everywhere first

- **Everything is immutable.** There are no mutating methods — `state.foo =
  bar` doesn't exist. Instead you always build a *new* value:
  `%{state | current_state: new_state}` returns a new struct with one field
  changed; the old one is untouched. This shows up constantly.
- **Atoms** (`:ok`, `:error`, `:client`, `:to1`) are like symbols/enum
  constants — cheap, self-documenting tags. Functions conventionally return
  `{:ok, value}` or `{:error, reason}` tuples instead of raising exceptions
  or using error codes.
- **Pattern matching** replaces a lot of `if`/`switch`. `def foo({:ok, x})`
  and `def foo({:error, _})` can be two separate function clauses; `case`
  and `with` destructure tuples directly.
- **The pipe `|>`** takes the expression on the left and inserts it as the
  first argument of the call on the right: `a |> f(b)` is just `f(a, b)`.
  It's used to chain transformations top-to-bottom instead of nesting.
- **`with`** chains a sequence of pattern-matches; the moment one fails to
  match, it bails out (optionally to an `else`). It's the idiomatic
  replacement for a pyramid of nested `if`/`case` for "do A, then B, then
  C, stop on first failure."

## `mix.exs` — the project manifest

Elixir's equivalent of `go.mod` / `setup.py`:

```elixir
defmodule Exmonitor.MixProject do
  use Mix.Project

  def project do
    [
      app: :exmonitor,
      version: "0.1.0",
      elixir: "~> 1.14",
      escript: [main_module: Exmonitor.CLI],
      deps: []
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end
end
```

`escript: [main_module: Exmonitor.CLI]` tells `mix escript.build` to produce
a single self-contained executable (like `go build`) whose entry point is
`Exmonitor.CLI.main/1`. `extra_applications: [:crypto, :logger]` declares
that the built-in OTP crypto library (used for HMAC) and the logger need to
be started — Elixir apps are assembled from composable OTP "applications,"
and you have to say which ones you depend on.

## `lib/exmonitor/timer.ex` — a restartable one-shot timer

This replaces Go's `Timeout` struct. The core primitive is
`Process.send_after(pid, message, ms)` — OTP's version of `time.AfterFunc`:
after `ms` milliseconds, `message` gets delivered to that process's
mailbox. No threads, no explicit locking.

```elixir
defstruct [:key, :tag, :ref, :ms, :eta, :alive]

def new(key, ms) do
  tag = make_ref()
  ref = Process.send_after(self(), {:timer, key, tag}, ms)
  %__MODULE__{key: key, tag: tag, ref: ref, ms: ms, eta: now_ms() + ms, alive: true}
end
```

`defstruct` declares a typed record — like a Go struct or a Python
dataclass. `%__MODULE__{...}` constructs one; `__MODULE__` just means "this
module" (`Exmonitor.Timer`), which makes the code easy to copy-paste
between modules without renaming.

The interesting design point is the `tag` field: timers get cancelled and
restarted a lot (every good ping response restarts a timeout), and
`Process.cancel_timer` can't yank back a message that's already landed in
the mailbox. So each `new/2` call stamps a fresh unique reference
(`make_ref()`) into the message. When a `{:timer, key, tag}` message
arrives later, the code checks the tag still matches the *current* timer
before treating it as real (see the Engine section below) — stale
duplicate messages are silently ignored. This is a standard OTP pattern
for debouncing timers.

```elixir
def restart(%__MODULE__{} = timer), do: restart(timer, timer.ms)

def restart(%__MODULE__{key: key, ref: ref}, ms) do
  if ref, do: Process.cancel_timer(ref)
  new(key, ms)
end

def alive?(%__MODULE__{alive: alive}), do: alive
def alive?(nil), do: false

def remaining(%__MODULE__{alive: false}), do: 0
def remaining(%__MODULE__{eta: eta}), do: max(0, div(eta - now_ms(), 1000))
def remaining(nil), do: 0
```

These are all examples of **multiple function heads**: instead of one
function body with `if`s inside, you write several `def name(pattern) do
... end` clauses and Elixir picks the first one whose pattern matches the
arguments, top to bottom. It's exhaustive pattern matching used as control
flow — e.g. `alive?/1` has one clause for a real `%Timer{}` struct and one
for `nil` (used when `hard_heartbeat` is disabled), instead of a null
check inside a single function body.

## `lib/exmonitor/packet.ex` — the wire codec

`gen/4` builds a packet:

```elixir
def gen(link, secret, challenge, response) do
  timestamp = Calendar.strftime(DateTime.utc_now(), "%Y-%m-%dT%H:%M:%S")
  data = "#{link} #{timestamp} #{challenge} #{response} "
  data <> hmac16(data, secret)
end
```

`Calendar.strftime` is built into Elixir (no dependency needed, unlike the
Go version's `go-strftime`). `"#{...}"` is string interpolation, and `<>`
is string concatenation.

`parse/3` is the more interesting one — a `case` on `String.split(data)`
matching the exact 5-field shape:

```elixir
def parse(link, secret, data) when is_binary(data) do
  case String.split(data) do
    [their_link_s, their_time, challenge, response, their_hmac] ->
      do_parse(link, secret, their_link_s, their_time, challenge, response, their_hmac)

    _ ->
      :error
  end
rescue
  _ -> :error
end
```

That pattern match does double duty as both "split it" and "verify there
are exactly 5 fields" — equivalent to Go's `len(data) != 5` check, but you
get it for free from the match failing to fit any other shape. The
trailing `rescue` clause is a safety net specifically because this data
comes from the network: `String.split` and the timestamp parser inside
`do_parse` assume well-formed input, and a hostile or corrupted UDP packet
could violate that and raise an exception. Anything unexpected here is
caught and turned into the normal `:error` return rather than crashing the
process.

`do_parse/7` is a `with` chain, and it maps directly onto the sequence of
checks in the Go/Python versions (valid link number → HMAC matches →
timestamp parses → clock skew within 120s):

```elixir
defp do_parse(link, secret, their_link_s, their_time, challenge, response, their_hmac) do
  with true <- their_link_s in ["1", "2"],
       {their_link, ""} <- Integer.parse(their_link_s),
       true <- their_link == link,
       tmp = "#{their_link_s} #{their_time} #{challenge} #{response} ",
       exp_hmac = hmac16(tmp, secret),
       true <- exp_hmac == their_hmac,
       {:ok, naive} <- NaiveDateTime.from_iso8601(their_time),
       their_dt = DateTime.from_naive!(naive, "Etc/UTC"),
       diff = DateTime.diff(DateTime.utc_now(), their_dt, :second),
       true <- abs(diff) <= @max_skew_seconds do
    {:ok, challenge, response}
  else
    _ -> :error
  end
end
```

Each `<-` line either matches (continue to the next) or falls through to
`else` and returns `:error` — so it reads like a checklist, with no nested
indentation pyramid. Plain `=` lines (`tmp = ...`, `their_dt = ...`) are
just intermediate values, not checks.

## `lib/exmonitor/config.ex` — the INI reader

Structurally the same idea as Go's `parse()`: read the file, extract
required fields, validate. `load/1` is one big `with` chain:

```elixir
def load(path) do
  with {:ok, content} <- read_file(path),
       {:ok, section} <- ini_section(content, "vmonitor"),
       {:ok, raw} <- collect_strings(section),
       {:ok, ip} <- collect_ints(section, @required_positive_ints, positive: true),
       {:ok, ni} <- collect_ints(section, @required_nonneg_ints, positive: false),
       :ok <- validate_secret(raw["secret"]),
       :ok <- validate_relations(ip, ni),
       :ok <- validate_distinct(raw),
       {:ok, server1} <- parse_addr(raw["link1_server"]),
       {:ok, server2} <- parse_addr(raw["link2_server"]),
       {:ok, client1} <- parse_addr(raw["link1_client"]),
       {:ok, client2} <- parse_addr(raw["link2_client"]) do
    {:ok, %__MODULE__{ secret: raw["secret"], ... }}
  end
end
```

Because every branch here already returns either `{:ok, x}` or `{:error,
msg}`, the `with` doesn't even need an `else` — a non-matching
`{:error, ...}` just gets returned directly, short-circuiting the rest of
the chain. This is what replaces the repeated
`if parseerr != "" { return }`-style early exits in the Go version.

The INI parser itself is hand-rolled, built on `Enum.reduce/3` —
Elixir's `fold`:

```elixir
defp ini_section(content, wanted) do
  {_current, sections} =
    content
    |> String.split(["\r\n", "\n"])
    |> Enum.reduce({nil, %{}}, &ini_line/2)

  case Map.fetch(sections, wanted) do
    {:ok, section} -> {:ok, section}
    :error -> {:error, "Config file has no [#{wanted}] section"}
  end
end
```

It walks each line, carrying an accumulator `{current_section_name,
%{section => %{key => value}}}`, updating it line by line via `ini_line/2`.
This is a very common Elixir shape: turn a list into a single value by
threading an accumulator through, instead of a mutable loop variable like
you'd use in Python or Go.

`collect_strings/1` and `collect_ints/3` use `Enum.reduce_while/3`
instead — same idea as `reduce`, but any step can return
`{:halt, result}` to stop early:

```elixir
defp collect_strings(section) do
  Enum.reduce_while(@required_strings, {:ok, %{}}, fn key, {:ok, acc} ->
    case Map.fetch(section, key) do
      {:ok, ""} -> {:halt, {:error, "Config file has empty item: #{key}"}}
      {:ok, v} -> {:cont, {:ok, Map.put(acc, key, v)}}
      :error -> {:halt, {:error, "Config file is missing item: #{key}"}}
    end
  end)
end
```

That's how "first missing/invalid field wins" (matching the Go behavior)
is expressed without a manual loop-with-break.

One thing worth resetting expectations on if you're coming from Python:

```elixir
@required_strings ~w(link1_server link2_server link1_client link2_client
                      secret link1_script link2_script link1_link2_script nolink_script)
```

`@required_strings` is a **module attribute** — a compile-time constant,
evaluated once and baked into the module, not a runtime instance attribute
like `self.foo` in Python. `~w(...)` is a "sigil" (a mini string-literal
syntax) that expands to a list of strings, one per whitespace-separated
word — shorthand for
`["link1_server", "link2_server", ...]`.

## `lib/exmonitor/engine.ex` — the event loop, and the actual OTP part

This is the one worth slowing down on, because it replaces the Go
version's goroutines + channel with something structurally different: a
single **GenServer**.

**The mental model**: a GenServer is a lightweight OTP process — not an OS
thread. Erlang/Elixir processes are cheap (you can spawn hundreds of
thousands), isolated, share no memory, and communicate only by sending
messages to each other's mailbox.

```elixir
defmodule Exmonitor.Engine do
  use GenServer
  require Logger

  def start_link(cfg, persona) do
    GenServer.start_link(__MODULE__, {cfg, persona})
  end

  @impl true
  def init({cfg, persona}) do
    # ... open sockets, set up timers ...
    {:ok, %__MODULE__{...}}
  end
```

`use GenServer` pulls in the behavior; `init/1` runs once when the process
starts and returns the initial state (the `@impl true` annotation just
tells the compiler "this implements a GenServer callback," so it can warn
you about typos). `handle_info/2` clauses (one per message shape) handle
everything that happens afterward. Crucially, a GenServer only ever
processes one message at a time, in order — so even though pings,
timeouts, and incoming packets are all "concurrent" events from the
outside, inside `Exmonitor.Engine` there's never a race condition to worry
about. That's the direct replacement for Go's `ch <- Event{...}` channel
plus `for { event := <-ch }` loop, but you get it from the OTP behavior
itself rather than hand-building it.

The other trick that removes code compared to Go: the sockets are opened
with `active: true`, using the raw Erlang `:gen_udp` module (Erlang
modules are called in lowercase-atom form like `:gen_udp`, `:inet`,
`:crypto`):

```elixir
defp open_socket({ip, port}) do
  :gen_udp.open(port, [:binary, active: true, ip: ip])
end
```

In active mode, the OS delivers each incoming datagram straight into the
owning process's mailbox as a `{:udp, socket, ip, port, data}` message —
there's no separate "reader goroutine" needed like `readudp()` in Go; the
mailbox *is* the reader.

Walking through the message clauses:

```elixir
# Pings: mirrors sendudp() in gomonitor.go / pingtime_cb() in vmonitor
def handle_info({:ping, link}, state) do
  state = do_ping(link, state)

  jitter = state.cfg.pingavg + state.cfg.pingvar * 2 * (:rand.uniform() - 0.5)
  ms = max(0, round(jitter * 1000))
  Process.send_after(self(), {:ping, link}, ms)

  {:noreply, state}
end
```

`{:ping, link}` fires periodically. Each `handle_info` clause reschedules
its *own* next firing via `Process.send_after` — a self-perpetuating
cycle rather than a `for {} { ...; sleep(...) }` loop. `{:noreply, state}`
is the standard "no reply to send back, here's my new state" return value
GenServer callbacks use.

```elixir
# Incoming datagrams: mirrors readudp() / recv_callback()
def handle_info({:udp, socket, ip, port, data}, state) do
  link = state.link_by_socket[socket]

  case Packet.parse(link, state.cfg.secret, data) do
    {:ok, challenge, response} ->
      state =
        state
        |> maybe_learn_peer(link, ip, port)
        |> restart_timer(to_key(link, :to))
        |> put_in([Access.key!(:their_challenge), link], challenge)
        |> handle_response(link, response)

      {:noreply, evaluate(state, "recv#{link}")}

    :error ->
      {:noreply, state}
  end
end
```

A packet arrived. On success it's threaded through a pipe of
state-transforming steps — each function takes `state` in, returns a new
`state` out — then `evaluate/2` decides if the link state changed. This
pipe is a nice concrete example of "immutable update chain": nothing here
is mutated, each step just builds the next version of `state`.

```elixir
# Timers firing: mirrors the timeout branches of the main loop
def handle_info({:timer, key, tag}, state) do
  timer = state.timers[key]

  if timer && timer.tag == tag do
    state = put_in(state.timers[key], Timer.fired(timer))
    {:noreply, evaluate(state, Atom.to_string(key))}
  else
    # Stale message from a timer that was already restarted; ignore.
    {:noreply, state}
  end
end
```

One of the six timers (`to1`/`to2`/`cto1`/`cto2`/`hysteresis`/
`heartbeat`/`hard_heartbeat`) fired. The tag check discussed in the Timer
section filters out stale messages, then the timer is marked "dead" and
`evaluate/2` runs.

`evaluate/2` and `apply_link_state/1` are the direct port of the Go main
loop's tail:

```elixir
defp evaluate(state, event_name) do
  state = restart_timer(state, :heartbeat)

  if Timer.alive?(state.timers[:hysteresis]) do
    state
  else
    apply_link_state(state)
  end
end

defp apply_link_state(state) do
  link1_up = Timer.alive?(state.timers[:to1]) and Timer.alive?(state.timers[:cto1])
  link2_up = Timer.alive?(state.timers[:to2]) and Timer.alive?(state.timers[:cto2])
  idx = (if link1_up, do: 1, else: 0) + (if link2_up, do: 2, else: 0)
  new_state = @states[idx]

  cond do
    new_state != state.current_state ->
      Logger.warning("New state: #{new_state}")
      state = %{state | current_state: new_state}
      new_hysteresis = Timer.restart(state.timers[:hysteresis], state.cfg.hysteresis * 1000)
      state = put_in(state.timers[:hysteresis], new_hysteresis)

      state
      |> run_state_script(new_state)
      |> restart_hard_heartbeat()

    hard_heartbeat_fired?(state) ->
      Logger.info("Reapply state: #{state.current_state}")

      state
      |> run_state_script(state.current_state)
      |> restart_hard_heartbeat()

    true ->
      state
  end
end
```

Restart the heartbeat; if the hysteresis timer is still alive, do nothing
further; otherwise recompute `NOLINK`/`LINK1`/`LINK2`/`LINK1_LINK2` from
which timers are still alive and, on a change (or an expired
`hard_heartbeat`), run the configured shell script. `cond` here is
Elixir's "if/elsif/elsif/else" chain, used when you have several unrelated
boolean conditions rather than one value to pattern-match on (that's what
`case` is for).

`run_state_script/2` is the `System.cmd/3` call, Elixir's
`subprocess.run`/`exec.Command` equivalent:

```elixir
defp run_state_script(state, link_state) do
  script = state.cfg.scripts[link_state]

  if script != "None" do
    Logger.info("Running state script #{script}")

    case System.cmd("/bin/bash", ["-c", script], stderr_to_stdout: true) do
      {_out, 0} -> :ok
      {out, code} -> Logger.error("Script exited with status #{code}: #{String.trim(out)}")
    end
  else
    Logger.debug("No script configured for state")
  end

  state
end
```

Note it still returns `state` unchanged at the end, since it's called from
inside a `|>` pipe and every pipe step needs to hand back a `state` value,
even the ones that are really just "for effect" (like running a shell
command).

One syntax wart worth explaining directly: `put_in(state.timers[key],
value)` and the `put_in([Access.key!(:their_challenge), link], challenge)`
form (used inside the `|>` pipe above) are both "return a new
struct/map with one nested field replaced" — nothing is mutated in place,
a new copy comes back. The plain dotted form (`put_in(state.timers[key],
...)`) works when you're writing the whole path out literally in one
expression. The `Access.key!/1` list form is needed instead when you're
piping a value in and the struct being updated (the `state` in `state |>
put_in(...)`) is implicit rather than spelled out — `Access.key!(:field)`
tells `put_in` "treat this as a struct field access" for that step of the
path.

## `lib/exmonitor/cli.ex` — entry point

```elixir
defmodule Exmonitor.CLI do
  def main(args) do
    case args do
      [config_path, persona_str] when persona_str in ["client", "server"] ->
        run(config_path, String.to_atom(persona_str))

      _ ->
        IO.puts(:stderr, "Usage: exmonitor <config file> <client|server>")
        System.halt(1)
    end
  end

  defp run(config_path, persona) do
    case Exmonitor.Config.load(config_path) do
      {:ok, cfg} ->
        {:ok, _pid} = Exmonitor.Engine.start_link(cfg, persona)
        Process.sleep(:infinity)

      {:error, reason} ->
        IO.puts(:stderr, reason)
        System.halt(1)
    end
  end
end
```

`main/1` is what the escript calls with the command-line args as a list of
strings, matched against the exact 2-element shape with a **guard
clause** — `when persona_str in ["client", "server"]`. Guards let you
attach extra boolean conditions to a pattern match that plain pattern
matching can't express (like "and this string must be one of these two
values").

`run/2` loads the config, starts the `Engine` GenServer, and then just
parks the main process forever with `Process.sleep(:infinity)`. Since all
the real work now happens asynchronously inside the GenServer's own
mailbox loop (see `engine.ex`), the "main" process has nothing left to do
but stay alive so the escript doesn't exit.
