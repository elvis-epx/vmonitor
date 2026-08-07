defmodule Exmonitor.Engine do
  @moduledoc """
  The event loop. Where the Go version has goroutines feeding a shared
  channel, this uses OTP's normal mailbox: UDP sockets are opened in
  `active: true` mode so each incoming datagram arrives as a message, and
  every timer is a `Process.send_after/3` that also lands in the mailbox.
  `handle_info/2` clauses are the equivalent of the `select`/`for { <-ch }`
  loop, and being a GenServer they are guaranteed to run one at a time, so
  no explicit locking is needed around the shared state.
  """

  use GenServer
  require Logger

  alias Exmonitor.{Packet, Timer}

  defstruct [
    :cfg,
    :persona,
    :sockets,
    :link_by_socket,
    :peer_fixed,
    :peer,
    :our_challenge,
    :their_challenge,
    :timers,
    :current_state,
    :peer_logged_missing
  ]

  @states %{0 => "NOLINK", 1 => "LINK1", 2 => "LINK2", 3 => "LINK1_LINK2"}

  def start_link(cfg, persona) do
    GenServer.start_link(__MODULE__, {cfg, persona})
  end

  @impl true
  def init({cfg, persona}) do
    {local, remote} =
      case persona do
        :client -> {cfg.client, cfg.server}
        :server -> {cfg.server, cfg.client}
      end

    {:ok, sock1} = open_socket(Enum.at(local, 0))
    {:ok, sock2} = open_socket(Enum.at(local, 1))

    peer_fixed = persona == :client

    peer =
      if peer_fixed do
        %{1 => Enum.at(remote, 0), 2 => Enum.at(remote, 1)}
      else
        %{1 => nil, 2 => nil}
      end

    timers = %{
      to1: Timer.new(:to1, cfg.timeout * 1000),
      to2: Timer.new(:to2, cfg.timeout * 1000),
      cto1: Timer.new(:cto1, cfg.ctimeout * 1000),
      cto2: Timer.new(:cto2, cfg.ctimeout * 1000),
      hysteresis: Timer.new(:hysteresis, cfg.initial_hysteresis * 1000),
      heartbeat: Timer.new(:heartbeat, cfg.heartbeat * 1000),
      hard_heartbeat:
        if(cfg.hard_heartbeat > 0, do: Timer.new(:hard_heartbeat, cfg.hard_heartbeat * 1000))
    }

    send(self(), {:ping, 1})
    send(self(), {:ping, 2})

    Logger.info("vmonitor, persona = #{persona}")

    {:ok,
     %__MODULE__{
       cfg: cfg,
       persona: persona,
       sockets: %{1 => sock1, 2 => sock2},
       link_by_socket: %{sock1 => 1, sock2 => 2},
       peer_fixed: peer_fixed,
       peer: peer,
       our_challenge: %{1 => "None", 2 => "None"},
       their_challenge: %{1 => "None", 2 => "None"},
       timers: timers,
       current_state: "undefined",
       peer_logged_missing: %{1 => false, 2 => false}
     }}
  end

  defp open_socket({ip, port}) do
    :gen_udp.open(port, [:binary, active: true, ip: ip])
  end

  # --- Pings: mirrors sendudp() in gomonitor.go / pingtime_cb() in vmonitor ---

  @impl true
  def handle_info({:ping, link}, state) do
    state = do_ping(link, state)

    jitter = state.cfg.pingavg + state.cfg.pingvar * 2 * (:rand.uniform() - 0.5)
    ms = max(0, round(jitter * 1000))
    Process.send_after(self(), {:ping, link}, ms)

    {:noreply, state}
  end

  # --- Incoming datagrams: mirrors readudp() / recv_callback() ---

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

  # --- Timers firing: mirrors the timeout branches of the main loop ---

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

  defp do_ping(link, state) do
    case state.peer[link] do
      nil ->
        unless state.peer_logged_missing[link] do
          Logger.info("Link #{link}: peer address still unknown")
        end

        put_in(state.peer_logged_missing[link], true)

      {ip, port} ->
        challenge =
          case state.our_challenge[link] do
            "None" -> gen_challenge()
            c -> c
          end

        state = put_in(state.our_challenge[link], challenge)
        packet = Packet.gen(link, state.cfg.secret, challenge, state.their_challenge[link])

        case :gen_udp.send(state.sockets[link], ip, port, packet) do
          :ok -> Logger.debug("Link #{link} sent #{packet}")
          {:error, reason} -> Logger.warning("Link #{link} send error: #{inspect(reason)}")
        end

        put_in(state.peer_logged_missing[link], false)
    end
  end

  defp maybe_learn_peer(state, link, ip, port) do
    if state.persona == :server and state.peer[link] != {ip, port} do
      Logger.info("Link #{link}: detected new peer addr #{:inet.ntoa(ip)}:#{port}")
      put_in(state.peer[link], {ip, port})
    else
      state
    end
  end

  defp handle_response(state, link, response) do
    our = state.our_challenge[link]

    cond do
      our == "None" ->
        Logger.debug("Link #{link}: not evaluating response")
        state

      response == our ->
        Logger.debug("Link #{link}: good response")

        state
        |> restart_timer(to_key(link, :cto))
        |> put_in([Access.key!(:our_challenge), link], "None")

      response == "None" ->
        Logger.debug("Link #{link}: null response (exchange incomplete)")
        state

      true ->
        Logger.debug("Link #{link}: wrong response (expected #{our}, got #{response})")
        state
    end
  end

  defp restart_timer(state, key) do
    put_in(state.timers[key], Timer.restart(state.timers[key]))
  end

  defp to_key(1, :to), do: :to1
  defp to_key(2, :to), do: :to2
  defp to_key(1, :cto), do: :cto1
  defp to_key(2, :cto), do: :cto2

  # --- State evaluation: mirrors the tail of the Go main loop / handle_link_change() ---

  defp evaluate(state, event_name) do
    state = restart_timer(state, :heartbeat)

    Logger.debug(fn ->
      "State #{state.current_state}" <>
        " to1 #{Timer.remaining(state.timers[:to1])}/#{Timer.remaining(state.timers[:cto1])}" <>
        " to2 #{Timer.remaining(state.timers[:to2])}/#{Timer.remaining(state.timers[:cto2])}" <>
        " hys #{Timer.remaining(state.timers[:hysteresis])} event #{event_name}"
    end)

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

  defp hard_heartbeat_fired?(state) do
    hh = state.timers[:hard_heartbeat]
    hh != nil and not Timer.alive?(hh)
  end

  defp restart_hard_heartbeat(state) do
    if state.timers[:hard_heartbeat] do
      restart_timer(state, :hard_heartbeat)
    else
      state
    end
  end

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

  defp gen_challenge do
    :rand.uniform(0xFFFFFFFF) |> Integer.to_string(16) |> String.downcase()
  end
end
