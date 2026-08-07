defmodule Exmonitor.Timer do
  @moduledoc """
  A restartable one-shot timer that delivers `{:timer, key, tag}` to the
  calling process and can report whether it is still "alive" (i.e. has not
  fired since it was last (re)started), mirroring the Timeout helper in the
  Python and Go implementations.

  Each (re)start gets a fresh `tag` (a unique reference) so that a message
  from a timer that was cancelled-and-restarted in the same instant, but
  had already been queued in the mailbox, can be recognized as stale and
  ignored instead of being mistaken for the new timer firing.
  """

  defstruct [:key, :tag, :ref, :ms, :eta, :alive]

  def new(key, ms) do
    tag = make_ref()
    ref = Process.send_after(self(), {:timer, key, tag}, ms)
    %__MODULE__{key: key, tag: tag, ref: ref, ms: ms, eta: now_ms() + ms, alive: true}
  end

  def restart(%__MODULE__{} = timer), do: restart(timer, timer.ms)

  def restart(%__MODULE__{key: key, ref: ref}, ms) do
    if ref, do: Process.cancel_timer(ref)
    new(key, ms)
  end

  def fired(%__MODULE__{} = timer), do: %{timer | alive: false, ref: nil}

  def alive?(%__MODULE__{alive: alive}), do: alive
  def alive?(nil), do: false

  def remaining(%__MODULE__{alive: false}), do: 0
  def remaining(%__MODULE__{eta: eta}), do: max(0, div(eta - now_ms(), 1000))
  def remaining(nil), do: 0

  defp now_ms, do: System.monotonic_time(:millisecond)
end
