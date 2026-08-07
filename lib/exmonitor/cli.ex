defmodule Exmonitor.CLI do
  @moduledoc """
  Entry point for the `exmonitor` escript. Usage mirrors vmonitor/gomonitor:

      exmonitor <config file> <client|server>
  """

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
