defmodule Exmonitor.Config do
  @moduledoc """
  Minimal INI reader plus validation for the `[vmonitor]` section, matching
  the required-field set of gomonitor.go (a superset of fields, such as the
  mail/logging options only used by the Python vmonitor, are read and
  silently ignored, so the same config file works with either version).
  """

  defstruct [
    :secret,
    :scripts,
    :server,
    :client,
    :pingavg,
    :pingvar,
    :timeout,
    :ctimeout,
    :heartbeat,
    :hysteresis,
    :initial_hysteresis,
    :hard_heartbeat
  ]

  @required_strings ~w(link1_server link2_server link1_client link2_client
                        secret link1_script link2_script link1_link2_script nolink_script)
  @required_positive_ints ~w(pingavg pingvar timeout ctimeout heartbeat)
  @required_nonneg_ints ~w(hysteresis initial_hysteresis hard_heartbeat)

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
      {:ok,
       %__MODULE__{
         secret: raw["secret"],
         scripts: %{
           "NOLINK" => raw["nolink_script"],
           "LINK1" => raw["link1_script"],
           "LINK2" => raw["link2_script"],
           "LINK1_LINK2" => raw["link1_link2_script"]
         },
         server: [server1, server2],
         client: [client1, client2],
         pingavg: ip["pingavg"],
         pingvar: ip["pingvar"],
         timeout: ip["timeout"],
         ctimeout: ip["ctimeout"],
         heartbeat: ip["heartbeat"],
         hysteresis: ni["hysteresis"],
         initial_hysteresis: ni["initial_hysteresis"],
         hard_heartbeat: ni["hard_heartbeat"]
       }}
    end
  end

  defp read_file(path) do
    case File.read(path) do
      {:ok, content} -> {:ok, content}
      {:error, _} -> {:error, "Failed to open or parse config file"}
    end
  end

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

  defp ini_line(line, {current, acc}) do
    trimmed = String.trim(line)

    cond do
      trimmed == "" or String.starts_with?(trimmed, ";") or String.starts_with?(trimmed, "#") ->
        {current, acc}

      String.starts_with?(trimmed, "[") and String.ends_with?(trimmed, "]") ->
        name = trimmed |> String.slice(1..-2//1) |> String.trim()
        {name, Map.put_new(acc, name, %{})}

      current == nil ->
        {current, acc}

      true ->
        case String.split(trimmed, "=", parts: 2) do
          [k, v] -> {current, Map.update!(acc, current, &Map.put(&1, String.trim(k), String.trim(v)))}
          _ -> {current, acc}
        end
    end
  end

  defp collect_strings(section) do
    Enum.reduce_while(@required_strings, {:ok, %{}}, fn key, {:ok, acc} ->
      case Map.fetch(section, key) do
        {:ok, ""} -> {:halt, {:error, "Config file has empty item: #{key}"}}
        {:ok, v} -> {:cont, {:ok, Map.put(acc, key, v)}}
        :error -> {:halt, {:error, "Config file is missing item: #{key}"}}
      end
    end)
  end

  defp collect_ints(section, keys, positive: positive) do
    Enum.reduce_while(keys, {:ok, %{}}, fn key, {:ok, acc} ->
      case Map.fetch(section, key) do
        :error ->
          {:halt, {:error, "Config file is missing item: #{key}"}}

        {:ok, raw} ->
          case Integer.parse(raw) do
            {v, ""} when positive and v > 0 -> {:cont, {:ok, Map.put(acc, key, v)}}
            {v, ""} when not positive and v >= 0 -> {:cont, {:ok, Map.put(acc, key, v)}}
            _ -> {:halt, {:error, "Config file has invalid int: #{key}"}}
          end
      end
    end)
  end

  defp validate_secret(secret) do
    if String.length(secret) < 10 do
      {:error, "Secret key must have at least 10 chars"}
    else
      :ok
    end
  end

  defp validate_relations(ip, ni) do
    cond do
      ip["pingavg"] <= ip["pingvar"] ->
        {:error, "pingavg must be larger than pingvar"}

      ip["pingavg"] + ip["pingvar"] + 1 >= ip["timeout"] ->
        {:error, "pingavg + pingvar + 1 should be less than timeout"}

      ip["ctimeout"] <= ip["timeout"] ->
        {:error, "ctimeout should be bigger than timeout"}

      ni["hysteresis"] <= ip["timeout"] ->
        {:error, "hysteresis should be bigger than timeout"}

      true ->
        :ok
    end
  end

  defp validate_distinct(raw) do
    s1 = raw["link1_server"]
    s2 = raw["link2_server"]
    c1 = raw["link1_client"]
    c2 = raw["link2_client"]

    if s1 == s2 or c1 == c2 or c1 == s1 or c1 == s2 or c2 == s1 or c2 == s2 do
      {:error, "All four link addresses must be different"}
    else
      :ok
    end
  end

  defp parse_addr(str) do
    with [host, port_str] <- String.split(str, ":"),
         {port, ""} <- Integer.parse(port_str),
         true <- port > 0 and port < 65536,
         {:ok, ip} <- resolve(host) do
      {:ok, {ip, port}}
    else
      _ -> {:error, "Invalid address, expected host:port: #{str}"}
    end
  end

  defp resolve(host) do
    case :inet.getaddr(String.to_charlist(host), :inet) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> {:error, "Could not resolve host: #{host}"}
    end
  end
end
