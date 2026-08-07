defmodule Exmonitor.Packet do
  @moduledoc """
  Wire format codec, compatible with vmonitor (Python) and gomonitor (Go):

      "<link> <iso8601 utc time> <challenge> <response> <hmac-16hex>"

  The HMAC-SHA256 is computed over the first four space-separated fields
  (including the trailing space) using the shared secret, then truncated
  to the first 16 hex characters.
  """

  @max_skew_seconds 120

  def gen(link, secret, challenge, response) do
    timestamp = Calendar.strftime(DateTime.utc_now(), "%Y-%m-%dT%H:%M:%S")
    data = "#{link} #{timestamp} #{challenge} #{response} "
    data <> hmac16(data, secret)
  end

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

  defp hmac16(data, secret) do
    :crypto.mac(:hmac, :sha256, secret, data)
    |> Base.encode16(case: :lower)
    |> String.slice(0, 16)
  end
end
