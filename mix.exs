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
