defmodule SSHPTY.MixProject do
  use Mix.Project

  def project do
    [ app: :ssh_pty_ex,
      version: "0.0.4",
      elixir: "~> 1.0",
      start_permanent: Mix.env == :prod,
      deps: deps(),
    ]
  end

  def application do
    [ extra_applications: [
        :logger,
        :ssh,
      ]
    ]
  end

  defp deps do
    []
  end
end
