defmodule SSHPTY.Mixfile do
  use Mix.Project

  def project do
    [app: :ssh_pty_ex,
     version: "0.0.1",
     elixir: "~> 1.0",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps]
  end

  def application do
    [applications: [:logger, :ssh]]
  end

  defp deps do
    []
  end
end
