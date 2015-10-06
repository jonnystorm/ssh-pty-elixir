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

  defp get_applications(:prod) do
    [
      applications: [
        :logger,
        :ssh,
        :pathname_ex
      ]
    ]
  end
  defp get_applications(_) do
    [applications: [:logger, :ssh]]
  end

  def application do
    get_applications Mix.env
  end

  defp deps do
    [
      {:pathname_ex, git: "https://github.com/jonnystorm/pathname-elixir"}
    ]
  end
end
