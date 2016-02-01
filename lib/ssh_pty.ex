# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule SSHPTY do
  require Logger

  @type credential :: [{atom, String.t}]

  defp resolve_hostname(hostname) do
    {:ok, {:hostent, _, _, :inet, 4, [address|_]}} =
      hostname
        |> :binary.bin_to_list
        |> :inet.gethostbyname

    address
      |> :inet.ntoa
      |> :binary.list_to_bin
  end

  @spec connect(URI.t, credential) :: :ssh.ssh_connection_ref
  def connect(%URI{scheme: "ssh", host: host, port: port}, credential) do
    address =
      host
        |> resolve_hostname
        |> :binary.bin_to_list

    port = port || 22
    username = :binary.bin_to_list credential[:username]
    args =
      [ user: username,
        silently_accept_hosts: true
      ]

    Logger.debug "Connecting to #{username}@#{address}:#{port}..."

    if credential[:rsa_password] do
      args =
        args ++ [rsa_pass_phrase: :binary.bin_to_list credential[:rsa_password]]
    end

    if credential[:dsa_password] do
      args =
        args ++ [dsa_pass_phrase: :binary.bin_to_list credential[:dsa_password]]
    end

    if credential[:password] do
      args =
        args ++ [password: :binary.bin_to_list credential[:password]]
    end

    {:ok, connection} = :ssh.connect address, port, args, 5000

    connection
  end

  @spec disconnect(:ssh.ssh_connection_ref) :: :ok
  def disconnect(connection) do
    :ssh.close connection
  end

  @spec get_shell(:ssh.ssh_connection_ref, pos_integer) :: :ssh.ssh_channel_id
  def get_shell(connection, timeout \\ 10_000) do
    {:ok, cid} = :ssh_connection.session_channel connection, timeout
    :ssh_connection.ptty_alloc connection, cid, []
    :ssh_connection.shell connection, cid

    cid
  end

  @spec credential(String.t, String.t) :: credential
  def credential(username, password) do
    [username: username, password: password]
  end

  defp _receive_messages(acc) do
    receive do
      {:ssh_cm, _, {:data, _, _, data}} ->
        _receive_messages acc <> data

      {:ssh_cm, _, {:eof, _}} ->
        {:ok, acc}

      {:ssh_cm, _, {:exit_signal, _, exit_signal, error_msg, lang_string}} ->
        {:exit_signal, {exit_signal, error_msg, lang_string}, acc}

      {:ssh_cm, _, {:exit_status, _, exit_status}} ->
        {:ok, {:exit_status, exit_status}, acc}

      {:ssh_cm, _, {:closed, _}} ->
        {:ok, acc}

    after
      3_000 ->
        {:ok, acc}
    end
  end

  defp receive_messages do
    _receive_messages ""
  end

  defp get_result do
    case receive_messages do
      {:ok, result} ->
        result

      {:ok, _, result} ->
        result
    end
  end

  @spec send([String.t] | String.t, :ssh.ssh_connection_ref, :ssh.ssh_channel_id) :: [{String.t, String.t} | {:error, any}]
  def send(commands, connection, channel) when is_list commands do
    for command <- commands do
      case :ssh_connection.send connection, channel, command <> "\r", 5000 do
        :ok ->
          {command, get_result}

        {:error, cause} ->
          {:error, cause}
      end
    end
  end
  def send(command, connection, channel) when is_binary command do
    send [command], connection, channel
  end
end

