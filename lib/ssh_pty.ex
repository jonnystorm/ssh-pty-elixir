# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule SSHPTY do
  @type ip_protocol :: :udp | :tcp
  @type port_number :: 0..65535

  defmodule Pathname do
    defstruct address: nil, protocol: nil, protocol_params: nil

    @type t :: %Pathname{
      address: String.t,
      protocol: OpenSSH.ip_protocol,
      protocol_params: [port: OpenSSH.port_number]
    }

    def address(pathname) do
      pathname.address
    end
    def address(pathname, value) do
      %Pathname{pathname|address: value}
    end

    def protocol(pathname) do
      pathname.protocol
    end
    def protocol(pathname, protocol, params) when is_list(params) do
      %Pathname{pathname|protocol: protocol, protocol_params: params}
    end
  end
  
  def pathname(address) do
    pathname(address, :tcp, [port: 22])
  end 
  def pathname(address, protocol, protocol_params) do
    %Pathname{}
    |> Pathname.address(address)
    |> Pathname.protocol(protocol, protocol_params)
  end 

  def connect(pathname, credential) do
    address = :binary.bin_to_list pathname.address
    port = pathname.protocol_params[:port]
    username = :binary.bin_to_list credential[:username]
    password = :binary.bin_to_list credential[:password]

    {:ok, connection} = :ssh.connect(address, port, [
      user: username,
      password: password,
      silently_accept_hosts: true
    ], 5000)

    connection
  end

  def disconnect(connection) do
    :ssh.close(connection)
  end

  def get_shell(connection, timeout \\ 10000) do
    {:ok, cid} = :ssh_connection.session_channel(connection, timeout)
    :ssh_connection.ptty_alloc(connection, cid, [])
    :ssh_connection.shell(connection, cid)

    cid
  end

  def credential(username, password) do
    [username: username, password: password]
  end

  defp _receive_messages(acc) do
    receive do
      {:ssh_cm, _, {:data, _, _, data}} ->
        _receive_messages(acc <> data)
      {:ssh_cm, _, {:eof, _}} ->
        {:ok, acc}
      {:ssh_cm, _, {:exit_signal, _, exit_signal, error_msg, lang_string}} ->
        {:exit_signal, {exit_signal, error_msg, lang_string}, acc}
      {:ssh_cm, _, {:exit_status, _, exit_status}} ->
        {:ok, {:exit_status, exit_status}, acc}
      {:ssh_cm, _, {:closed, _}} ->
        {:ok, acc}
    after
      3_000 -> {:ok, acc}
    end
  end

  defp receive_messages do
    _receive_messages("")
  end

  def send(commands, connection, channel) when is_list(commands) do
    for command <- commands do
      case :ssh_connection.send(connection, channel, command <> "\r", 5000) do
        :ok ->
          #{:ok, _} = receive_messages
          {:ok, result} = receive_messages

          {command, result}
        {:error, cause} ->
          {:error, cause}
      end
    end
  end
  def send(command, connection, channel) when is_binary(command) do
    send([command], connection, channel)
  end
end

