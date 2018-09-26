# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule SSHPTY do
  require Logger

  @type session
    :: %{ref: :ssh.connection_ref,
         cid: :ssh.ssh_channel_id,
       }

  defp get_delimiter_by_family(4), do: "."
  defp get_delimiter_by_family(6), do: ":"

  defp resolve_hostname(hostname) do
    result =
      hostname
      |> :binary.bin_to_list
      |> :inet.gethostbyname

    with {:ok, {_, _, _, _, family, addresses}}
           <- result
    do
      delimiter =
        get_delimiter_by_family family

      address_strings =
        addresses
        |> Enum.map(&Tuple.to_list/1)
        |> Enum.map(&Enum.join(&1, delimiter))

      {:ok, address_strings}
    end
  end

  @type credential :: Keyword.t
  @type opts
    :: [{:timeout, timeout}]
     | nil

  @type uri
    :: %{scheme: String.t,
         host: String.t,
         port: 1..65535,
       }

  @spec connect(uri, credential, opts)
    :: {:ok, session}
     | {:error, any}
  def connect(
    %{scheme: "ssh", host: host, port: port0} = _uri,
    credential,
    opts \\ []
  ) when is_binary(host)
  do
    with {:ok, addresses} <- resolve_hostname(host),

         address_erl <-
           addresses
           |> List.first
           |> :binary.bin_to_list,

         port <- port0 || 22,

         username_erl <-
           credential
           |> Keyword.fetch!(:username)
           |> String.to_charlist,

         :ok <-
           Logger.debug("Connecting to #{username_erl}@#{address_erl}:#{port}..."),

         and_then <-
           fn (x, f) ->
             if x,
             do: f.(x),
             else: x
           end,

         append_to <-
           &Enum.concat(&2, List.wrap(&1)),

         accrete_as <-
           fn(acc, value, key) ->
             [ &String.to_charlist/1,
               &{key, &1},
               &List.wrap/1,
             ]
             |> Enum.reduce(value, &and_then.(&2, &1))
             |> append_to.(acc)
           end,

         accrete_cred_as <-
           fn(acc, key, new_key) ->
             accrete_as.(acc, credential[key], new_key)
           end,

         args <-
           [ user: username_erl,
             silently_accept_hosts: true,
           ]
           |> accrete_cred_as.(:password, :password),
           #|> accrete_cred_as.(:rsa_password, :rsa_pass_phrase)
           #|> accrete_cred_as.(:dsa_password, :dsa_pass_phrase)

         timeout <-
           Keyword.get(opts, :timeout, 5000),

         {:ok, ref} <-
           :ssh.connect(address_erl, port, args, timeout)
    do
      {:ok, %{ref: ref, cid: nil}}
    end
  end

  @spec disconnect(session)
    :: :ok
     | {:error, any}
  def disconnect(%{ref: ref} = _session),
    do: :ssh.close(ref)

  @spec get_shell(session, timeout)
    :: {:ok, session}
     | {:error, :closed|:timeout}
  def get_shell(session, timeout \\ 10_000)

  def get_shell(
    %{ref: ref, cid: nil} = session,
    timeout
  ) do
    with {:ok, cid} <-
           :ssh_connection.session_channel(ref, timeout)
    do
      :ssh_connection.ptty_alloc(ref, cid, [])
      :ssh_connection.shell(ref, cid)

      {:ok, %{session|cid: cid}}
    end
  end

  def get_shell(session, _timeout),
    do: {:ok, session}

  @spec credential(String.t, String.t)
    :: credential
  def credential(username, password),
    do: [username: username, password: password]

  defp _receive_messages(timeout, acc) do
    receive do
      {:ssh_cm, _, {:data, _, _, data}} ->
        _receive_messages(timeout, acc <> data)

      {:ssh_cm, _, {:eof, _}} ->
        {:ok, acc}

      { :ssh_cm, _,
        { :exit_signal,
          _,
          exit_signal,
          error_msg,
          lang_string
        }
      } ->
        { :exit_signal,
          { exit_signal,
            error_msg,
            lang_string
          },
          acc
        }

      {:ssh_cm, _, {:exit_status, _, exit_status}} ->
        {:ok, {:exit_status, exit_status}, acc}

      {:ssh_cm, _, {:closed, _}} ->
        {:ok, acc}

    after
      timeout ->
        {:ok, acc}
    end
  end

  defp receive_messages(timeout),
    do: _receive_messages(timeout, "")

  defp get_result(timeout) do
    case receive_messages timeout do
      {:ok,    result} -> result
      {:ok, _, result} -> result
    end
  end

  @type command :: String.t

  @spec send([command] | command, session)
    :: [ {:ok, {command, String.t}}
       | {:error, any}
       ]
  def send(commands, session),
    do: send(commands, session, 3000)

  @spec send([command] | command, session, timeout)
    :: [ {:ok, {command, String.t}}
       | {:error, any}
       ]
  def send(
    commands,
    %{ref: ref, cid: cid},
    timeout
  )   when is_list(commands)
       and is_integer(timeout)
       and timeout >= 0
  do
    for command <- commands do
      result =
        :ssh_connection.send(ref, cid, "#{command}\r", 5000)

      case result do
        :ok ->
          {:ok, {command, get_result(timeout)}}

        {:error, cause} ->
          {:error, cause}
      end
    end
  end

  def send(command, session, timeout),
    do: send([command], session, timeout)
end

