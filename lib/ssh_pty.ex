# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule SSHPTY do
  require Logger

  @type uri
    :: %{scheme: String.t,
         host:   String.t,
         port:   1..65535 | nil,
       }

  @type credential
    :: %{username: String.t}

  @type opts   :: [] | nil
  @type expect :: Regex.t

  @type session
    :: %{ref:      :ssh.connection_ref,
         cid:      :ssh.ssh_channel_id,
         expect:   expect,
         greeting: String.t,
       }

  @doc """
  Open an SSH connection.

  Setting option `:scrub_ansi` to `true` removes ANSI
  escape sequences from the output. This is the default.

  ## Examples

  iex> prompt = ~r/>|#/
  iex> credential =
  ...>   %{username: "user",
  ...>     password: "pass",
  ...>   }
  iex> "ssh://192.0.2.1:2222"
  ...> |> URI.parse
  ...> |> SSHPTY.connect(credential, ~r/>|#/)
  {:ok, %{cid: 0, ref: pid(0,100,0), greeting: "prompt>\r\n"}}
  """
  @spec connect(uri, credential, expect, opts)
    :: {:ok, session}
     | {:error, term}
  def connect(uri, credential, expect, opts \\ [])

  def connect(
    %{scheme: "ssh", host: host, port: port0} = _uri,
    %{username: username} = credential,
    expect,
    opts
  )   when is_binary(host)
       and is_list(opts)
  do
    port = port0 || 22

    username_erl = String.to_charlist(username)
    cred_to_arg  =
      %{:password     => :password,
      # :rsa_password => :rsa_pass_phrase,
      # :dsa_password => :dsa_pass_phrase,
      }

    args =
      credential
      |> Map.take(Map.keys(cred_to_arg))
      |> Enum.reduce([], fn({k, v}, acc) ->
        if v do
          {cred_to_arg[k], String.to_charlist(v)}
          |> List.wrap
          |> Enum.concat(acc)
        else
          acc
        end
      end)
      |> Enum.concat(
        [ user: username_erl,
          silently_accept_hosts: true,
        ]
      )

    check_expect =
      fn
        %Regex{}      -> :ok
        <<_::binary>> -> :ok
        e ->
          {:error, {:einval, e}}
      end

    timeout0 = opts[:timeout]
    timeout  =
      if timeout0 != nil
         and is_integer(timeout0)
         and timeout0 > 0,
          do: timeout0,
        else: 5000

    scrub_ansi =
      if opts[:scrub_ansi] == false,
        do: false,
      else: true

    with :ok <- check_expect.(expect),

         {:ok, erl_addresses} <- resolve_hostname(host),

         erl_address <- List.first(erl_addresses),

         {:ok, netaddr} <-
           NetAddr.erl_ip_to_netaddr(erl_address),

         address <- NetAddr.address(netaddr),

         :ok <- Logger.debug("Connecting to ssh://#{username}@#{address}:#{port}..."),

         {:ok, ref} <-
           :ssh.connect(erl_address, port, args, timeout),

         {:ok, cid} <- get_shell(ref, timeout)
    do
      session =
        %{ref:        ref,
          cid:        cid,
          expect:     expect,
          scrub_ansi: scrub_ansi,
        }

      with {:ok, greeting} <-
             get_result(session, timeout),
        do: {:ok, Map.put(session, :greeting, greeting)}
    end
  end

  defp resolve_hostname(hostname) do
    with {:ok, {_, _, _, _, _, erl_addresses}} <-
           hostname
           |> String.to_charlist
           |> :inet.gethostbyname,

      do: {:ok, erl_addresses}
  end

  defp get_shell(ref, timeout) do
    with {:ok, cid} <-
           :ssh_connection.session_channel(ref, timeout),

         :success <-
           :ssh_connection.ptty_alloc(ref, cid, []),

         :ok <-
           :ssh_connection.shell(ref, cid)
    do
      {:ok, cid}
    else
      :failure ->
        {:error, :no_pty_or_shell}

      {:error, _} = e ->
        e
    end
  end

  @spec disconnect(session)
    :: :ok
     | {:error, any}
  def disconnect(%{ref: ref} = _session),
    do: :ssh.close(ref)

  defp _receive_messages(session, timeout, acc) do
    ref = session.ref

    receive do
      {:ssh_cm, ^ref, {:data, _, _, data}} ->
        if data =~ session.expect do
          {:ok, acc <> data}
        else
          _receive_messages(session, timeout, acc <> data)
        end

      {:ssh_cm, ^ref, {:eof, _}} ->
        {:ok, acc}

      { :ssh_cm, ^ref,
        { :exit_signal,
          _,
          exit_signal,
          error_msg,
          lang_string
        }
      } ->
        { :error,
          {:exit_signal,
            exit_signal,
            error_msg,
            lang_string,
            acc
          }
        }

      {:ssh_cm, ^ref, {:exit_status, _, exit_status}} ->
        {:ok, {:exit_status, exit_status, acc}}

      {:ssh_cm, ^ref, {:closed, _}} ->
        {:ok, acc}

    after
      timeout ->
        {:error, {:etimedout, acc}}
    end
  end

  defp receive_messages(session, timeout),
    do: _receive_messages(session, timeout, "")

  defp if_do(term, pairs) do
    pairs
    |> Enum.reduce(term, fn({condition, fun}, acc) ->
      if condition, do: fun.(acc), else: acc
    end)
  end

  defp get_result(session, timeout) do
    scrub =
      fn str ->
        if_do(str, [
            { session.scrub_ansi,
              &scrub_ansi_escape_sequences/1
            },
          ]
        )
      end

    case receive_messages(session, timeout) do
      {:ok, {_, _, buf0}} ->
        {:ok, scrub.(buf0)}

      {:ok, buf0} ->
        {:ok, scrub.(buf0)}

      {:error, {:etimedout, buf0}} ->
        {:error, {:etimedout, scrub.(buf0)}}

      {:error, {_, sig, msg, _, buf0}} ->
        :ok = Logger.error("SSH ref #{session.ref} got exit signal #{sig}: #{msg}")

        {:error, {:enotconn, scrub.(buf0)}}
    end
  end

  @type input  :: String.t
  @type output :: String.t

  @doc """
  Send input and receive output.

  ## Examples

  iex> SSHPTY.exchange("ls\r", session)
  [{"ls\r", {:ok, "prompt$ ls\r\nstuff  things\r\n"}}]
  """
  @spec exchange([input]|input, session, opts)
    :: [ {input, {:ok, output}}
       | {input, {:error, term}}
       ]
  def exchange(inputs, session, opts \\ [])

  def exchange(inputs, session, opts)
      when is_list(inputs)
       and is_list(opts)
  do
    timeout0 = opts[:timeout]
    timeout  =
      if timeout0 != nil
         and is_integer(timeout0)
         and timeout0 > 0,
          do: timeout0,
        else: 3000

    send_and_receive =
      fn input ->
        if is_binary(input) do
          with :ok <-
                 :ssh_connection.send(
                   session.ref,
                   session.cid,
                   input,
                   5000
                 ),
            do: get_result(session, timeout)
        else
          {:error, :einval}
        end
      end

    Enum.reduce(inputs, [], fn
      (input, []) ->
        result = send_and_receive.(input)

        [{input, result}]

      (input, [last|_] = acc) ->
        result =
          case last do
            {:ok, _} ->
              send_and_receive.(input)

            {:error, _} ->
              {:error, :ecanceled}
          end

        [{input, result}|acc]
    end)
  end

  def exchange(input, session, timeout)
      when is_binary(input),
    do: exchange([input], session, timeout)

  def scrub_ansi_escape_sequences(string)
      when is_binary(string)
  do
    string
    |> String.replace(~r"\e\[[0-9;]*[a-z]"i, "")
    |> String.replace(~r"\e\]0;.*\a", "")  # term title
  end
end

