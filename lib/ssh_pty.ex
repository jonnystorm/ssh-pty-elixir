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

  defp check_expect(term) do
    case term do
      %Regex{}      -> :ok
      <<_::binary>> -> :ok
      _ ->
        {:error, {:einval, term}}
    end
  end

  @doc """
  Open an SSH connection.

  Setting option `:scrub_ansi` to `true` removes ANSI
  escape sequences from the output. This is the default.

  ## Examples

  iex> prompt = ~r/^.*(>|#)$/m
  iex> credential =
  ...>   %{username: "user",
  ...>     password: "pass",
  ...>   }
  iex> "ssh://192.0.2.1:2222"
  ...> |> URI.parse
  ...> |> SSHPTY.connect(credential, ~r/^.*(>|#)$/m)
  {:ok, %{cid: 0, ref: pid(0,100,0), greeting: "prompt>"}}
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

    timeout =
      validate_non_zero_natural(opts[:timeout], 5000)

    scrub_ansi =
      if is_boolean(opts[:scrub_ansi]),
        do: opts[:scrub_ansi],
      else: true

    with :ok <- check_expect(expect),

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
    # Instead of scrubbing only the latest data, we should
    # probably scrub the data and acc, combined
    #
    # ```elixir
    # next_acc = scrub.(acc <> data)
    # ```
    #
    # which is insane. Will ANSI escape sequences really
    # ever be split between two chunks of data? I have no
    # idea, but I can't justify the polynomial time cost
    # until I see cause to do so.
    #
    # Meanwhile, the "expect" pattern search is certainly
    # polynomial, and I see no reasonable way to prevent
    # this without a substantial loss of
    # correctness/determinism or simplicity. Maybe there
    # will be reason to amortize this cost in the future.
    #
    scrub_ansi_escape_sequences =
      fn string ->
        string
        |> String.replace(~r"\e\[[0-9;]*[a-z]"i, "")
        |> String.replace(~r"\e\]0;.*\a", "")  # term title
      end

    scrub =
      fn str ->
        if_do(str, [
            { session[:scrub_ansi],
              scrub_ansi_escape_sequences
            },
          ]
        )
      end

    ref = session.ref

    receive do
      {:ssh_cm, ^ref, {:data, _, _, data}} ->
        next_acc = acc <> scrub.(data)

        if next_acc =~ session.expect do
          {:ok, next_acc}
        else
          _receive_messages(session, timeout, next_acc)
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
    case receive_messages(session, timeout) do
      {:error, {_, sig, msg, _, buf}} ->
        :ok = Logger.error("SSH ref #{session.ref} got exit signal #{sig}: #{msg}")

        {:error, {:enotconn, buf}}

      {:ok, {_, _, buf}} ->
        {:ok, buf}

      _ = r ->
        r
    end
  end

  defp validate_non_zero_natural(term, _default)
      when is_integer(term)
       and term > 0,
  do: term

  defp validate_non_zero_natural(_term, default),
    do: default

  defp _exchange(inputs, session, opts)
      when is_list(inputs)
  do
    # We avoid frivolously hitting the network after
    # encountering an error by returning `:ecanceled` as
    # the result for all remaining inputs.
    #
    inputs
    |> Enum.reduce([], fn
      (input, []) ->
        [_exchange(input, session, opts)]

      (input, [last|_] = acc) ->
        result =
          case last do
            {_, {:ok, _}} ->
              _exchange(input, session, opts)

            {_, {:error, _}} ->
              {:error, :ecanceled}
          end

        [result|acc]
    end)
    |> Enum.reverse
  end

  defp _exchange(
    input,
    %{ref: ref, cid: cid} = session,
    opts
  )   when is_binary(input)
  do
    with :ok <-
           :ssh_connection.send(ref, cid, input, 5000),
      do: {input, get_result(session, opts[:timeout])}
  end


  @type input  :: String.t
  @type output :: String.t

  @doc """
  Send input and receive output.

  ## Examples

  iex> SSHPTY.exchange("ls\r", session)
  {:ok, [{"ls\r", {:ok, "prompt$ ls\r\nstuff  things\r\n"}}]}
  """
  @spec exchange([input] | input, session, opts)
    :: { :ok,
         [ {input, {:ok, output}}
         | {input, {:error, term}}
         ]
       } | {:error, term}
  def exchange(inputs, session, opts \\ [])

  def exchange(
    term,
    %{ref: _, cid: _, expect: expect} = session,
    opts0
  )   when (
        is_list(term)
        or is_binary(term)
      ) and is_list(opts0)
  do
    timeout =
      validate_non_zero_natural(opts0[:timeout], 3000)

    opts =
      opts0
      |> Keyword.put(:timeout, timeout)

    with :ok <- check_expect(expect) do
      { :ok,
        term
        |> _exchange(session, opts)
        |> List.wrap
      }
    end
  end

  def exchange(term, _session, _timeout),
    do: {:error, {:einval, term}}
end

