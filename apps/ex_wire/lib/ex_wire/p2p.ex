defmodule ExWire.P2P do
  require Logger

  alias ExWire.Framing.Frame
  alias ExWire.{Handshake, Packet, TCP, DEVp2p}
  alias ExWire.Struct.Peer

  defmodule Connection do
    defstruct peer: nil,
              socket: nil,
              handshake: nil,
              secrets: nil,
              queued_data: <<>>,
              session: nil
  end

  def new_outbound_connection(options) do
    socket = Keyword.get(options, :socket)
    peer = Keyword.get(options, :peer)

    handshake =
      Handshake.new(peer.remote_id)
      |> Handshake.generate_auth()

    send_unframed_data(handshake.encoded_auth_msg, socket, peer)

    %Connection{socket: socket, peer: peer, handshake: handshake}
  end

  def new_inbound_connection(options) do
    socket = Keyword.get(options, :socket)

    handshake = Handshake.new_response()

    %Connection{socket: socket, handshake: handshake}
  end

  @doc """
  Handle inbound communication from a peer node.

  If we have already performed the handshake, then we should have `secrets`
  defined. In that case, we simply need to handle packets as they come along.

  If we haven't yet completed the handshake, we'll await an auth or ack message
  as appropriate. That is, if we've established the connection and have sent an
  auth message, then we'll look for an ack. If we listened for a connection,
  we'll await an auth message.

  Once the encrypted handshake is complete, we'll handle the DEVp2p session.

  TODO: clients may send an auth before (or as) we do, and we should handle this case without error.
  """
  def handle_message(conn = %{secrets: %ExWire.Framing.Secrets{}}, data) do
    handle_packet_data(data, conn)
  end

  def handle_message(conn = %{handshake: %Handshake{}}, data) do
    conn
    |> handle_encrypted_handshake(data)
    |> prepare_devp2p_session()
  end

  defp prepare_devp2p_session(conn = %Connection{secrets: %ExWire.Framing.Secrets{}}) do
    session = initiate_dev_p2p_session()
    send_packet(conn, session.hello_sent)
    %{conn | session: session}
  end

  defp prepare_devp2p_session(conn), do: conn

  defp handle_encrypted_handshake(conn = %Connection{handshake: handshake}, data) do
    case handshake do
      %Handshake{initiator: true} ->
        handle_acknowledgement_received(data, conn)

      %Handshake{initiator: false} ->
        handle_auth_message_received(data, conn)
    end
  end

  defp handle_packet_data(data, conn) when byte_size(data) == 0, do: conn

  defp handle_packet_data(data, conn) do
    %Connection{peer: peer, secrets: secrets, session: session} = conn
    total_data = conn.queued_data <> data

    case Frame.unframe(total_data, secrets) do
      {:ok, packet_type, packet_data, frame_rest, updated_secrets} ->
        Logger.debug("[Network] [#{peer}] Got packet `#{inspect(packet_type)}` from #{peer.host}")

        updated_session =
          get_packet(packet_type, packet_data)
          |> handle_packet(session, conn)

        updated_conn = %{
          conn
          | secrets: updated_secrets,
            queued_data: <<>>,
            session: updated_session
        }

        handle_packet_data(frame_rest, updated_conn)

      {:error, "Insufficent data"} ->
        %{conn | queued_data: total_data}

      {:error, reason} ->
        Logger.error(
          "[Network] [#{peer}] Failed to read incoming packet from #{peer.host} `#{reason}`)"
        )

        conn
    end
  end

  defp handle_packet(packet, session, conn) do
    if DEVp2p.session_active?(session) do
      notify_subscribers(packet, conn)
      session
    else
      attempt_session_activation(session, packet)
    end
  end

  defp attempt_session_activation(session, packet) do
    case DEVp2p.handle_message(session, packet) do
      {:ok, updated_session} -> updated_session
      {:error, :handshake_incomplete} -> session
    end
  end

  defp get_packet(packet_type, packet_data) do
    case Packet.get_packet_mod(packet_type) do
      {:ok, packet_mod} ->
        apply(packet_mod, :deserialize, [packet_data])

      :unknown_packet_type ->
        :unknown_packet_type
    end
  end

  defp notify_subscribers(:unknown_packet_type, _conn), do: :noop

  defp notify_subscribers(packet, conn) do
    for subscriber <- Map.get(conn, :subscribers, []) do
      case subscriber do
        {module, function, args} -> apply(module, function, [packet | args])
        {:server, server} -> send(server, {:packet, packet, conn.peer})
      end
    end
  end

  defp handle_acknowledgement_received(data, conn = %{peer: peer}) do
    case Handshake.handle_ack(conn.handshake, data) do
      {:ok, handshake, secrets} ->
        Logger.debug("[Network] [#{peer}] Got ack from #{peer.host}, deriving secrets")

        Map.merge(conn, %{handshake: handshake, secrets: secrets})

      {:invalid, reason} ->
        Logger.warn(
          "[Network] [#{peer}] Failed to get handshake message when expecting ack - #{reason}"
        )

        conn
    end
  end

  defp handle_auth_message_received(data, conn = %{socket: socket}) do
    case Handshake.handle_auth(conn.handshake, data) do
      {:ok, handshake, secrets} ->
        peer = get_peer_info(handshake.auth_msg, socket)

        Logger.debug("[Network] Received auth. Sending ack.")
        send_unframed_data(handshake.encoded_ack_resp, socket, peer)

        Map.merge(conn, %{handshake: handshake, secrets: secrets, peer: peer})

      {:invalid, reason} ->
        Logger.warn("[Network] Received unknown handshake message when expecting auth: #{reason}")

        conn
    end
  end

  @doc """
  Function for sending a packet over to a peer.
  """
  def send_packet(conn, packet) do
    %{socket: socket, secrets: secrets, peer: peer} = conn

    {:ok, packet_type} = Packet.get_packet_type(packet)
    {:ok, packet_mod} = Packet.get_packet_mod(packet_type)

    Logger.info("[Network] [#{peer}] Sending packet #{inspect(packet_mod)} to #{peer.host}")

    packet_data = apply(packet_mod, :serialize, [packet])

    {frame, updated_secrets} = Frame.frame(packet_type, packet_data, secrets)

    TCP.send_data(socket, frame)

    Map.merge(conn, %{secrets: updated_secrets})
  end

  defp send_unframed_data(data, socket, peer) do
    Logger.debug(
      "[Network] [#{peer}] Sending raw data message of length #{byte_size(data)} byte(s) to #{
        peer.host
      }"
    )

    TCP.send_data(socket, data)
  end

  defp initiate_dev_p2p_session() do
    session = DEVp2p.init_session()
    hello = DEVp2p.build_hello()

    DEVp2p.hello_sent(session, hello)
  end

  defp get_peer_info(auth_msg, socket) do
    {host, port} = TCP.peer_info(socket)
    remote_id = Peer.hex_node_id(auth_msg.initiator_public_key)

    Peer.new(host, port, remote_id)
  end
end
