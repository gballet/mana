defmodule ExWire.Adapter.TCP.Server do
  @moduledoc """
  Server handling TCP data
  """

  use GenServer

  require Logger

  alias ExWire.Framing.Frame
  alias ExWire.{TCP, P2P}

  @doc """
  Initialize by opening up a `gen_tcp` connection to given host and port.
  """
  def init(%{is_outbound: true, peer: peer}) do
    {:ok, socket} = TCP.connect(peer.host, peer.port)
    Logger.debug("[Network] [#{peer}] Established outbound connection with #{peer.host}.")

    state = P2P.new_outbound_connection(socket: socket, peer: peer)

    {:ok, state}
  end

  def init(%{is_outbound: false, socket: socket}) do
    state = P2P.new_inbound_connection(socket: socket)

    {:ok, state}
  end

  @doc """
  Allows a client to subscribe to incoming packets. Subscribers must be in the form
  of `{module, function, args}`, in which case we'll call `module.function(packet, ...args)`,
  or `{:server, server_pid}` for a GenServer, in which case we'll send a message
  `{:packet, packet, peer}`.
  """
  def handle_call({:subscribe, {_module, _function, _args} = mfa}, _from, state) do
    updated_state =
      Map.update(state, :subscribers, [mfa], fn subscribers -> [mfa | subscribers] end)

    {:reply, :ok, updated_state}
  end

  def handle_call({:subscribe, {:server, _server_pid} = server}, _from, state) do
    updated_state =
      Map.update(state, :subscribers, [server], fn subscribers -> [server | subscribers] end)

    {:reply, :ok, updated_state}
  end

  @doc """
  Handle inbound communication from a peer node via tcp.
  """
  def handle_info({:tcp, _socket, data}, state) do
    new_state = P2P.handle_message(state, data)

    {:noreply, new_state}
  end

  @doc """
  Function triggered when tcp closes the connection
  """
  def handle_info({:tcp_closed, _socket}, state) do
    peer = Map.get(state, :peer, :unknown)

    Logger.warn("[Network] [#{peer}] Peer closed connection")

    Process.exit(self(), :normal)

    {:noreply, state}
  end

  @doc """
  If we receive a `send` and we have secrets set, we'll send the message as a framed Eth packet.
  """
  def handle_cast({:send, %{packet: packet_data}}, state) do
    {packet_mod, packet_type, packet_data} = packet_data
    %{socket: socket, secrets: secrets, peer: peer} = state

    Logger.info("[Network] [#{peer}] Sending packet #{inspect(packet_mod)} to #{peer.host}")

    {frame, updated_secrets} = Frame.frame(packet_type, packet_data, secrets)

    TCP.send_data(socket, frame)

    {:noreply, Map.merge(state, %{secrets: updated_secrets})}
  end

  @doc """
  Server function handling disconnecting from tcp connection. See TCP.disconnect/1
  """
  def handle_cast(:disconnect, state = %{socket: socket}) do
    TCP.shutdown(socket)

    {:noreply, Map.delete(state, :socket)}
  end
end
