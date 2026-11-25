package com.httpcustom.clone;

import com.jcraft.jsch.ChannelDirectTCPIP;
import com.jcraft.jsch.Session;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class UdpGwServer {
    private static final int FLAG_KEEPALIVE = 1;
    private static final int FLAG_IPV6 = 8;
    private static final String[] DNS_SERVERS = {"1.1.1.1", "8.8.8.8", "9.9.9.9"};

    private final Session session;
    private final int port;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final ExecutorService clients = Executors.newCachedThreadPool();
    private final Set<Socket> activeClients = ConcurrentHashMap.newKeySet();
    private final ExecutorService dnsWorkers = Executors.newFixedThreadPool(4);
    private final ScheduledExecutorService timeouts = Executors.newSingleThreadScheduledExecutor();
    private ServerSocket serverSocket;
    private Thread acceptThread;

    public UdpGwServer(Session session, int port) {
        this.session = session;
        this.port = port;
    }

    public void start() throws IOException {
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
            running.set(true);
            acceptThread = new Thread(this::acceptLoop, "udpgw-accept");
            acceptThread.setDaemon(true);
            acceptThread.start();
        } catch (IOException e) {
            running.set(false);
            closeQuietly(serverSocket);
            serverSocket = null;
            closeActiveClients();
            clients.shutdownNow();
            dnsWorkers.shutdownNow();
            timeouts.shutdownNow();
            throw e;
        }
    }

    public void stop() {
        running.set(false);
        closeQuietly(serverSocket);
        closeActiveClients();
        clients.shutdownNow();
        dnsWorkers.shutdownNow();
        timeouts.shutdownNow();
    }

    private void closeActiveClients() {
        for (Socket client : activeClients) {
            closeQuietly(client);
        }
        activeClients.clear();
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket client = serverSocket.accept();
                activeClients.add(client);
                try {
                    clients.execute(() -> {
                        try {
                            serve(client);
                        } finally {
                            activeClients.remove(client);
                        }
                    });
                } catch (RuntimeException e) {
                    activeClients.remove(client);
                    closeQuietly(client);
                }
            } catch (IOException e) {
                if (!running.get() || serverSocket == null || serverSocket.isClosed()) {
                    break;
                }
            }
        }
    }

    private void serve(Socket client) {
        if (!running.get()) {
            closeQuietly(client);
            return;
        }
        try {
            client.setSoTimeout(0);
            DataInputStream input = new DataInputStream(new BufferedInputStream(client.getInputStream()));
            DataOutputStream output = new DataOutputStream(new BufferedOutputStream(client.getOutputStream()));

            while (running.get()) {
                int length = input.readUnsignedShort();
                if (length < 3 || length > 65535) {
                    break;
                }
                byte[] packet = new byte[length];
                input.readFully(packet);
                handlePacket(packet, output);
            }
        } catch (Exception ignored) {
        } finally {
            closeQuietly(client);
        }
    }

    private void handlePacket(byte[] packet, DataOutputStream output) {
        int flags = packet[0] & 0xff;
        int connectionId = ((packet[1] & 0xff) << 8) | (packet[2] & 0xff);
        if ((flags & FLAG_KEEPALIVE) != 0) {
            return;
        }

        boolean ipv6 = (flags & FLAG_IPV6) != 0;
        int addressLength = ipv6 ? 16 : 4;
        int position = 3;
        if (packet.length < position + addressLength + 2) {
            return;
        }

        byte[] address = new byte[addressLength];
        System.arraycopy(packet, position, address, 0, addressLength);
        position += addressLength;

        int destinationPort = ((packet[position] & 0xff) << 8) | (packet[position + 1] & 0xff);
        position += 2;

        if (destinationPort != 53) {
            return;
        }

        byte[] query = new byte[packet.length - position];
        System.arraycopy(packet, position, query, 0, query.length);
        if (query.length == 0) {
            return;
        }

        dnsWorkers.execute(() -> resolveAndReply(flags, connectionId, address, ipv6, query, output));
    }

    private void resolveAndReply(int flags, int connectionId, byte[] address, boolean ipv6,
                                 byte[] query, DataOutputStream output) {
        byte[] response = queryDns(query);
        if (response == null) {
            return;
        }

        int addressLength = ipv6 ? 16 : 4;
        int headerLength = 3 + addressLength + 2;
        if (headerLength + response.length > 65535) {
            return;
        }

        byte[] reply = new byte[headerLength + response.length];
        reply[0] = (byte) (ipv6 ? (flags | FLAG_IPV6) : (flags & ~FLAG_IPV6));
        reply[1] = (byte) (connectionId >> 8);
        reply[2] = (byte) connectionId;
        System.arraycopy(address, 0, reply, 3, addressLength);
        int position = 3 + addressLength;
        reply[position] = 0;
        reply[position + 1] = 53;
        System.arraycopy(response, 0, reply, position + 2, response.length);

        synchronized (output) {
            try {
                output.writeShort(reply.length);
                output.write(reply);
                output.flush();
            } catch (IOException ignored) {
            }
        }
    }

    private byte[] queryDns(byte[] query) {
        for (String server : DNS_SERVERS) {
            ChannelDirectTCPIP channel = null;
            try {
                if (!session.isConnected()) {
                    return null;
                }
                channel = (ChannelDirectTCPIP) session.openChannel("direct-tcpip");
                final ChannelDirectTCPIP activeChannel = channel;
                activeChannel.setHost(server);
                activeChannel.setPort(53);
                activeChannel.setOrgIPAddress("127.0.0.1");
                activeChannel.setOrgPort(port);
                activeChannel.connect(8000);

                ScheduledFuture<?> timeout = timeouts.schedule(() -> {
                    try {
                        activeChannel.disconnect();
                    } catch (Exception ignored) {
                    }
                }, 10, TimeUnit.SECONDS);
                try {
                    DataOutputStream output = new DataOutputStream(
                            new BufferedOutputStream(channel.getOutputStream()));
                    output.writeShort(query.length);
                    output.write(query);
                    output.flush();

                    DataInputStream input = new DataInputStream(
                            new BufferedInputStream(channel.getInputStream()));
                    int length = input.readUnsignedShort();
                    if (length <= 0 || length > 65535) {
                        continue;
                    }
                    byte[] response = new byte[length];
                    input.readFully(response);
                    return response;
                } finally {
                    timeout.cancel(false);
                }
            } catch (Exception ignored) {
            } finally {
                if (channel != null) {
                    try {
                        channel.disconnect();
                    } catch (Exception ignored) {
                    }
                }
            }
        }
        return null;
    }

    private static void closeQuietly(ServerSocket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (Exception ignored) {
            }
        }
    }

    private static void closeQuietly(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (Exception ignored) {
            }
        }
    }
}
