package com.httpcustom.clone;

import com.jcraft.jsch.ChannelDirectTCPIP;
import com.jcraft.jsch.Session;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public final class Socks5Server {
    private final Session session;
    private final int port;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final ExecutorService clients = Executors.newCachedThreadPool();
    private final Set<Socket> activeClients = ConcurrentHashMap.newKeySet();
    private ServerSocket serverSocket;
    private Thread acceptThread;

    public Socks5Server(Session session, int port) {
        this.session = session;
        this.port = port;
    }

    public void start() throws IOException {
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
            running.set(true);
            acceptThread = new Thread(this::acceptLoop, "socks5-accept");
            acceptThread.setDaemon(true);
            acceptThread.start();
        } catch (IOException e) {
            running.set(false);
            closeQuietly(serverSocket);
            serverSocket = null;
            closeActiveClients();
            clients.shutdownNow();
            throw e;
        }
    }

    public void stop() {
        running.set(false);
        closeQuietly(serverSocket);
        closeActiveClients();
        clients.shutdownNow();
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
                            handle(client);
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

    private void handle(Socket client) {
        if (!running.get()) {
            closeQuietly(client);
            return;
        }
        ChannelDirectTCPIP channel = null;
        boolean replied = false;
        try {
            client.setSoTimeout(15000);
            InputStream input = new BufferedInputStream(client.getInputStream());
            OutputStream output = new BufferedOutputStream(client.getOutputStream());

            int version = input.read();
            if (version != 5) {
                return;
            }
            int methodCount = input.read();
            if (methodCount < 1) {
                return;
            }
            byte[] methods = new byte[methodCount];
            readFully(input, methods);
            output.write(new byte[]{5, 0});
            output.flush();

            int requestVersion = input.read();
            int command = input.read();
            input.read();
            int addressType = input.read();
            if (requestVersion != 5) {
                return;
            }

            String targetHost;
            if (addressType == 1) {
                byte[] address = new byte[4];
                readFully(input, address);
                targetHost = InetAddress.getByAddress(address).getHostAddress();
            } else if (addressType == 3) {
                int length = input.read();
                if (length <= 0) {
                    return;
                }
                byte[] address = new byte[length];
                readFully(input, address);
                targetHost = new String(address, StandardCharsets.UTF_8);
            } else if (addressType == 4) {
                byte[] address = new byte[16];
                readFully(input, address);
                targetHost = InetAddress.getByAddress(address).getHostAddress();
            } else {
                reply(output, 8);
                return;
            }

            int targetPort = (input.read() << 8) | input.read();
            if (command != 1) {
                reply(output, 7);
                return;
            }
            if (!session.isConnected()) {
                reply(output, 1);
                return;
            }

            channel = (ChannelDirectTCPIP) session.openChannel("direct-tcpip");
            channel.setHost(targetHost);
            channel.setPort(targetPort);
            channel.setOrgIPAddress("127.0.0.1");
            channel.setOrgPort(client.getPort());
            channel.connect(15000);

            reply(output, 0);
            replied = true;
            client.setSoTimeout(0);

            ChannelDirectTCPIP activeChannel = channel;
            Thread remoteToClient = new Thread(
                    () -> pumpRemoteToClient(activeChannel, output),
                    "socks5-remote");
            remoteToClient.setDaemon(true);
            remoteToClient.start();

            pumpClientToRemote(input, channel);
            try {
                remoteToClient.join(1000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        } catch (Exception e) {
            if (!replied) {
                try {
                    OutputStream output = new BufferedOutputStream(client.getOutputStream());
                    reply(output, 1);
                } catch (Exception ignored) {
                }
            }
        } finally {
            if (channel != null) {
                try {
                    channel.disconnect();
                } catch (Exception ignored) {
                }
            }
            closeQuietly(client);
        }
    }

    private static void pumpRemoteToClient(ChannelDirectTCPIP channel, OutputStream clientOutput) {
        byte[] buffer = new byte[8192];
        try (InputStream remoteInput = channel.getInputStream()) {
            int read;
            while ((read = remoteInput.read(buffer)) >= 0) {
                clientOutput.write(buffer, 0, read);
                clientOutput.flush();
            }
        } catch (Exception ignored) {
        }
    }

    private static void pumpClientToRemote(InputStream clientInput, ChannelDirectTCPIP channel) {
        byte[] buffer = new byte[8192];
        try (OutputStream remoteOutput = channel.getOutputStream()) {
            int read;
            while ((read = clientInput.read(buffer)) >= 0) {
                remoteOutput.write(buffer, 0, read);
                remoteOutput.flush();
            }
        } catch (Exception ignored) {
        }
    }

    private static void reply(OutputStream output, int code) throws IOException {
        output.write(new byte[]{5, (byte) code, 0, 1, 0, 0, 0, 0, 0, 0});
        output.flush();
    }

    private static void readFully(InputStream input, byte[] buffer) throws IOException {
        int offset = 0;
        while (offset < buffer.length) {
            int read = input.read(buffer, offset, buffer.length - offset);
            if (read < 0) {
                throw new EOFException();
            }
            offset += read;
        }
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
