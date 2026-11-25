package com.httpcustom.clone;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

public final class PortScanner {
    public interface Progress {
        void onProgress(int scanned, int total, int open, int ssh);
    }

    public static final class Result {
        public final List<Integer> openPorts;
        public final List<Integer> sshPorts;

        public Result(List<Integer> openPorts, List<Integer> sshPorts) {
            this.openPorts = openPorts;
            this.sshPorts = sshPorts;
        }
    }

    private static final int BATCH_SIZE = 512;
    private static final int CONNECT_TIMEOUT_MS = 1000;
    private static final int BANNER_TIMEOUT_MS = 1400;

    private PortScanner() {
    }

    public static Result scan(String host, int[] ports, Progress progress, AtomicBoolean cancelled) throws IOException {
        InetAddress address = InetAddress.getByName(host);
        List<Integer> openPorts = new ArrayList<>();
        int total = ports.length;
        int scanned = 0;

        for (int offset = 0; offset < total && !cancelled.get(); offset += BATCH_SIZE) {
            int end = Math.min(total, offset + BATCH_SIZE);
            List<Integer> batch = new ArrayList<>(end - offset);
            for (int i = offset; i < end; i++) {
                batch.add(ports[i]);
            }
            openPorts.addAll(connectBatch(address, batch, cancelled));
            scanned = end;
            if (progress != null) {
                progress.onProgress(scanned, total, openPorts.size(), 0);
            }
        }

        List<Integer> sshPorts = new ArrayList<>();
        if (!cancelled.get()) {
            for (int port : openPorts) {
                if (cancelled.get()) {
                    break;
                }
                if (hasSshBanner(address, port)) {
                    sshPorts.add(port);
                }
            }
        }

        if (progress != null) {
            progress.onProgress(total, total, openPorts.size(), sshPorts.size());
        }
        return new Result(openPorts, sshPorts);
    }

    private static List<Integer> connectBatch(InetAddress address, List<Integer> ports, AtomicBoolean cancelled) {
        List<Integer> result = new ArrayList<>();
        if (ports.isEmpty()) {
            return result;
        }

        Selector selector = null;
        List<SocketChannel> channels = new ArrayList<>(ports.size());
        Set<SocketChannel> pending = new HashSet<>();

        try {
            selector = Selector.open();
            for (int i = 0; i < ports.size(); i++) {
                if (cancelled.get()) {
                    break;
                }
                SocketChannel channel = null;
                try {
                    channel = SocketChannel.open();
                    channel.configureBlocking(false);
                    boolean connected = channel.connect(new InetSocketAddress(address, ports.get(i)));
                    if (connected) {
                        result.add(ports.get(i));
                        channel.close();
                    } else {
                        channel.register(selector, SelectionKey.OP_CONNECT, ports.get(i));
                        channels.add(channel);
                        pending.add(channel);
                    }
                } catch (Exception e) {
                    if (channel != null) {
                        try {
                            channel.close();
                        } catch (Exception ignored) {
                        }
                    }
                }
            }

            long deadline = System.currentTimeMillis() + CONNECT_TIMEOUT_MS;
            while (!pending.isEmpty() && !cancelled.get()) {
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0) {
                    break;
                }
                int ready = selector.select(remaining);
                if (ready == 0) {
                    break;
                }
                Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();
                while (iterator.hasNext()) {
                    SelectionKey key = iterator.next();
                    iterator.remove();
                    SocketChannel channel = (SocketChannel) key.channel();
                    int port = (Integer) key.attachment();
                    try {
                        if (channel.finishConnect()) {
                            result.add(port);
                        }
                    } catch (Exception ignored) {
                    }
                    key.cancel();
                    try {
                        channel.close();
                    } catch (Exception ignored) {
                    }
                    pending.remove(channel);
                }
            }
        } catch (IOException ignored) {
        } finally {
            for (SocketChannel channel : channels) {
                try {
                    channel.close();
                } catch (Exception ignored) {
                }
            }
            if (selector != null) {
                try {
                    selector.close();
                } catch (Exception ignored) {
                }
            }
        }
        return result;
    }

    private static boolean hasSshBanner(InetAddress address, int port) {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(address, port), BANNER_TIMEOUT_MS);
            socket.setSoTimeout(400);
            InputStream input = socket.getInputStream();
            byte[] buffer = new byte[256];
            int read;
            try {
                read = input.read(buffer);
            } catch (SocketTimeoutException timeout) {
                socket.getOutputStream().write("SSH-2.0-Probe\r\n".getBytes(StandardCharsets.US_ASCII));
                socket.getOutputStream().flush();
                socket.setSoTimeout(BANNER_TIMEOUT_MS);
                read = input.read(buffer);
            }
            if (read <= 0) {
                return false;
            }
            String banner = new String(buffer, 0, read, StandardCharsets.US_ASCII);
            return banner.startsWith("SSH-");
        } catch (Exception e) {
            return false;
        } finally {
            try {
                socket.close();
            } catch (Exception ignored) {
            }
        }
    }
}
