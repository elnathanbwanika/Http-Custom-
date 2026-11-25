package com.httpcustom.clone;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.util.Log;

import com.jcraft.jsch.Session;

import org.bugs4u.proxyserver.core.Tun2Socks;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public class SshVpnService extends VpnService {
    public static final String ACTION_CONNECT = "com.httpcustom.clone.CONNECT";
    public static final String ACTION_DISCONNECT = "com.httpcustom.clone.DISCONNECT";
    public static final String EXTRA_HOST = "host";
    public static final String EXTRA_PORTS = "ports";
    public static final String EXTRA_USER = "user";
    public static final String EXTRA_PASS = "pass";
    public static final String EXTRA_VPN = "vpn";

    private static final String CHANNEL_ID = "ssh_tunnel";
    private static final int NOTIFICATION_ID = 1001;

    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private volatile boolean stopping = false;
    private volatile boolean running = false;

    private volatile Thread worker;
    private volatile Thread tunWorker;
    private Session session;
    private Socks5Server socks;
    private UdpGwServer udpGw;
    private ParcelFileDescriptor tun;
    private PowerManager.WakeLock wakeLock;

    private String host;
    private String user;
    private String password;
    private int[] ports;
    private boolean useVpn;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        PowerManager powerManager = (PowerManager) getSystemService(POWER_SERVICE);
        if (powerManager != null) {
            wakeLock = powerManager.newWakeLock(
                    PowerManager.PARTIAL_WAKE_LOCK, "HttpCustomClone:ssh");
            wakeLock.setReferenceCounted(false);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_DISCONNECT.equals(intent.getAction())) {
            stopTunnel();
            stopSelf();
            return START_NOT_STICKY;
        }

        if (intent == null) {
            stopTunnel();
            stopSelf();
            return START_NOT_STICKY;
        }

        if (worker != null && worker.isAlive()) {
            publish("Tunnel is already running", true);
            return START_STICKY;
        }

        startForegroundNotification("Starting...");

        host = intent.getStringExtra(EXTRA_HOST);
        user = intent.getStringExtra(EXTRA_USER);
        password = intent.getStringExtra(EXTRA_PASS);
        if (host != null) {
            host = host.trim();
        }
        if (user != null) {
            user = user.trim();
        }
        if (password == null) {
            password = "";
        }
        useVpn = intent.getBooleanExtra(EXTRA_VPN, true);

        try {
            ports = PortRange.parse(intent.getStringExtra(EXTRA_PORTS)).ports();
        } catch (Exception e) {
            fail("Invalid port range: " + e.getMessage());
            return START_NOT_STICKY;
        }

        if (host == null || host.trim().isEmpty() || user == null || user.trim().isEmpty()) {
            fail("Host and username are required");
            return START_NOT_STICKY;
        }

        if (worker == null || !worker.isAlive()) {
            stopping = false;
            cancelled.set(false);
            if (wakeLock != null && !wakeLock.isHeld()) {
                wakeLock.acquire();
            }
            worker = new Thread(this::runTunnel, "ssh-tunnel");
            worker.start();
        }
        return START_STICKY;
    }

    private void runTunnel() {
        try {
            publish("Scanning " + ports.length + " port(s)...", true);

            PortScanner.Result scan = PortScanner.scan(
                    host,
                    ports,
                    (scanned, total, open, ssh) -> {
                        if (scanned == total || (scanned % 512) == 0) {
                            updateNotification("Scanning " + scanned + "/" + total
                                    + "  open=" + open + " ssh=" + ssh);
                        }
                    },
                    cancelled);

            if (stopping) {
                return;
            }
            if (scan.sshPorts.isEmpty()) {
                fail("No SSH service found in the selected port range");
                return;
            }

            publish("SSH found on " + joinPorts(scan.sshPorts) + "; authenticating...", true);

            Session connected = null;
            int connectedPort = -1;
            String authError = null;
            String lastError = null;
            for (int port : scan.sshPorts) {
                if (stopping) {
                    return;
                }
                try {
                    connected = SshConnector.connect(host, port, user, password, 15000);
                    if (stopping) {
                        connected.disconnect();
                        return;
                    }
                    connectedPort = port;
                    break;
                } catch (SshConnector.AuthException e) {
                    authError = e.getMessage();
                    publish("Port " + port + " authentication failed", true);
                } catch (Exception e) {
                    lastError = e.getMessage() == null ? e.toString() : e.getMessage();
                    publish("Port " + port + " failed: " + lastError, true);
                }
            }

            if (connected == null) {
                fail(authError != null ? authError
                        : lastError != null ? lastError
                        : "Could not establish an SSH session on any discovered port");
                return;
            }

            session = connected;
            if (stopping) {
                connected.disconnect();
                session = null;
                return;
            }
            publish("SSH connected on port " + connectedPort, true);

            Socks5Server newSocks = new Socks5Server(connected, 1080);
            newSocks.start();
            socks = newSocks;
            if (stopping) {
                newSocks.stop();
                socks = null;
                return;
            }

            if (useVpn) {
                startVpn();
            }
            if (stopping) {
                return;
            }

            synchronized (this) {
                if (stopping) {
                    return;
                }
                running = true;
                publish(useVpn
                        ? "Connected on port " + connectedPort + " (VPN active)"
                        : "Connected on port " + connectedPort + " (SOCKS 127.0.0.1:1080)", true);
            }

            while (!stopping && session.isConnected()) {
                Thread.sleep(1000);
            }

            if (!stopping) {
                publish("SSH session closed", true);
            }
        } catch (Throwable e) {
            if (!stopping) {
                fail(e.getMessage() == null ? e.toString() : e.getMessage());
            }
        } finally {
            if (!stopping) {
                stopTunnel();
                stopSelf();
            }
        }
    }

    private void startVpn() throws Exception {
        VpnService.Builder builder = new VpnService.Builder();
        builder.setSession(getString(R.string.app_name));
        builder.setMtu(1500);
        builder.addAddress("10.0.0.2", 32);
        builder.addRoute("0.0.0.0", 0);
        builder.addDnsServer("1.1.1.1");
        builder.addDnsServer("8.8.8.8");
        builder.setBlocking(true);
        try {
            builder.addDisallowedApplication(getPackageName());
        } catch (Exception ignored) {
        }

        ParcelFileDescriptor newTun = builder.establish();
        if (newTun == null) {
            throw new IOException("Could not establish VPN interface");
        }
        tun = newTun;
        if (stopping) {
            newTun.close();
            tun = null;
            return;
        }

        Session activeSession = session;
        if (activeSession == null) {
            return;
        }
        UdpGwServer newUdpGw = new UdpGwServer(activeSession, 7300);
        newUdpGw.start();
        udpGw = newUdpGw;
        if (stopping) {
            newUdpGw.stop();
            udpGw = null;
            return;
        }

        final ParcelFileDescriptor vpnInterface = newTun;
        Tun2Socks.Reset();
        tunWorker = new Thread(() -> {
            if (stopping) {
                return;
            }
            try {
                Tun2Socks.Start(vpnInterface, 1500, "10.0.0.2", "255.255.255.0",
                        "127.0.0.1:1080", "", "127.0.0.1:7300", false);
            } catch (Throwable t) {
                Log.e("SshVpnService", "tun2socks failed", t);
                fail("tun2socks failed: " + (t.getMessage() == null ? t.toString() : t.getMessage()));
            }
        }, "tun2socks");
        tunWorker.start();
        Thread.sleep(500);
    }

    private void fail(String message) {
        stopTunnel();
        TunnelBus.publish("Error: " + message, false);
        stopSelf();
    }

    private synchronized void stopTunnel() {
        boolean firstStop = !stopping;
        stopping = true;
        cancelled.set(true);
        if (worker != null) {
            worker.interrupt();
        }
        cleanupResources();

        if (firstStop) {
            publish("Disconnected", false);
            stopForeground(STOP_FOREGROUND_REMOVE);
        }
    }

    private void cleanupResources() {
        if (socks != null) {
            socks.stop();
            socks = null;
        }
        if (udpGw != null) {
            udpGw.stop();
            udpGw = null;
        }
        try {
            Tun2Socks.Stop();
        } catch (Throwable ignored) {
        }
        if (tun != null) {
            try {
                tun.close();
            } catch (Exception ignored) {
            }
            tun = null;
        }
        if (session != null) {
            try {
                session.disconnect();
            } catch (Exception ignored) {
            }
            session = null;
        }
        password = null;
        running = false;
        try {
            if (wakeLock != null && wakeLock.isHeld()) {
                wakeLock.release();
            }
        } catch (Exception ignored) {
        }
    }

    private synchronized void publish(String message, boolean isRunning) {
        if (stopping && !"Disconnected".equals(message)) {
            return;
        }
        TunnelBus.publish(message, isRunning);
        updateNotification(message);
    }

    private void updateNotification(String message) {
        if (stopping) {
            return;
        }
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, buildNotification(message));
        }
    }

    private void startForegroundNotification(String message) {
        Notification notification = buildNotification(message);
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private Notification buildNotification(String message) {
        Intent openIntent = new Intent(this, MainActivity.class);
        PendingIntent openPending = PendingIntent.getActivity(this, 0, openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent stopIntent = new Intent(this, SshVpnService.class).setAction(ACTION_DISCONNECT);
        PendingIntent stopPending = PendingIntent.getService(this, 1, stopIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder builder = new Notification.Builder(this, CHANNEL_ID);
        builder.setContentTitle(getString(R.string.notification_title))
                .setContentText(message)
                .setSmallIcon(R.drawable.ic_stat_ssh)
                .setOngoing(running)
                .setContentIntent(openPending)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel,
                        getString(R.string.disconnect), stopPending);
        return builder.build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.channel_name),
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription(getString(R.string.channel_description));
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    private static String joinPorts(List<Integer> ports) {
        StringBuilder builder = new StringBuilder();
        int limit = Math.min(8, ports.size());
        for (int i = 0; i < limit; i++) {
            if (i > 0) {
                builder.append(", ");
            }
            builder.append(ports.get(i));
        }
        if (ports.size() > limit) {
            builder.append("...");
        }
        return builder.toString();
    }

    @Override
    public void onRevoke() {
        stopTunnel();
        stopSelf();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopTunnel();
        super.onDestroy();
    }
}
