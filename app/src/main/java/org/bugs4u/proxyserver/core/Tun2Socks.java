package org.bugs4u.proxyserver.core;

import android.os.ParcelFileDescriptor;
import android.util.Log;

public class Tun2Socks {
    private static final Object LOCK = new Object();

    private static boolean libraryLoaded;
    private static volatile boolean startRequested;
    private static volatile boolean started;
    private static volatile boolean stopRequested;

    private static synchronized void load() {
        if (!libraryLoaded) {
            System.loadLibrary("tun2socks");
            libraryLoaded = true;
        }
    }

    public static void Reset() {
        synchronized (LOCK) {
            stopRequested = false;
        }
    }

    public static void Start(ParcelFileDescriptor vpnInterface, int mtu, String ipAddress,
                             String netMask, String socksServer, String dnsGateway,
                             String udpGateway, boolean transparentDns) {
        load();
        synchronized (LOCK) {
            if (startRequested) {
                throw new IllegalStateException("tun2socks is already running");
            }
            if (stopRequested) {
                return;
            }
            startRequested = true;
            started = true;
        }
        try {
            int result = runTun2Socks(vpnInterface.detachFd(), mtu, ipAddress, netMask,
                    socksServer, dnsGateway, udpGateway, transparentDns ? 1 : 0);
            if (result != 0 && !stopRequested) {
                throw new IllegalStateException("tun2socks exited with code " + result);
            }
        } finally {
            synchronized (LOCK) {
                started = false;
                startRequested = false;
            }
        }
    }

    public static void Stop() {
        load();
        synchronized (LOCK) {
            stopRequested = true;
        }
        if (!startRequested) {
            return;
        }
        long deadline = System.currentTimeMillis() + 2000;
        while (!started && startRequested && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        if (started) {
            synchronized (LOCK) {
                started = false;
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            terminateTun2Socks();
        }
    }

    public static void logTun2Socks(String level, String message, String extra) {
        Log.d("Tun2Socks", level + ": " + message + " " + extra);
    }

    private static native int runTun2Socks(int fd, int mtu, String ipAddress, String netMask,
                                           String socksServer, String dnsGateway,
                                           String udpGateway, int transparentDns);

    private static native int terminateTun2Socks();
}
