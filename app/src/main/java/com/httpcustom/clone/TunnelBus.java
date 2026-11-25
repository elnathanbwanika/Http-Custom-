package com.httpcustom.clone;

import android.os.Handler;
import android.os.Looper;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public final class TunnelBus {
    public interface Listener {
        void onStatus(String message, boolean running);
    }

    private static final List<Listener> LISTENERS = new CopyOnWriteArrayList<>();
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static volatile String lastMessage = "Idle";
    private static volatile boolean lastRunning = false;

    private TunnelBus() {
    }

    public static void addListener(Listener listener) {
        LISTENERS.add(listener);
        listener.onStatus(lastMessage, lastRunning);
    }

    public static void removeListener(Listener listener) {
        LISTENERS.remove(listener);
    }

    public static void publish(String message, boolean running) {
        lastMessage = message;
        lastRunning = running;
        MAIN.post(() -> {
            for (Listener listener : LISTENERS) {
                listener.onStatus(message, running);
            }
        });
    }

    public static boolean isRunning() {
        return lastRunning;
    }
}
