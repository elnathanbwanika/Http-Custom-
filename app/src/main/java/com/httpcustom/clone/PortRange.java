package com.httpcustom.clone;

import java.util.Locale;
import java.util.TreeSet;

public final class PortRange {
    private final int[] ports;

    private PortRange(int[] ports) {
        this.ports = ports;
    }

    public int[] ports() {
        return ports;
    }

    public int size() {
        return ports.length;
    }

    public static PortRange parse(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            raw = "22";
        }
        raw = raw.trim().toLowerCase(Locale.ROOT);
        raw = raw.replaceAll("\\s*-\\s*", "-");
        if (raw.equals("*") || raw.equals("all")) {
            raw = "1-65535";
        }

        TreeSet<Integer> unique = new TreeSet<>();
        for (String part : raw.split("[,\\s]+")) {
            if (part.isEmpty()) {
                continue;
            }
            if (part.equals("*") || part.equals("all")) {
                addRange(unique, 1, 65535);
                continue;
            }
            int dash = part.indexOf('-');
            if (dash > 0) {
                int start = parsePort(part.substring(0, dash));
                int end = parsePort(part.substring(dash + 1));
                if (start > end) {
                    int swap = start;
                    start = end;
                    end = swap;
                }
                addRange(unique, start, end);
            } else {
                unique.add(parsePort(part));
            }
        }

        if (unique.isEmpty()) {
            throw new IllegalArgumentException("No ports specified");
        }

        int[] result = new int[unique.size()];
        int index = 0;
        for (int port : unique) {
            result[index++] = port;
        }
        return new PortRange(result);
    }

    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value.trim());
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Port out of range: " + port);
            }
            return port;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid port: " + value);
        }
    }

    private static void addRange(TreeSet<Integer> ports, int start, int end) {
        for (int port = start; port <= end; port++) {
            ports.add(port);
        }
    }
}
