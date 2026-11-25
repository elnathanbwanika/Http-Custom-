package com.httpcustom.clone;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UIKeyboardInteractive;
import com.jcraft.jsch.UserInfo;

import java.util.Locale;
import java.util.Properties;

public final class SshConnector {
    public static final class AuthException extends Exception {
        private static final long serialVersionUID = 1L;

        public AuthException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private SshConnector() {
    }

    public static Session connect(String host, int port, String user, String password, int timeoutMs) throws Exception {
        JSch jsch = new JSch();
        Session session = jsch.getSession(user, host, port);
        session.setPassword(password);

        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");
        config.put("PreferredAuthentications", "password,keyboard-interactive");
        config.put("PubkeyAuthentication", "no");
        config.put("kex", "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                + "diffie-hellman-group-exchange-sha256,"
                + "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
                + "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,"
                + "diffie-hellman-group1-sha1");
        config.put("server_host_key", "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,"
                + "ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa");
        session.setConfig(config);
        session.setUserInfo(new PasswordUserInfo(password));
        session.setServerAliveInterval(30000);
        session.setServerAliveCountMax(3);
        session.setTimeout(timeoutMs);

        try {
            session.connect(timeoutMs);
            session.setTimeout(0);
            return session;
        } catch (JSchException e) {
            try {
                session.disconnect();
            } catch (Exception ignored) {
            }
            String message = e.getMessage() == null ? "" : e.getMessage();
            if (message.toLowerCase(Locale.ROOT).contains("auth")) {
                throw new AuthException("SSH authentication failed: " + message, e);
            }
            throw e;
        }
    }

    private static final class PasswordUserInfo implements UserInfo, UIKeyboardInteractive {
        private final String password;

        PasswordUserInfo(String password) {
            this.password = password;
        }

        @Override
        public String getPassphrase() {
            return null;
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public boolean promptPassword(String message) {
            return true;
        }

        @Override
        public boolean promptPassphrase(String message) {
            return false;
        }

        @Override
        public boolean promptYesNo(String message) {
            return true;
        }

        @Override
        public void showMessage(String message) {
        }

        @Override
        public String[] promptKeyboardInteractive(String destination, String name, String instruction,
                                                  String[] prompt, boolean[] echo) {
            String[] answers = new String[prompt.length];
            for (int i = 0; i < prompt.length; i++) {
                answers[i] = password;
            }
            return answers;
        }
    }
}
