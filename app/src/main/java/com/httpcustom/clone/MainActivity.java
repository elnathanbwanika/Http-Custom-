package com.httpcustom.clone;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {
    private static final int REQUEST_VPN = 1001;
    private static final int REQUEST_NOTIFICATIONS = 1002;

    private EditText hostField;
    private EditText portsField;
    private EditText userField;
    private EditText passwordField;
    private CheckBox vpnCheckBox;
    private Button connectButton;
    private Button disconnectButton;
    private TextView statusView;
    private SharedPreferences preferences;

    private final TunnelBus.Listener statusListener = (message, running) -> {
        statusView.setText(message);
        connectButton.setEnabled(!running);
        disconnectButton.setEnabled(running);
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        preferences = getSharedPreferences("config", MODE_PRIVATE);
        setContentView(buildUi());
        TunnelBus.addListener(statusListener);
        requestNotificationPermission();
    }

    private ScrollView buildUi() {
        ScrollView scrollView = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(20);
        root.setPadding(padding, padding, padding, padding);
        scrollView.addView(root, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView title = new TextView(this);
        title.setText("HTTP Custom Clone");
        title.setTextSize(24);
        root.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("SSH port-range scanner, local SOCKS5, and Android VPN via tun2socks.");
        subtitle.setTextSize(13);
        subtitle.setPadding(0, dp(4), 0, dp(12));
        root.addView(subtitle);

        hostField = addField(root, "SSH host", "example.com or 1.2.3.4", InputType.TYPE_CLASS_TEXT);
        portsField = addField(root, "SSH port range",
                "22  •  1-65535  •  22,80,443  •  22-2222", InputType.TYPE_CLASS_TEXT);
        userField = addField(root, "Username", "root", InputType.TYPE_CLASS_TEXT);
        passwordField = addField(root, "Password", "password",
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);

        TextView scanHint = new TextView(this);
        scanHint.setText("Tip: a full 1-65535 scan can take 1-3 minutes. Single port or small ranges are much faster.");
        scanHint.setTextSize(12);
        scanHint.setPadding(0, dp(8), 0, dp(8));
        root.addView(scanHint);

        vpnCheckBox = new CheckBox(this);
        vpnCheckBox.setText("Create Android VPN (recommended)");
        vpnCheckBox.setChecked(true);
        root.addView(vpnCheckBox);

        connectButton = new Button(this);
        connectButton.setText("Connect");
        connectButton.setOnClickListener(v -> onConnectClicked());
        root.addView(connectButton);

        disconnectButton = new Button(this);
        disconnectButton.setText("Disconnect");
        disconnectButton.setEnabled(false);
        disconnectButton.setOnClickListener(v -> onDisconnectClicked());
        root.addView(disconnectButton);

        TextView statusLabel = new TextView(this);
        statusLabel.setText("Status");
        statusLabel.setTextSize(14);
        statusLabel.setPadding(0, dp(16), 0, dp(4));
        root.addView(statusLabel);

        statusView = new TextView(this);
        statusView.setText("Idle");
        statusView.setTextSize(14);
        statusView.setTextIsSelectable(true);
        root.addView(statusView);

        hostField.setText(preferences.getString("host", ""));
        portsField.setText(preferences.getString("ports", "22"));
        userField.setText(preferences.getString("user", ""));
        vpnCheckBox.setChecked(preferences.getBoolean("vpn", true));

        return scrollView;
    }

    private EditText addField(LinearLayout parent, String label, String hint, int inputType) {
        TextView labelView = new TextView(this);
        labelView.setText(label);
        labelView.setTextSize(14);
        labelView.setPadding(0, dp(10), 0, dp(4));
        parent.addView(labelView);

        EditText editText = new EditText(this);
        editText.setHint(hint);
        editText.setInputType(inputType);
        editText.setSingleLine(true);
        parent.addView(editText, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        return editText;
    }

    private void onConnectClicked() {
        String host = hostField.getText().toString().trim();
        String ports = portsField.getText().toString().trim();
        String user = userField.getText().toString().trim();
        if (host.isEmpty()) {
            toast("Host is required");
            return;
        }
        if (user.isEmpty()) {
            toast("Username is required");
            return;
        }
        try {
            PortRange.parse(ports);
        } catch (Exception e) {
            toast(e.getMessage());
            return;
        }

        preferences.edit()
                .putString("host", host)
                .putString("ports", ports)
                .putString("user", user)
                .putBoolean("vpn", vpnCheckBox.isChecked())
                .apply();

        if (vpnCheckBox.isChecked()) {
            Intent prepareIntent = VpnService.prepare(this);
            if (prepareIntent != null) {
                startActivityForResult(prepareIntent, REQUEST_VPN);
                return;
            }
        }
        startTunnel();
    }

    private void startTunnel() {
        Intent intent = new Intent(this, SshVpnService.class)
                .setAction(SshVpnService.ACTION_CONNECT)
                .putExtra(SshVpnService.EXTRA_HOST, hostField.getText().toString().trim())
                .putExtra(SshVpnService.EXTRA_PORTS, portsField.getText().toString().trim())
                .putExtra(SshVpnService.EXTRA_USER, userField.getText().toString().trim())
                .putExtra(SshVpnService.EXTRA_PASS, passwordField.getText().toString())
                .putExtra(SshVpnService.EXTRA_VPN, vpnCheckBox.isChecked());

        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        statusView.setText("Starting...");
        connectButton.setEnabled(false);
        disconnectButton.setEnabled(true);
    }

    private void onDisconnectClicked() {
        disconnectButton.setEnabled(false);
        boolean stopped = stopService(new Intent(this, SshVpnService.class));
        if (stopped) {
            statusView.setText("Disconnecting...");
        } else {
            statusView.setText("Disconnected");
            connectButton.setEnabled(true);
        }
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},
                    REQUEST_NOTIFICATIONS);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) {
                startTunnel();
            } else {
                toast("VPN permission was denied");
            }
        }
    }

    @Override
    protected void onDestroy() {
        TunnelBus.removeListener(statusListener);
        super.onDestroy();
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }

    private int dp(int value) {
        return Math.round(getResources().getDisplayMetrics().density * value);
    }
}
