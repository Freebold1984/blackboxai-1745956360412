package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.border.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class VulnDetectorUI {
    private final VulnDetector detector;
    private final JPanel mainPanel;
    private final JTextField apiUrlField;
    private final JPasswordField apiKeyField;
    private final JTextArea logArea;
    private final AtomicBoolean isRunning;

    public VulnDetectorUI(VulnDetector detector) {
        this.detector = detector;
        this.isRunning = new AtomicBoolean(false);

        // Create main panel
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());

        // Create configuration panel
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("Configuration"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // API URL configuration
        gbc.gridx = 0;
        gbc.gridy = 0;
        configPanel.add(new JLabel("API URL:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        apiUrlField = new JTextField(detector.getApiUrl());
        configPanel.add(apiUrlField, gbc);

        // API Key configuration
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.0;
        configPanel.add(new JLabel("API Key:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        apiKeyField = new JPasswordField(detector.getApiKey());
        configPanel.add(apiKeyField, gbc);

        // Save button
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        JButton saveButton = new JButton("Save Configuration");
        saveButton.addActionListener(e -> saveConfiguration());
        configPanel.add(saveButton, gbc);

        // Test connection button
        gbc.gridy = 3;
        JButton testButton = new JButton("Test Connection");
        testButton.addActionListener(e -> testConnection());
        configPanel.add(testButton, gbc);

        // Add configuration panel to main panel
        mainPanel.add(configPanel, BorderLayout.NORTH);

        // Create log panel
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Log"));
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setPreferredSize(new Dimension(600, 300));
        logPanel.add(scrollPane, BorderLayout.CENTER);

        // Clear log button
        JButton clearButton = new JButton("Clear Log");
        clearButton.addActionListener(e -> logArea.setText(""));
        logPanel.add(clearButton, BorderLayout.SOUTH);

        // Add log panel to main panel
        mainPanel.add(logPanel, BorderLayout.CENTER);

        // Create control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.setBorder(BorderFactory.createTitledBorder("Controls"));

        // Start/Stop scanning button
        JToggleButton toggleButton = new JToggleButton("Start Scanning");
        toggleButton.addActionListener(e -> {
            if (toggleButton.isSelected()) {
                startScanning();
                toggleButton.setText("Stop Scanning");
            } else {
                stopScanning();
                toggleButton.setText("Start Scanning");
            }
        });
        controlPanel.add(toggleButton);

        // Add control panel to main panel
        mainPanel.add(controlPanel, BorderLayout.SOUTH);
    }

    private void saveConfiguration() {
        try {
            String apiUrl = apiUrlField.getText().trim();
            String apiKey = new String(apiKeyField.getPassword()).trim();

            // Validate URL format
            if (!apiUrl.startsWith("http://") && !apiUrl.startsWith("https://")) {
                JOptionPane.showMessageDialog(mainPanel,
                    "Invalid API URL format. URL must start with http:// or https://",
                    "Configuration Error",
                    JOptionPane.ERROR_MESSAGE);
                return;
            }

            // Validate API key
            if (apiKey.length() < 32) {
                JOptionPane.showMessageDialog(mainPanel,
                    "Invalid API key. Key must be at least 32 characters long.",
                    "Configuration Error",
                    JOptionPane.ERROR_MESSAGE);
                return;
            }

            // Save configuration
            detector.setApiUrl(apiUrl);
            detector.setApiKey(apiKey);

            log("Configuration saved successfully");
            JOptionPane.showMessageDialog(mainPanel,
                "Configuration saved successfully",
                "Success",
                JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            log("Error saving configuration: " + e.getMessage());
            JOptionPane.showMessageDialog(mainPanel,
                "Error saving configuration: " + e.getMessage(),
                "Error",
                JOptionPane.ERROR_MESSAGE);
        }
    }

    private void testConnection() {
        new Thread(() -> {
            try {
                log("Testing connection to API...");
                
                // Create test request
                String testCode = "print('test')";
                String result = sendTestRequest(testCode);
                
                if (result != null) {
                    log("Connection test successful!");
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(mainPanel,
                            "Connection test successful!",
                            "Success",
                            JOptionPane.INFORMATION_MESSAGE);
                    });
                } else {
                    throw new Exception("No response from server");
                }
            } catch (Exception e) {
                log("Connection test failed: " + e.getMessage());
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(mainPanel,
                        "Connection test failed: " + e.getMessage(),
                        "Error",
                        JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }

    private String sendTestRequest(String code) {
        try {
            // Implementation of test request
            // This should use the detector's API client to send a test request
            return "Test successful"; // Placeholder
        } catch (Exception e) {
            return null;
        }
    }

    private void startScanning() {
        if (isRunning.compareAndSet(false, true)) {
            log("Starting vulnerability scanning...");
            // Implementation of starting the scanning process
        }
    }

    private void stopScanning() {
        if (isRunning.compareAndSet(true, false)) {
            log("Stopping vulnerability scanning...");
            // Implementation of stopping the scanning process
        }
    }

    public void log(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append("[" + new java.util.Date() + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    public Component getComponent() {
        return mainPanel;
    }
}
