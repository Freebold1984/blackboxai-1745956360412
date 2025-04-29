package burp;

import java.io.PrintWriter;
import java.util.*;
import java.net.URL;
import java.net.http.*;
import java.net.URI;
import java.time.Duration;
import com.google.gson.*;

public class VulnDetector implements IBurpExtender, IScannerCheck, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private String apiUrl = "http://localhost:8000";
    private String apiKey = "";
    private JsonParser jsonParser;
    private HttpClient httpClient;
    private VulnDetectorUI ui;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.jsonParser = new JsonParser();
        
        // Initialize HTTP client
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

        // Set extension name
        callbacks.setExtensionName("ML-Powered Vulnerability Detector");

        // Initialize UI
        this.ui = new VulnDetectorUI(this);
        callbacks.addSuiteTab(this);

        // Register scanner check
        callbacks.registerScannerCheck(this);

        stdout.println("ML-Powered Vulnerability Detector loaded successfully!");
        stdout.println("Version: 2.0.0");
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();
        
        try {
            // Get response details
            byte[] response = baseRequestResponse.getResponse();
            if (response == null) return issues;

            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            String responseBody = new String(Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length));

            // Prepare request for vulnerability detection
            JsonObject requestBody = new JsonObject();
            requestBody.addProperty("code", responseBody);
            requestBody.addProperty("confidence_threshold", 0.7);

            // Send request to API
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl + "/detect"))
                .header("Content-Type", "application/json")
                .header("X-API-Key", apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .build();

            HttpResponse<String> apiResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (apiResponse.statusCode() == 200) {
                JsonObject result = jsonParser.parse(apiResponse.body()).getAsJsonObject();
                
                if (result.get("vulnerable").getAsBoolean()) {
                    // Process findings
                    JsonArray findings = result.getAsJsonArray("findings");
                    for (JsonElement finding : findings) {
                        JsonObject findingObj = finding.getAsJsonObject();
                        
                        // Create issue
                        issues.add(new VulnerabilityIssue(
                            baseRequestResponse,
                            helpers,
                            findingObj.get("type").getAsString(),
                            findingObj.get("description").getAsString(),
                            findingObj.get("severity").getAsString(),
                            generatePoC(responseBody, findingObj.get("type").getAsString())
                        ));
                    }
                }
            }
        } catch (Exception e) {
            stderr.println("Error in passive scan: " + e.getMessage());
        }

        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // Implement active scanning if needed
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()) &&
            existingIssue.getUrl().equals(newIssue.getUrl())) {
            return -1; // Existing issue is newer
        }
        return 0; // Issues are different
    }

    private String generatePoC(String code, String vulnerabilityType) {
        try {
            JsonObject requestBody = new JsonObject();
            requestBody.addProperty("code", code);
            requestBody.addProperty("vulnerability_type", vulnerabilityType);

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl + "/poc"))
                .header("Content-Type", "application/json")
                .header("X-API-Key", apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonObject result = jsonParser.parse(response.body()).getAsJsonObject();
                if (result.get("success").getAsBoolean()) {
                    return result.get("poc").getAsString();
                }
            }
        } catch (Exception e) {
            stderr.println("Error generating PoC: " + e.getMessage());
        }
        return "Failed to generate PoC";
    }

    // Getter and setter for API configuration
    public String getApiUrl() {
        return apiUrl;
    }

    public void setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    @Override
    public String getTabCaption() {
        return "ML Vuln Detector";
    }

    @Override
    public java.awt.Component getUiComponent() {
        return ui.getComponent();
    }

    // Custom vulnerability issue class
    private static class VulnerabilityIssue implements IScanIssue {
        private final IHttpRequestResponse requestResponse;
        private final IExtensionHelpers helpers;
        private final String type;
        private final String description;
        private final String severity;
        private final String poc;

        public VulnerabilityIssue(
            IHttpRequestResponse requestResponse,
            IExtensionHelpers helpers,
            String type,
            String description,
            String severity,
            String poc
        ) {
            this.requestResponse = requestResponse;
            this.helpers = helpers;
            this.type = type;
            this.description = description;
            this.severity = severity;
            this.poc = poc;
        }

        @Override
        public URL getUrl() {
            return helpers.analyzeRequest(requestResponse).getUrl();
        }

        @Override
        public String getIssueName() {
            return "ML-Detected: " + type;
        }

        @Override
        public int getIssueType() {
            return 0x08000000; // Custom issue type
        }

        @Override
        public String getSeverity() {
            return severity;
        }

        @Override
        public String getConfidence() {
            return "Certain";
        }

        @Override
        public String getIssueBackground() {
            return "This issue was detected by the ML-powered vulnerability detector.";
        }

        @Override
        public String getRemediationBackground() {
            return "Please review the generated PoC and implement appropriate security controls.";
        }

        @Override
        public String getIssueDetail() {
            return description + "\n\nProof of Concept:\n" + poc;
        }

        @Override
        public String getRemediationDetail() {
            return null;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return new IHttpRequestResponse[] { requestResponse };
        }

        @Override
        public IHttpService getHttpService() {
            return requestResponse.getHttpService();
        }
    }
}
