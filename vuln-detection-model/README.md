# Vulnerability Detection Model API

This project provides a simple FastAPI server that exposes endpoints for vulnerability detection, confirmation, and proof of concept (PoC) generation. It is designed to be integrated with a Burp Suite Pro extension written in Java 21.

## Features

- Detect potential vulnerabilities in code snippets.
- Confirm vulnerabilities.
- Generate example PoC for detected vulnerabilities.

## API Endpoints

- `POST /detect` - Detect vulnerabilities in provided code.
- `POST /confirm` - Confirm vulnerabilities (currently same as detect).
- `POST /poc` - Generate a working PoC for the vulnerability.

## Running the API Server

1. Install dependencies:

```bash
pip install fastapi uvicorn pydantic
```

2. Run the server:

```bash
python api_server.py
```

The server will be available at `http://localhost:8000`.

## Example Java Integration for Burp Suite Pro Extension

Below is an example Java snippet to call the `/detect` endpoint from your Burp Suite extension using Java 21's `HttpClient`:

```java
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;

public class VulnDetectionClient {

    private static final String API_URL = "http://localhost:8000/detect";

    public static String detectVulnerability(String code) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        String jsonRequest = String.format("{\"code\": \"%s\"}", code.replace("\"", "\\\""));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_URL))
                .header("Content-Type", "application/json")
                .POST(BodyPublishers.ofString(jsonRequest))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    public static void main(String[] args) throws Exception {
        String codeSample = "eval(userInput)";
        String result = detectVulnerability(codeSample);
        System.out.println("Detection result: " + result);
    }
}
```

Replace `codeSample` with the code snippet you want to analyze.

## Next Steps

- Replace the placeholder detection logic with a real Hugging Face model.
- Extend the API and Java client as needed for your Burp Suite extension.
