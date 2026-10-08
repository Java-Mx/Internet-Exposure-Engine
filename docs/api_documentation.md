# REST API Documentation — IERSS

## Base URL

```
http://localhost:8000
```

## Endpoints

### Health Check
```
GET /api/v1/health
```
**Response:**
```json
{
  "status": "healthy",
  "api_version": "1.0.0",
  "models_loaded": true
}
```

---

### Analyze URL (Primary Endpoint)
```
POST /api/v1/analyze
Content-Type: application/json
```

**Request:**
```json
{
  "url": "https://example.com",
  "include_evidence": true
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "risk_score": 15,
  "severity": "LOW",
  "evidence": ["Standard TLD detected", "No suspicious patterns"],
  "confidence": 0.15,
  "is_risky": false
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `url` | string | Echo of the input URL |
| `risk_score` | int | 0–100 risk score |
| `severity` | string | LOW / MEDIUM / HIGH / CRITICAL |
| `evidence` | string[] | Human-readable risk indicators |
| `confidence` | float | 0.0–1.0 confidence in assessment |
| `is_risky` | bool | `true` if score ≥ 50 |

---

### Scan Multiple Assets
```
POST /api/scan
Content-Type: application/json
```

**Request:**
```json
{
  "assets": [
    {"domain": "example.com", "port": 443},
    {"ip": "192.168.1.1", "service": "http"}
  ],
  "include_breaches": false,
  "include_github": false
}
```

---

### System Statistics
```
GET /api/stats
```

### List Reports
```
GET /api/reports
```

### Download Report
```
GET /api/reports/{filename}
```

---

## C++ Client Example (libcurl)

```cpp
#include <curl/curl.h>
#include <string>

std::string analyze_url(const std::string& url) {
    CURL* curl = curl_easy_init();
    std::string response;
    
    std::string json = R"({"url":")" + url + R"(","include_evidence":true})";
    
    curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8000/api/v1/analyze");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.c_str());
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    // Set write callback to capture response...
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    return response;
}
```

## Running the API

```bash
cd F:\internet_exposure_system
python -m api.rest_api
# Server starts on http://localhost:8000
# Interactive docs at http://localhost:8000/docs
```
