# PhishAegis

Phishing Detection & Email Forensics Engine

---

## Overview

PhishAegis analyzes emails and flags phishing attempts using a layered detection pipeline: rules, machine learning, URL inspection, and header analysis.

It returns a **risk score, classification, and explicit reasons** for every decision.

---

## Methodology

The system follows a DFIR-aligned pipeline focused on **detection and initial forensic analysis**.

1. **Input**
   Raw email text or `.eml` file

2. **Parsing**
   Extracts:

   * Subject
   * Sender / Receiver
   * Body content
   * URLs
   * Header metadata

3. **Rule-Based Analysis**
   Detects:

   * Urgency language
   * Credential requests
   * Common phishing phrases

4. **URL Analysis**
   Flags:

   * IP-based links
   * Suspicious domains
   * Obfuscated URLs

5. **Machine Learning**

   * TF-IDF vectorization
   * Naive Bayes classification
   * Predicts phishing vs legitimate

6. **Header Forensics**
   Detects:

   * Reply-To mismatch
   * Sender inconsistencies
   * Suspicious routing patterns

7. **Risk Engine**
   Combines all signals into a final score

8. **Output**

   * Risk score (0–10)
   * Classification (Safe / Suspicious / Phishing)
   * Reasons

---

## Architecture

![Architecture](images/architecture.png)

---

## Features

* Multi-layer phishing detection
* Explainable output (clear reasons)
* Email header anomaly detection
* URL inspection
* API-based architecture
* Dockerized deployment

---

## Tech Stack

**Core**

* Python

**Backend**

* FastAPI

**Machine Learning**

* scikit-learn
* TF-IDF
* Multinomial Naive Bayes

**Text Processing**

* NLTK / spaCy
* Regex

**Email Processing**

* Python `email` module

**Database**

* PostgreSQL

**Frontend**

* React
* Tailwind CSS

**Deployment**

* Docker

---

## API

### POST `/analyze`

Analyze raw email

**Request**

```json
{
  "email": "email content"
}
```

**Response**

```json
{
  "risk_score": 7,
  "classification": "Phishing",
  "reasons": [
    "Urgent language detected",
    "Suspicious URL",
    "Reply-To mismatch"
  ]
}
```

---

### POST `/upload`

Upload `.eml` file

---

### GET `/health`

Check service status

---

## Risk Scoring

**Range: 0 – 10**

* 0–3 → Safe
* 4–6 → Suspicious
* 7–10 → Phishing

Score is derived from:

* Rule matches
* ML prediction confidence
* URL risk indicators
* Header anomalies

---

## Data Collection

* Uses labeled datasets (phishing vs legitimate emails)
* Preprocessing:

  * Text cleaning
  * Stopword removal
  * TF-IDF vectorization

---

## Analysis Approach

* Rule-based detection → catches known patterns
* ML model → detects unseen patterns
* URL checks → identifies malicious links
* Header analysis → detects spoofing

Combining signals reduces false positives compared to single-method systems.

---

## Evaluation

Metrics:

* Accuracy
* Precision
* Recall

> Add actual values. Without metrics, this section is incomplete.

---

## Project Structure

```
backend/
frontend/
docker-compose.yml
README.md
```

---

## Setup

### Clone

```bash
git clone <repo-url>
cd phishaegis
```

### Run

```bash
docker-compose up --build
```

### Access

* Backend: http://localhost:8000
* Frontend: http://localhost:3000

---

## Use Cases

* Phishing detection systems
* Security operations (SOC) support
* Email threat analysis
* Cybersecurity research projects

---

## Limitations

* Uses baseline ML model (limited contextual understanding)
* No zero-day phishing detection
* No domain reputation or threat intelligence integration
* Limited forensic depth (no SPF/DKIM/DMARC validation)

---

## Roadmap

* Transformer-based model (BERT or similar)
* Domain reputation and threat intel APIs
* SPF / DKIM / DMARC validation
* SIEM integration
* Real-time email ingestion

---

## Conclusion

PhishAegis demonstrates that combining rule-based detection, machine learning, and basic email forensics produces more reliable phishing detection than single-method systems.

It fits the **detection and triage layer of DFIR**, not full incident response.

---

## Author

Your Name

---

## License

Educational / Research Use
