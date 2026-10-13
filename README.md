
# PrivacyVault AI — Intelligent Data Privacy & Leakage Prevention

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![Flask 3.0](https://img.shields.io/badge/Framework-Flask_3.0-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Tests-Pytest](https://img.shields.io/badge/Tests-22%20Passed-brightgreen.svg)](https://pytest.org/)
[![License-Academic](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

> **Final-Year Computer Science & Engineering (CSE) Capstone Project**  
> An enterprise-grade, privacy-preserving security intelligence platform that scans documents and datasets across 5 formats, detects exposed PII, credentials, and financial identifiers, classifies privacy risks using mathematical models and machine learning, intercepts data leakage vectors, and produces audit-ready compliance dossiers.

---

## 1. System Architecture

```mermaid
graph TD
    A[Client Web UI / REST API] --> B[File Ingestion & Validation Gateway]
    B -->|Magic Header & Size Check| C{Format Dispatcher}
    
    C -->|PDF| D1[pypdf Page Extractor]
    C -->|DOCX| D2[python-docx Paragraph/Table Extractor]
    C -->|TXT| D3[Plaintext & Source Line Extractor]
    C -->|CSV| D4[pandas Tabular Coordinate Parser]
    C -->|JSON| D5[Hierarchical Pointer Traversal]
    
    D1 & D2 & D3 & D4 & D5 --> E[ExtractedDocument Structure]
    
    E --> F[Modular Detection Engine]
    F -->|Regex Patterns| G1[PII, Financial, Secrets, NDA]
    F -->|Cryptographic Validators| G2[Luhn Alg., Verhoeff Alg., IP Check]
    F -->|Shannon Entropy| G3[High-Randomness Token Filter]
    
    E --> H[scikit-learn ML Classifier]
    H -->|TF-IDF + MultinomialNB| H1[Thematic Confidentiality Prediction]
    
    F --> I[Masking & In-Flight Sanitization]
    
    I & H1 --> J[Explainable Risk Scoring Engine]
    J -->|Weighted Log-Dampened Math| K[Risk Score 0-100 & Tier]
    
    I --> L[Data Leakage Vector Analyzer]
    L -->|Co-occurrence, Public Columns, Configs| M[Leakage Alerts]
    
    K & M & I --> N[(SQLite Database Persistence)]
    
    N --> O1[Interactive CyberSec Dashboard Chart.js]
    N --> O2[ReportLab PDF Audit Dossier]
    N --> O3[CSV & JSON Compliance Manifests]
    N --> O4[Sanitized/Redacted File Generator]
```

---

## 2. Supported Formats & Extraction Coordinates

| Format | Extraction Engine | Location Coordinates Captured | Metadata Extracted |
| :--- | :--- | :--- | :--- |
| **PDF** | `pypdf` | Page Number, Line Number | Author, Producer, Title, Page Count, Creation Date |
| **DOCX** | `python-docx` | Paragraph #, Table #, Row #, Column Header | Author, Last Modified By, Revision, Created |
| **TXT** | Python `open(errors='replace')` | Line Number | Total Lines, Character Count |
| **CSV** | `pandas` & `csv.Sniffer` | Row Index, Column Header Name | Total Rows, Total Columns, Header Schema |
| **JSON** | Python `json` recursive traversal | JSON Pointer Key Path (`$.users[0].token`) | Top-Level Type, Leaf Count, Structural Depth |

---

## 3. Sensitive Information Detection & Validation

PrivacyVault AI combines modular regex rules with **algorithmic checksums** and **Shannon entropy** to drastically reduce false positives:

- **Financial Instruments**:
  - Credit & Debit Cards (Visa, MasterCard, Amex, Discover, RuPay) verified via the **Luhn Algorithm (Mod 10)**. Random 16-digit sequences that fail Luhn are discarded.
  - International Bank Account Numbers (IBAN) & US ABA Routing numbers.
- **Personally Identifiable Information (PII)**:
  - US Social Security Numbers (SSN) with area/group rule checks.
  - Indian Aadhaar numbers validated using the **Verhoeff Checksum Algorithm**.
  - Indian PAN Cards (`[A-Z]{5}[0-9]{4}[A-Z]`).
  - RFC 5322 Email addresses & International / Indian mobile numbers (`+91`).
  - Identified Person Names and IPv4/IPv6 network addresses.
- **Authentication Secrets**:
  - AWS Access Key IDs (`AKIA[0-9A-Z]{16}`) and context-aware secret tokens.
  - GitHub Personal Access Tokens (`ghp_...` and `github_pat_...`).
  - Slack API tokens (`xoxb-...`).
  - Cryptographic Private Keys (`-----BEGIN RSA/OPENSSH PRIVATE KEY-----`).
  - JSON Web Tokens (`eyJ...`).
  - Static passwords assigned in code or configurations (`password = "..."`).
- **Confidential Business Labels**:
  - Explicit markings (`CONFIDENTIAL`, `RESTRICTED`, `PROPRIETARY`, `INTERNAL ONLY`).
  - NDA legal terms, Trade Secret covenants, and M&A insider preview keywords.

### In-Flight Value Masking Guarantee
Raw sensitive values are **never** logged to the console or written unmasked to audit logs:
- `rohan.verma@example.com` $\rightarrow$ `roh***@example.com`
- `4532 0151 1283 0366` $\rightarrow$ `****-****-****-0366`
- `AKIAIOSFODNN7EXAMPLE` $\rightarrow$ `AKIA************`
- `123-45-6789` $\rightarrow$ `***-**-6789`
- `ABCDE1234F` $\rightarrow$ `*****1234*`

---

## 4. Explainable Risk Scoring Formulation

Unlike opaque scoring, PrivacyVault AI evaluates document privacy risk using a mathematically grounded, reproducible formulation:

$$\text{Base Subtotal} = \sum_{t \in \text{Tiers}} W_t \cdot \left(1 + 0.5 \cdot \log_2(1 + N_t)\right)$$

Where:
- $W_{\text{CRITICAL}} = 25.0$, $W_{\text{HIGH}} = 15.0$, $W_{\text{MEDIUM}} = 8.0$, $W_{\text{LOW}} = 3.0$
- $N_t$ is the finding count within tier $t$, dampened with $\log_2$ to prevent repetitive items from artificially distorting the score.

### Exposure Multipliers ($M_{\text{context}}$):
1. **Co-Occurrence Multiplier ($1.25\times$)**: Applied when direct personal identifiers (PII) and financial attributes co-occur, creating identity theft exposure.
2. **Credential Penalty ($1.30\times$)**: Applied when active cloud tokens or private keys are exposed, with a mandatory floor score of $80.0$ (CRITICAL).
3. **Multi-Category Breadth ($1.15\times$)**: Applied when findings span 3 or more distinct sensitivity classes.

$$\text{Final Score} = \min\left(100.0, \, \max\left(0.0, \, \text{Base Subtotal} \times \prod M_i\right)\right)$$

| Score Range | Severity Tier | Mandated Security Action |
| :---: | :---: | :--- |
| **76 – 100** | **CRITICAL** | Halt publication immediately. Revoke exposed keys via AWS/GitHub; scrub card data. |
| **51 – 75** | **HIGH** | Mandatory redaction of government IDs and direct financial instruments. |
| **26 – 50** | **MEDIUM** | Apply pseudonymization to personal emails and contact attributes before sharing. |
| **0 – 25** | **LOW** | General internal sharing permissible; perform routine periodic compliance audits. |

---

## 5. Machine Learning Document Classification

PrivacyVault AI features a dedicated **scikit-learn Pipeline** (`TfidfVectorizer` + `MultinomialNB`) trained across 5 canonical confidentiality classes:
1. `PII`
2. `Financial`
3. `Authentication Secrets`
4. `Confidential Business`
5. `Public / Low Sensitivity`

**Architectural Separation**: The ML model classifies the overall text thematic confidentiality and extracts the top 5 salient TF-IDF keywords, while modular regex rules locate exact coordinate-level findings. Both outputs are presented transparently side-by-side in the UI.

---

## 6. Data Leakage Vector Analysis

PrivacyVault AI analyzes 6 structural exposure vectors and **strictly distinguishes potential exposure risks from confirmed external breaches**:
1. **Multi-Field Co-Occurrence**: Combines direct personal identity (Name/Email) with high-impact sensitive data (Card/SSN) on the same row or page.
2. **Public Column Exposure**: Flags sensitive data residing in dataset columns labeled `public`, `comments`, `notes`, `bio`, or `feedback`.
3. **Config Credentials**: Identifies static passwords, API tokens, or RSA keys embedded in plain `.txt` or `.json` configuration files.
4. **Document Metadata Leak**: Extracts author usernames, machine file paths, or creator software fingerprints embedded in PDF/DOCX headers.
5. **High Concentration Datasets**: Identifies bulk unredacted dumps exceeding 15 sensitive entries.
6. **Cross-Record Identifier Repetition**: Flags duplicate sensitive numbers repeated across multiple entries.

---

## 7. Execution Instructions (Windows PowerShell)

Follow these exact steps to run PrivacyVault AI locally:

### Step 1: Clone & Open Repository
```powershell
cd "c:\Users\rohan\OneDrive\Desktop\wipro project"
```

### Step 2: Create & Activate Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Run Automated Test Suite
```powershell
pytest -v
```
*(All 22 unit and integration tests will execute and pass)*

### Step 5: Start the PrivacyVault AI Server
```powershell
python app.py
```

### Step 6: Access the Application
Open your web browser and navigate to:
```
http://127.0.0.1:5000/
```

---

## 8. Web User Interface Tour (10 Pages)

1. **Home Page (`/`)**: Product overview, telemetry counters, architecture diagram, and 1-click synthetic sample scan launcher.
2. **Privacy Dashboard (`/dashboard`)**: Database-derived analytics featuring Chart.js Category Doughnut, Severity Bar, and Top Data Types charts.
3. **Upload Document (`/upload`)**: Drag-and-drop zone with MIME validation, progress bar, and 1-click synthetic sample buttons.
4. **Scan Summary (`/scan/<id>`)**: Overall risk gauge circle, ML category, document metadata, and remediation checklist.
5. **Detailed Findings (`/scan/<id>/findings`)**: Filterable table with category/severity dropdowns, live search, masked code pills, and **AI Explain Modal**.
6. **Privacy Risk Analysis (`/scan/<id>/risk`)**: Step-by-step mathematical score calculation, formula breakdown, and ML confidence metrics.
7. **Data Leakage Analysis (`/scan/<id>/leakage`)**: Vector alert cards detailing co-occurrence, public column leaks, and config credentials.
8. **Scan History (`/history`)**: Searchable audit log of past scans with PDF download and permanent deletion actions.
9. **Export Center (`/scan/<id>/export`)**: Download center for **ReportLab PDF reports**, **CSV manifests**, **JSON audit logs**, and **Sanitized/Redacted files**.
10. **Rules & Settings (`/settings`)**: Interactive toggle switches to enable/disable detection rules dynamically and configure optional AI keys.

---

## 9. Regulatory Mapping & Compliance

Privacy remediation recommendations are directly aligned with international privacy standards:
- **GDPR (EU)**: Articles 5(1)(c) (Data Minimization), Article 6 (Lawfulness), and Article 32 (Security of Processing / Encryption).
- **PCI-DSS v4.0**: Requirement 3.4 (Render Primary Account Numbers unreadable anywhere stored).
- **HIPAA**: 45 CFR § 164.312 (Technical Safeguards for Protected Health Information).
- **India DPDP Act 2023**: Digital Personal Data Protection Act safeguards regarding personal identifiers.
- **NIST SP 800-88**: Guidelines for Media Sanitization.

---

## 10. Security & Privacy Guarantees

- **100% Offline Capability**: Runs entirely on local machine without paid API keys, third-party tracking, or cloud credentials.
- **Zero Raw Secret Logging**: Credit cards, passwords, and private keys are never printed to terminal or saved unmasked to the database.
- **Parameterized SQL**: All database operations use SQLite parameterized queries to eliminate SQL injection vulnerabilities.
- **Safe File Parsing**: Strictly validates file size (25MB limit), magic headers, and safe filenames using `werkzeug.utils.secure_filename`.
- **Synthetic Data Standard**: Includes 5 pre-built synthetic test files containing zero real personal or corporate data.

---

*Developed for CSE Capstone Project Evaluation 2026.*
=======
# bug-free-octo-robot
>>>>>>> 0a75f83639e27eef80c08f14558bedb1824a0276
