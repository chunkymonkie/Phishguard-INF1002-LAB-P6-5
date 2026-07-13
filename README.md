# PhishGuard (INF1002)

## Overview

Link: [text](https://github.com/andrxhh/phishguard.git)

By: Lab 6-5

AARON ALISON DSILVA (2500461)
AFIQAH BINTE MOHAMED ADNAN (2503067)
ANDREW CHIA KAI XUN BEDINA (2501298)
CHESTON LEROY ONG (2502701)
CHUA JIA JUN (2500533)


**PhishGuard** is a transparent, rule-based email analyzer designed to classify messages as **Safe** or **Phishing**. The focus is on clean logic, explainability, and zero third-party dependencies—leveraging only the Python standard library.

- **Python Version:** 3.10 or higher
- **Dependencies:** Standard library only
- **Mode:** Offline, rule-based (no machine learning)

## Key Features

- **Flexible Ingestion:** Supports single files, folders, or mbox archives (auto-detected).
- **Normalization:** Decodes MIME headers and bodies, extracts addresses, and provides plain-text fallback for HTML content.
- **Feature Extraction:** Identifies URLs, label↔href pairs, and attachments.
- **Rule-Based Detection:**
  - Email address analysis and domain allowlist (whitelisting + analysis)
  - Keyword analysis and positioning
  - Detection of look-alike domains (brand impersonation)
  - URL red flags (IP addresses, shorteners, mismatched labels, suspicious TLDs)
  - Headers analysis (Header behaviour that implies risk of phishing)
- **Deterministic Scoring:** Aggregates rule results and applies thresholds to classify emails.
- **Reporting:**
  - JSON output for single messages
  - CSV output for batch processing
  - Per-rule explanations for transparency
- **Storage:** CSV append mode
- **Interfaces:** Command-line (CLI) and graphical user interface (GUI), both using the same backend pipeline.

## Setup

Clone the repository and install in editable mode:

```sh
pip install -e .
```

## Usage

### Command-Line Interface (CLI)

**Analyze a single email file:**

```sh
python -m phishguard.cli.main --eml path/to/message.eml
```

**Output result to a JSON file:**

```sh
python -m phishguard.cli.main \
    --eml path/to/message.eml \
    --out-json ./outPutResult/message_result.json
```

**Batch analysis for a folder of emails:**

```sh
python -m phishguard.cli.main \
    --folder path/to/email/ham \
    --out-csv ./outPutResult/results.csv
```

### Graphical User Interface (GUI)

To launch the GUI:

```sh
python -m phishguard.cli.main -- gui run
```

_Note: The GUI uses the same backend pipeline as the CLI._
