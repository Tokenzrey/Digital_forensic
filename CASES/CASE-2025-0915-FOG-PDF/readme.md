# Comprehensive Forensic Analysis: PDF Malware – FOG Campaign

**Case ID:** CASE-2025-0915-FOG-PDF  
**Case Title:** MalwareBazaar Fog PDF  
**Generated:** 2025-09-16T14:08:45Z  
**Analyst:** Analyst A

---

## Abstract

This report documents the forensic analysis of a suspicious PDF file acquired from MalwareBazaar, associated with the "Fog" malware campaign. The sample, originally distributed as a password-protected ZIP, was processed using a custom forensic workflow in a Linux (Kali) VM. The analysis covered evidence acquisition, integrity verification, static and dynamic analysis, and IOC extraction.

Notably, the PDF contained a suspicious external link to a ZIP file hosted on Netlify—indicative of a maldoc designed to deliver further payloads. No embedded JavaScript or automatic execution actions were detected; however, the document structure and metadata strongly suggest its use in delivering secondary malware via social engineering.

All findings, artifacts, and commands are fully documented to support reproducibility and transparency.

---

## Table of Contents

- Abstract
- Introduction
- 1. Case Overview & Executive Summary
- 2. Indicators of Compromise (IOC)
- 3. Findings, Impact & Recommendations
  - 3.1. Summary of Findings
  - 3.2. Impact & Risk
  - 3.3. Recommendations
- 4. Forensic Workflow & Methodology
  - 4.1. Directory Structure
  - 4.2. Workflow & Commands
  - 4.3. File/Artifact Explanation
- 5. Detailed Analysis & Evidence Logs
  - 5.1. Evidence Overview
  - 5.2. Automated Action Timeline
  - 5.3. PDF Static Analysis Details
- 6. Tools, References & Appendices
  - 6.1. Tool Usage
  - 6.2. References
  - 6.3. Appendices

---

## Introduction

Malicious documents (maldocs) remain a prevalent vector for malware delivery in phishing and targeted attacks. PDF files, due to their ubiquity and flexible object structure, are frequently abused to embed links, scripts, or payloads that exploit vulnerabilities or trick users into downloading secondary malware.

This case investigates a PDF sample with SHA256 `6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3`, obtained from MalwareBazaar. The sample was distributed as a ZIP archive with the password "infected". Using a forensic Linux toolkit, the workflow started with ingestion of the original ZIP, extraction and hash verification of the contained PDF, followed by comprehensive static analysis (file structure, metadata, embedded objects, and links), and network/process monitoring for dynamic behaviors.

The main objective was to determine whether the PDF contained direct exploit mechanisms (e.g., JavaScript, `/OpenAction`) or operated as a lure for secondary downloads. The analysis revealed a suspicious embedded link ([https://hilarious-trifle-d9182e.netlify.app/Pay Adjustment.zip](https://hilarious-trifle-d9182e.netlify.app/Pay%20Adjustment.zip)) but no active scripting or auto-execution triggers.

---

## 1. Case Overview & Executive Summary

This forensic case investigates a suspicious PDF sample associated with the "Fog" campaign, downloaded from MalwareBazaar. The scope covers the digital forensic analysis of the file to identify its behavior, extract indicators of compromise (IOCs), and assess the potential risk.

- **Sample SHA256:** `6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3`
- **MalwareBazaar Tags:** fog, hilarious-trifle-d9182e-netlify-app, pdf
- **Suspicious URL:** [https://hilarious-trifle-d9182e.netlify.app/Pay Adjustment.zip](https://hilarious-trifle-d9182e.netlify.app/Pay%20Adjustment.zip)

The workflow detailed in this report covers evidence ingestion, hash verification, static analysis, IOC extraction, and reporting. All evidence integrity was verified via hash manifests, and the chain of custody was maintained throughout the process.

---

## 2. Indicators of Compromise (IOC)

| Type   | Value                                                                 | Source       | Confidence | Notes                          |
|--------|-----------------------------------------------------------------------|--------------|------------|--------------------------------|
| hash   | 6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3     | manifest     | high       | SHA256 of main PDF             |
| sha1   | e4721effe1aa5b54fb00f80a6e628a1e3c2d86e3                              | manifest     | high       | SHA1 of main PDF               |
| md5    | f294e7c2f611835afc267b1d46419879                                     | manifest     | high       | MD5 of main PDF                |
| url    | https://hilarious-trifle-d9182e.netlify.app/Pay Adjustment.zip        | pdf-object   | high       | /URI in object 22, likely payload |
| file   | 6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3.pdf | manifest     | high       | Filename from sample metadata  |
| tag    | fog, hilarious-trifle-d9182e-netlify-app, pdf                        | metadata     | medium     | MalwareBazaar tags             |
| ssdeep | 1536:stK5sS3caw12btZxEms/z7/OtEmlNIW2wI:X3vw12btZxEms/v/OtEmEWBIm    | metadata     | medium     | Fuzzy hash (MalwareBazaar)     |
| TLSH   | T19974A499D5C0ADC0D5160CB7DFA2282DAFB93C5615E68E43B315BAE3CCF2043993E189 | metadata | medium     | TLSH hash (MalwareBazaar)      |

---

## 3. Findings, Impact & Recommendations

### 3.1 Summary of Findings

- The PDF is version 1.7, not encrypted, and not linearized.
- No direct JavaScript or `/OpenAction` triggers detected.
- Utilizes `/AcroForm` and `/Action` objects to present a malicious link.
- **Object 22** contains a suspicious `/URI`:  
  [https://hilarious-trifle-d9182e.netlify.app/Pay Adjustment.zip](https://hilarious-trifle-d9182e.netlify.app/Pay%20Adjustment.zip)
- The file structure has a damaged cross-reference table, a common evasion technique.
- All hashes and metadata tags align with the "Fog" campaign signature.

### 3.2 Impact & Risk

- **High Risk:** PDF contains a clickable link (/URI) to a suspicious ZIP file. If a user opens this PDF and clicks the link, they could download and execute a secondary malware payload.
- No direct exploit for Linux PDF readers was detected during analysis. The primary threat is social engineering.
- Potential for exploitation is higher if the PDF is opened in vulnerable or outdated PDF readers/email clients, especially on Windows environments.

### 3.3 Recommendations

- Block access to the domain `hilarious-trifle-d9182e.netlify.app` at the network perimeter (firewall, web proxy).
- Add the SHA256 hash to blocklists for email gateways and endpoint security solutions.
- Deploy detection signatures for the "Fog" campaign in AV/EDR/YARA rules.
- Educate users about the risks of opening unknown PDF attachments and clicking embedded links.
- Monitor for similar PDF maldocs and payloads hosted on services like Netlify.

---

## 4. Forensic Workflow & Methodology

### 4.1 Directory Structure

```
cases/
  └── CASE-2025-0915-FOG-PDF/
      ├── 00_admin/              # Case metadata (CoC, scope)
      ├── 01_evidence_original/  # Pristine, read-only evidence
      ├── 02_evidence_working/   # Working copies for analysis
      ├── 03_clones/             # Immutable reference clones for verification
      ├── 04_analysis/           # All analysis outputs (static, dynamic, IOCs)
      ├── 05_transfers/          # Reports and packaged case files
      ├── 06_hashes/             # Hash manifests for all files
      ├── 07_logs/               # Automated action logs
      └── 08_temp/               # Temporary files
```

### 4.2 Workflow & Commands

**1. Evidence Acquisition & Verification**

Create Case & Ingest ZIP:
```bash
export CASE_ID="CASE-2025-0915-FOG-PDF"
./bin/case_setup.sh -c "$CASE_ID" --evidence "type=file;src=...;name=EVID-PDF-FOG-001.zip;..."
```

Extract ZIP & Verify PDF Hash:
```bash
7z x -p'infected' -o"..." "./02_evidence_working/EVID-PDF-FOG-001_work.zip"
sha256sum "./02_evidence_working/extracted_zip/..."
# Confirmed match with expected hash.
```

Ingest Extracted PDF as Evidence:
```bash
./bin/evidence_ingest.sh -c "$CASE_ID" --evidence "type=file;src=...;name=EVID-PDF-FOG-001.pdf;..."
```

**2. Static Analysis**

All tool outputs are saved to `04_analysis/static/`.
```bash
export PDF_WORK="./02_evidence_working/EVID-PDF-FOG-001_work.pdf"
export ANA_DIR="./04_analysis/static"

# Basic info & structure check
file "$PDF_WORK" > "$ANA_DIR/file.txt"
exiftool "$PDF_WORK" > "$ANA_DIR/exiftool.txt"
qpdf --check "$PDF_WORK" 2>&1 > "$ANA_DIR/qpdf_check.txt"

# PDF structure analysis
pdfid.py "$PDF_WORK" > "$ANA_DIR/pdfid.txt"
pdf-parser.py -a "$PDF_WORK" > "$ANA_DIR/objects.txt"

# Content extraction and scanning
strings -n 6 "$PDF_WORK" > "$ANA_DIR/strings.txt"
yara ./rules/pdf_malware.yar "$PDF_WORK" > "$ANA_DIR/yara.txt"
```

**3. Reporting & Packaging**

Generate Report & Package Case:
```bash
./bin/generate_final_report.sh -c "$CASE_ID"
./bin/package_case.sh -c "$CASE_ID"
```

### 4.3 File/Artifact Explanation

- **00_admin/**: Administrative files like chain_of_custody.txt and evidence_index.json.
- **01_evidence_original/**: Original, untouched evidence files (.zip, .pdf).
- **02_evidence_working/**: Writable copies of evidence used for analysis.
- **04_analysis/static/**: Outputs from tools like pdfid.py, exiftool, strings, qpdf, providing detailed structural and metadata information.
- **04_analysis/iocs.json**: Structured file containing all identified IOCs for automated processing.
- **06_hashes/**: Hash manifests (.sha256, .md5, .sha1) proving the integrity of all case files.
- **07_logs/**: Timestamped logs (actions.log, actions.jsonl) of every command run by the forensic toolkit.

---

## 5. Detailed Analysis & Evidence Logs

### 5.1 Evidence Overview

| Type | Name                    | Size (bytes) | SHA256                                                         | Notes                              |
|------|-------------------------|--------------|----------------------------------------------------------------|------------------------------------|
| file | EVID-PDF-FOG-001.zip    | 352000       | (See manifest)                                                 | Original ZIP from MalwareBazaar    |
| file | EVID-PDF-FOG-001.pdf    | 351978       | 6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3 | Extracted from ZIP, main target    |

### 5.2 Automated Action Timeline

This log shows the initial, automated setup of the case environment.

| UTC Timestamp        | Action              | Target                   | Status | Details                                |
|----------------------|---------------------|--------------------------|--------|----------------------------------------|
| 2025-09-15T13:43:02Z | session_begin       | CASE-2025-0915-FOG-PDF   | OK     | Start session                          |
| 2025-09-15T13:43:02Z | acquire_file        | EVID-PDF-FOG-001.pdf     | OK     | size=351978 notes=Extracted from ZIP   |
| 2025-09-15T13:43:02Z | hash_compute        | EVID-PDF-FOG-001.pdf     | OK     | SHA256=6eb8b598...                     |
| 2025-09-15T13:43:02Z | preserve            | EVID-PDF-FOG-001.pdf     | OK     | Mode=immutable                         |
| 2025-09-15T13:43:03Z | clone_create        | EVID-PDF-FOG-001_work.pdf| OK     | work                                   |
| 2025-09-15T13:43:03Z | clone_verify        | EVID-PDF-FOG-001_work.pdf| OK     | MATCH                                  |
| 2025-09-15T13:43:03Z | case_setup_complete | CASE-2025-0915-FOG-PDF   | OK     | Done                                   |
| 2025-09-15T13:43:03Z | session_end         | CASE-2025-0915-FOG-PDF   | OK     | End session                            |

### 5.3 PDF Static Analysis Details

**PDF Metadata (exiftool):**

- File Type: PDF
- Version: 1.7
- MIME Type: application/pdf
- Not encrypted, not linearized
- Warning: Invalid xref table

**Structure (pdfid, pdf-parser):**

- 35 objects, 10 streams
- `/AcroForm` present
- `/Action` present (object 22)
- `/URI`: [https://hilarious-trifle-d9182e.netlify.app/Pay Adjustment.zip](https://hilarious-trifle-d9182e.netlify.app/Pay%20Adjustment.zip) (object 22)
- No `/JS`, `/JavaScript`, `/AA`, or `/OpenAction` detected, confirming the threat is a malicious link, not an exploit script.
- Multiple embedded image streams.

**Preview of Malicious PDF:**

<img width="600" alt="Preview of the malicious PDF" src="https://github.com/user-attachments/assets/a0f68db2-9332-4455-b545-67247672e750" />

---

## 6. Tools, References & Appendices

### 6.1 Tool Usage

- **pdfid.py & pdf-parser.py:** Scan for and parse PDF structure, identifying key malicious objects like `/Action` and `/URI`.
- **exiftool:** Extracts core PDF metadata.
- **qpdf:** Checks PDF structural integrity and identifies issues like a damaged xref table.
- **strings:** Extracts readable text and URLs from the binary file.
- **yara:** Scans the file against custom rules to identify malware patterns.

### 6.2 References

- [MalwareBazaar Entry](https://bazaar.abuse.ch/sample/6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3/)
- [Didier Stevens PDF Tools](https://blog.didierstevens.com/programs/pdf-tools/)

### 6.3 Appendices

- **Hash manifests:** `./06_hashes/`
- **Action logs:** `./07_logs/actions.log`
- **Static analysis outputs:** `./04_analysis/static/`
- **IOC file:** `./04_analysis/iocs.json`
- **Chain of Custody:** `./00_admin/chain_of_custody.txt`

---
