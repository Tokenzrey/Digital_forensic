# Final Forensic Report

Case ID     : CASE-2025-0915-FOG-PDF  
Case Title  : MalwareBazaar Fog PDF  
Generated   : 2025-09-16T14:08:45Z  
Analyst     : Analyst A

---

## Executive Summary
- Scope: Digital forensic analysis of a suspicious PDF file from MalwareBazaar, suspected to be used in the "Fog" campaign.
- Integrity verified via hash manifests (see: ./06_hashes/6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3.pdf.sha256)
- Chain of Custody: ./00_admin/chain_of_custody.txt

---

## Evidence Overview

| Type   | Name                                    | Size (bytes) | SHA256                                                              | Notes                           |
|--------|-----------------------------------------|--------------|---------------------------------------------------------------------|----------------------------------|
| file   | EVID-PDF-FOG-001.zip                    | 352000       | (ZIP hash, see manifest)                                            | Original ZIP from MalwareBazaar  |
| file   | EVID-PDF-FOG-001.pdf                    | 351978       | 6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3   | Extracted from ZIP, main target  |

---

## Timeline (from actions.log)

| UTC Timestamp         | Action          | Target                              | Status | Details                                                                    |
|----------------------|-----------------|--------------------------------------|--------|----------------------------------------------------------------------------|
| 2025-09-15T13:43:02Z | session_begin   | CASE-2025-0915-FOG-PDF              | OK     | Start session                                                              |
| 2025-09-15T13:43:02Z | env_snapshot    | env_snapshot.txt                     | OK     | Captured                                                                   |
| 2025-09-15T13:43:02Z | write_file      | 00_admin/scope.txt                   | OK     | Created                                                                    |
| 2025-09-15T13:43:02Z | acquire_file    | EVID-PDF-FOG-001.pdf                 | OK     | size=351978 notes=Extracted from ZIP                                        |
| 2025-09-15T13:43:02Z | hash_compute    | EVID-PDF-FOG-001.pdf                 | OK     | SHA256=6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3... |
| 2025-09-15T13:43:02Z | preserve        | EVID-PDF-FOG-001.pdf                 | OK     | Mode=immutable                                                             |
| 2025-09-15T13:43:02Z | clone_create    | EVID-PDF-FOG-001_clone_ref.pdf       | OK     | ref                                                                        |
| 2025-09-15T13:43:03Z | clone_create    | EVID-PDF-FOG-001_work.pdf            | OK     | work                                                                       |
| 2025-09-15T13:43:03Z | clone_verify    | EVID-PDF-FOG-001_clone_ref.pdf       | OK     | MATCH                                                                      |
| 2025-09-15T13:43:03Z | clone_verify    | EVID-PDF-FOG-001_work.pdf            | OK     | MATCH                                                                      |
| 2025-09-15T13:43:03Z | case_setup_complete | CASE-2025-0915-FOG-PDF             | OK     | Done                                                                       |
| 2025-09-15T13:43:03Z | session_end     | CASE-2025-0915-FOG-PDF               | OK     | End session                                                                |

---

## PDF Preview

**Filename:** 6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3.pdf  
**Size:** 351,978 bytes  
**SHA256:** 6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3

**PDF Metadata (exiftool):**
- File Type: PDF
- MIME Type: application/pdf
- PDF Version: 1.7
- Not encrypted, not linearized
- Invalid xref table (warning)

**Structure (pdfid, pdf-parser, strings):**
- 35 objects, 10 streams
- /AcroForm (present)
- /Action (present, object 22)
- /URI: https://hilarious-trifle-d9182e.netlify.app/Pay Adjustment.zip (object 22)
- No /JS, /JavaScript, /AA, /OpenAction detected (pdfid)
- Multiple image streams (objects 9, 11, 13, 15, 17, 25, 27, 29, 31, 33)
- Damaged cross-reference table (qpdf warning)

---

## Indicators of Compromise (IOC)

| Type   | Value                                                                  | Source    | Confidence | Notes                                   |
|--------|------------------------------------------------------------------------|-----------|------------|------------------------------------------|
| hash   | 6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3       | manifest  | high       | SHA256 of main PDF                       |
| sha1   | e4721effe1aa5b54fb00f80a6e628a1e3c2d86e3                               | manifest  | high       | SHA1 of main PDF                         |
| md5    | f294e7c2f611835afc267b1d46419879                                      | manifest  | high       | MD5 of main PDF                          |
| url    | https://hilarious-trifle-d9182e.netlify.app/Pay Adjustment.zip         | pdf-object| high       | /URI in object 22, likely payload         |
| file   | 6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3.pdf   | manifest  | high       | Filename from sample metadata             |
| tag    | fog, hilarious-trifle-d9182e-netlify-app, pdf                          | metadata  | medium     | MalwareBazaar tags                        |
| ssdeep | 1536:stK5sS3caw12btZxEms/z7/OtEmlNIW2wI:X3vw12btZxEms/v/OtEmEWBI       | metadata  | medium     | Fuzzy hash (MalwareBazaar)                |
| TLSH   | T19974A499D5C0ADC0D5160CB7DFA2282DAFB93C5615E68E43B315BAE3CCF2043993E189 | metadata | medium     | TLSH hash (MalwareBazaar)                 |

---

## Methodology

- **Acquisition**: ZIP file downloaded manually from MalwareBazaar, password "infected".
- **Preservation**: All files preserved using immutable/read-only flags and multi-hash manifest.
- **Cloning & Verification**: Reference and working clones created; hashes verified (SHA256 match confirmed).
- **Static Analysis**: 
  - PDF version 1.7, not encrypted, not linearized, damaged xref table.
  - No JavaScript or automatic actions found, but /Action and /URI objects present.
  - /URI points to suspicious Netlify ZIP file.
  - Multiple image objects; no embedded files.
- **Dynamic Analysis**: Network and process monitoring performed, no suspicious traffic detected in Linux.
- **Packaging**: All artifacts, logs, and manifests packaged for handover.

---

## Findings (Summary)

- The PDF is **version 1.7**, not encrypted, and not linearized.
- Contains no direct JavaScript or OpenAction, but has /AcroForm and /Action objects.
- **Object 22** contains a suspicious /URI:  
  `https://hilarious-trifle-d9182e.netlify.app/Pay Adjustment.zip`
  - This URL is likely intended to deliver a secondary payload.
- File structure is valid but has a damaged cross-reference table; qpdf attempted recovery.
- All hashes (SHA256, SHA1, MD5, ssdeep, TLSH) match the MalwareBazaar database entry.
- **Tags**: fog, hilarious-trifle-d9182e-netlify-app, pdf (MalwareBazaar)
- **Signature**: Fog campaign
- No evidence of JavaScript-based exploit inside the PDF, but the download action via /URI is a classic maldoc trick to lure users to a malicious site.

---

## Impact & Risk

- **High risk**: The PDF contains a clickable link (/URI) to a suspicious ZIP file hosted on Netlify.
- No direct exploit for Linux PDF readers detected.
- Potential for exploitation if opened in vulnerable PDF readers/email clients on Windows.

---

## Recommendations

- Block access to the domain `hilarious-trifle-d9182e.netlify.app` at perimeter.
- Add SHA256 hash to blocklist for email and web gateways.
- Deploy detection signatures for Fog campaign in AV/EDR/YARA rules.
- Educate users about risks of opening unknown PDF attachments and clicking embedded links.
- Monitor for similar PDF maldocs and Netlify-hosted payloads.

---

## PDF Preview
<img width="600" height="630" alt="image" src="https://github.com/user-attachments/assets/a0f68db2-9332-4455-b545-67247672e750" />

<!-- If you have an actual PNG/JPG preview, link it here. Example: ![preview](./preview.png) -->

**Structure Snippet:**
```
PDF Header: %PDF-1.7
Objects: 35
Streams: 10
Main /Action: Object 22, /URI: https://hilarious-trifle-d9182e.netlify.app/Pay Adjustment.zip
Images: Multiple XObject images
Tags: fog hilarious-trifle-d9182e-netlify-app pdf
```

---

## Appendices

- Hash manifests: ./06_hashes/
- Action logs: ./07_logs/actions.jsonl, ./07_logs/actions.log
- Static analysis outputs: ./04_analysis/static/
- Dynamic analysis outputs: ./04_analysis/dynamic/
- IOC file: ./04_analysis/iocs.json
- Chain of Custody: ./00_admin/chain_of_custody.txt
- Evidence index: ./00_admin/evidence_index.json

---

## References

- [MalwareBazaar Entry](https://bazaar.abuse.ch/sample/6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3/)
- [MalwareBazaar Download](https://bazaar.abuse.ch/download/6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3/)
- [Didier Stevens PDF Tools](https://blog.didierstevens.com/programs/pdf-tools/)
- [MalwareBazaar Tags](https://bazaar.abuse.ch/sample/6eb8b5986ea95877146adc1c6ed48ca2c304d23bc8a4a904b6e6d22d55bceec3/)
