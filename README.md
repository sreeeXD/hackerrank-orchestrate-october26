# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists: AI-Powered Deletion-Audit Agent

An autonomous deletion-audit system that investigates whether user personal data was truly deleted across distributed cloud services, databases, replicas, search indexes, analytics platforms, support archives, and backups at the required `audit_at` cutoff time.

---

## 1. System Overview & Architecture

When an enterprise deletion workflow reports **Complete**, personal data frequently persists due to:
- Cross-region replication drift and network partitions;
- Stale search and analytics indices keyed on current or historical identifiers (including SHA-256 hashes);
- Active synchronization workflows (`integration_service`) recreating deleted rows from downstream copies;
- Unblocked disaster recovery backup images (`backup_service`) staging pre-deletion data back into production;
- Incomplete tombstone redaction where names, emails, or phone numbers remain exposed in violation of policy.

The **Ghost Data Still Exists** agent implements a modular, deterministic pipeline:

```
                                  +-----------------------------+
                                  | dataset/deletion_rules.csv  |
                                  +--------------+--------------+
                                                 |
+------------------------------+                 v                 +-------------------------+
| dataset/deletion_requests.csv|-----> [ DeletionAuditAgent ] <----+ Evidence Indexer        |
+------------------------------+       |  - Identity Resolver |    | (SQL, PDF, Logs, JSON,  |
                                       |  - Request Classifier|    |  Screenshots, Text)     |
                                       |  - Temporal Guard    |    +-------------------------+
                                       |  - Remediation Plan  |
                                       +----------+-----------+
                                                  |
                                                  v
                                      [ root-level output.csv ]
```

### Core Architecture Components:

1. **`code/evidence_parser.py` (`EvidenceIndex`):**
   - **SQL Snapshots:** Mounts all 24 regional database snapshots in in-memory SQLite instances, querying `payload` and `record_json` columns to identify unpropagated deletions and replication drift.
   - **ReportLab PDF Decompression:** Directly decodes binary `/Filter [ /ASCII85Decode /FlateDecode ]` streams using `base64.a85decode` and `zlib.decompress` without external heavy dependencies.
   - **Multi-Line Log Correlation:** Groups service and lookup logs by `trace_id` to link asynchronous operations, correlation keys, and resource identifiers.
   - **JSON / Text / Console Evidence:** Indexes structured exports, configuration records, customer handovers, and data catalog links.

2. **`code/main.py` (`DeletionAuditAgent`):**
   - **Request Intent Classifier:** Identifies non-deletion actions (access, export, marketing opt-out, profile correction) and maps them to `NOT_APPLICABLE` with `steps_json = []`.
   - **Transitive Identity Resolution:** Traverses `user_identities.csv` and `user_audit_log.csv` to capture current and historical emails, names, phone numbers, and SHA-256 hashes of all email variants.
   - **Temporal Guard:** Enforces `requested_at` and `audit_at` bounds. Ignores pre-request evidence and guarantees zero post-audit leakage.
   - **Ordered Remediation & Verification Synthesis:** Applies `deletion_rules.csv` to generate the strictly ordered `FINDING` $\to$ `REMEDIATION` $\to$ `VERIFICATION` sequence.

3. **`code/evaluation/main.py`:**
   - Evaluates predictions against the public sample ground truth (`dataset/sample_output.csv`).
   - Assesses case-level accuracy, step counts, field-level matching across all 7 step attributes, and phase/operation ordering invariants.
   - Executes custom participant-created stress tests.

---

## 2. Quick Start & Execution

### Prerequisites
- Python 3.10+ (Standard Library only; no external package installation required)
- Operating System: Linux, macOS, or Windows

### Running the Deletion-Audit Agent
To run the full audit pipeline on all 518 evaluation requests and generate the final `output.csv` at the repository root:

```bash
python code/main.py
```
*(On Unix-based environments, `python3 code/main.py` can be used)*

Expected Output:
```text
Starting Ghost Data Still Exists Deletion-Audit Agent...
============================================================
Validating agent logic against public sample cases...
============================================================
Sample Status Accuracy:     32/32 (100.0%)
Sample Step Count Accuracy: 32/32 (100.0%)
Sample Exact Match:         32/32 (100.0%)
============================================================
SUCCESS: 100% exact match on all public sample cases verified.

Processing evaluation requests from: dataset/deletion_requests.csv
Total evaluation cases to process: 518

Writing final output to: output.csv
Successfully generated 518 rows in output.csv

Summary of Deletion Statuses:
  COMPLETE       : 226 (43.6%)
  INCOMPLETE     : 282 (54.4%)
  NOT_APPLICABLE : 10 (1.9%)
Audit process completed cleanly and deterministically.
```

### Running the Evaluation Harness
To run the formal evaluation benchmark and verify metrics against the public sample dataset:

```bash
python code/evaluation/main.py
```

Expected Output:
```text
Total Sample Cases:               32
Case Deletion-Status Accuracy:     32/32 (100.00%)
Exact Case-Level Match Rate:       32/32 (100.00%)
Step Count Match Rate:             32/32 (100.00%)
Phase & Operation Sequence Order:  32/32 (100.00%)
Total Steps Compared:              193
Field-Level Matching Accuracy:     193/193 (100.00%)
```

---

## 3. Dataset Contract & Layout

All participant-facing inputs are located inside `dataset/`:

| File | Description |
|---|---|
| `dataset/deletion_requests.csv` | 518 evaluation deletion requests requiring prediction |
| `dataset/sample_deletion_requests.csv` | 32 sample requests for validation |
| `dataset/sample_output.csv` | Ground-truth benchmark answers for sample requests |
| `dataset/user_identities.csv` | Current user identity snapshots (`user_id`, email, phone, name) |
| `dataset/user_audit_log.csv` | Historical changes to identity attributes |
| `dataset/system_activity.csv` | Global system and deletion worker event stream |
| `dataset/deletion_rules.csv` | Retention, tombstone, redaction, and deletion policies |
| `dataset/evidence_files.csv` | Manifest mapping `file_id` to evidence paths and capture times |
| `dataset/evidence/` | 94 multi-modal evidence files (SQL, logs, PDFs, JSON, images, text) |

---

## 4. Output Contract

The root-level `output.csv` adheres strictly to the required specification:

```text
case_id,deletion_status,steps_json
```

- **Row Count:** Exactly 518 data rows sorted by `case_id` ascending.
- **`deletion_status`:** Exactly one of `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
- **`steps_json`:** Valid JSON array with consecutive 1-based step numbering:
  - `NOT_APPLICABLE`: `steps_json = []`.
  - `COMPLETE`: Contains only evidence-backed `VERIFICATION` steps proving the compliant state at `audit_at`.
  - `INCOMPLETE`: Contains `FINDING` steps citing participant-visible evidence, followed by proposed `REMEDIATION` steps (`evidence_id: ""`), followed by post-remediation `VERIFICATION` checks (`evidence_id: ""`).
- **Ordering:** Phases ordered as `FINDING` $\to$ `REMEDIATION` $\to$ `VERIFICATION`. Secondary ordering follows problem statement operational priorities and `(system_id, resource_id)`.

---

## 5. Evaluation and Usage Reports

Comprehensive Markdown reports detailing benchmark accuracy, custom edge cases, token metrics, and operational costs are available in `code/evaluation/` and `evaluation/`:
- **`code/evaluation/evaluation_report.md`** (and `evaluation/evaluation_report.md`): Case-level, step-level, field-level, and sequence accuracy; failure modes and systematic fixes; detailed walkthroughs of three custom participant-designed edge cases.
- **`code/evaluation/usage_report.md`** (and `evaluation/usage_report.md`): Full model specifications, call counts, input/output token metrics, cost estimations, and optimization techniques.

---

## 6. Packaging `code.zip` for Submission

Per AGENTS.md §6.9, the final submission requires:
- `code.zip`: Containing `code/`, `README.md`, and evaluation reports (strictly excluding `dataset/`, `.git/`, `__pycache__`, and credentials).
- `output.csv`: Root-level 518-case prediction file.
- `log.txt`: Complete session chat transcript following AGENTS.md §5.
- Submission URL: [HackerRank Orchestrate - Ghost Data Still Exists](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)

### Packaging Command (Windows PowerShell):
```powershell
# Remove build cache
Remove-Item -Recurse -Force code\__pycache__ -ErrorAction SilentlyContinue

# Create zip archive
Compress-Archive -Path code, README.md, evaluation -DestinationPath code.zip -Force
```

### Packaging Command (macOS / Linux):
```bash
zip -r code.zip README.md code evaluation -x "*/__pycache__/*" "*/.git/*" "*/.DS_Store"
```
