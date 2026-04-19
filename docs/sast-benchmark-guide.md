# SentinelCore SAST Benchmark Guide

## What this benchmark measures

The SAST benchmark runs the SentinelCore Java SAST engine against a labeled
corpus of 21 test cases across 5 vulnerability classes. Each case is a
standalone Java file with a known expected result (true positive or true
negative). The benchmark produces a per-class and overall precision/recall/F1
scorecard.

## Vulnerability classes covered

| Class | Positive cases | Negative cases | Rule |
|---|---|---|---|
| SQL Injection | 3 | 2 | SC-JAVA-SQL-001 |
| Command Injection | 2 | 1 | SC-JAVA-CMD-001 |
| Path Traversal | 2 | 1 | SC-JAVA-PATH-001 |
| Weak Crypto | 3 | 2 | SC-JAVA-CRYPTO-001 |
| Hardcoded Secret | 3 | 2 | SC-JAVA-SECRET-001 |
| **Total** | **13** | **8** | |

## How to run

```bash
cd internal/sast/bench
go test -v -run TestBenchmark
```

This:
1. Loads `manifest.json` (the ground truth)
2. Parses each Java file with the real Java frontend
3. Runs the full SAST engine (all 5 rules, inter-procedural taint, summaries)
4. Classifies each case as TP/FP/FN/TN
5. Prints a formatted scorecard to stdout
6. Writes `scorecard.md` as a markdown table

## Interpreting the results

| Metric | Meaning |
|---|---|
| **Precision** | Of the findings the engine reported, what fraction were real? |
| **Recall** | Of the real vulnerabilities, what fraction did the engine catch? |
| **F1** | Harmonic mean of precision and recall — the balanced score |
| **TP** | True Positive — engine flagged, and it's a real vulnerability |
| **FP** | False Positive — engine flagged, but it's actually safe |
| **FN** | False Negative — engine missed a real vulnerability |
| **TN** | True Negative — engine correctly did not flag a safe case |

## Current limitations

- **Corpus size.** 21 cases is enough for a baseline but too small for
  statistical confidence. Future iterations should expand to the OWASP
  Benchmark Java corpus (~3000 cases).
- **Self-authored cases.** The corpus is authored alongside the engine. The
  real test is performance on external corpora (OWASP Benchmark, Juliet) that
  were NOT written to match the engine's pattern vocabulary.
- **No Fortify comparison yet.** The scorecard currently shows SentinelCore
  numbers only. Adding Fortify SARIF baselines is a future calibration step.
- **Path traversal precision.** The `getCanonicalPath()` sanitizer is not
  always recognized when the taint engine's conservative passthrough
  propagates taint through unmodeled call chains. This is the known FP vector.

## Known false positive

| Case | Class | Issue |
|---|---|---|
| PATH-N-001 | path_traversal | `getCanonicalPath()` sanitizer not clearing taint in all code patterns. The engine's conservative passthrough overapproximation causes taint to survive through the sanitizer call when the return value path doesn't match the exact modeled method. |

## Adding new benchmark cases

1. Add a `.java` file under `corpus/<class>/{positive,negative}/`.
2. Add an entry to `manifest.json` with a unique ID, file path, class, expected result, and rule.
3. Run the benchmark and verify the outcome matches.
4. Commit both the file and the manifest update.

## Expanding to external corpora

Future benchmark iterations will add:
- **OWASP Benchmark v1.2** (Java, ~3000 labeled cases)
- **NIST SARD Juliet Test Suite** (Java SQLi/XSS/CmdI subsets)
- **WebGoat** (realistic vulnerable Spring app)

These require a corpus fetch step (they're not vendored in the repo). The
manifest format supports external corpus entries with a `source` field.
