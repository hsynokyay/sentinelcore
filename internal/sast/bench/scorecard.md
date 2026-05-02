# SentinelCore SAST Benchmark Scorecard

| Class | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| sql_injection | 6 | 0 | 0 | 4 | 100.0% | 100.0% | 100.0% |
| command_injection | 3 | 0 | 0 | 2 | 100.0% | 100.0% | 100.0% |
| path_traversal | 3 | 1 | 0 | 1 | 75.0% | 100.0% | 85.7% |
| weak_crypto | 3 | 0 | 0 | 2 | 100.0% | 100.0% | 100.0% |
| hardcoded_secret | 4 | 0 | 0 | 3 | 100.0% | 100.0% | 100.0% |
| ssrf | 4 | 0 | 0 | 3 | 100.0% | 100.0% | 100.0% |
| open_redirect | 1 | 0 | 0 | 1 | 100.0% | 100.0% | 100.0% |
| unsafe_deserialization | 1 | 0 | 0 | 1 | 100.0% | 100.0% | 100.0% |
| **OVERALL** | **25** | **1** | **0** | **17** | **96.2%** | **100.0%** | **98.0%** |
