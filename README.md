\# TaintGate



\*\*An experimental security gateway for tool-using AI agents.\*\*



TaintGate explores how provenance tracking, deterministic policies, and audit logging can help protect AI agents from prompt injection and unsafe tool calls. It tracks untrusted content, evaluates sensitive actions against explicit rules, and experiments with local semantic similarity as an additional detection signal.



The project is designed to run locally using open-source tooling, without requiring paid AI APIs.



> \*\*Research prototype:\*\* TaintGate is an experimental defense-in-depth system, not a production-ready security boundary. Its detection methods have known limitations and require further independent evaluation.



\## The Problem



AI agents can read documents, retrieve web content, and invoke tools. Those inputs may contain malicious instructions intended to manipulate the agent into performing unauthorized actions.



A simple example:



\- An agent retrieves a document containing a malicious instruction.

\- The instruction asks the agent to send confidential information to an external recipient.

\- Without appropriate safeguards, untrusted content may influence a sensitive tool call.



TaintGate explores ways to identify untrusted content, enforce explicit policies, and record security-relevant events before sensitive actions are carried out.



\## How TaintGate Works



1\. \*\*Track provenance:\*\* Mark untrusted content and track matching values back to their recorded sources.

2\. \*\*Evaluate tool calls:\*\* Apply deterministic policy checks to sensitive actions, including recipient restrictions.

3\. \*\*Experiment with semantic detection:\*\* Compare text embeddings using a locally hosted embedding model to investigate paraphrased or indirect injection attempts.

4\. \*\*Record audit events:\*\* Store structured logs to support inspection and debugging.

5\. \*\*Inspect results:\*\* Use a dashboard API and React-based interface to explore recorded events.

6\. \*\*Evaluate defenses:\*\* Run regression tests, adversarial datasets, threshold experiments, and a separate holdout evaluation.



Semantic similarity is an experimental signal, not proof of malicious intent or authorization. It should not replace deterministic policy checks or explicit authorization.



\## Architecture



```text

Untrusted Documents / Retrieved Content

&#x20;                 |

&#x20;                 v

&#x20;      Provenance \& Taint Tracking

&#x20;                 |

&#x20;                 v

&#x20;         MCP Gateway Prototype

&#x20;                 |

&#x20;                 v

&#x20;      Deterministic Policy Checks

&#x20;                 |

&#x20;         +-------+-------+

&#x20;         |               |

&#x20;         v               v

&#x20;      Reject          Allow / Forward

&#x20;                         |

&#x20;                         v

&#x20;                   Mock MCP Tools



Untrusted Text ---> Local Embedding Experiments

&#x20;                         |

&#x20;                         v

&#x20;               Evaluation Reports



Security Events ---> JSONL Audit Logs

&#x20;                         |

&#x20;                         v

&#x20;                   FastAPI API

&#x20;                         |

&#x20;                         v

&#x20;                  React Dashboard

```



The architecture represents the project's intended security flow. The implemented mock-tool workflow and individual experimental components should not be interpreted as a guarantee that every possible agent action is intercepted.



\## Key Features



\- \*\*MCP gateway prototype\*\* for experimenting with tool-call interception and enforcement.

\- \*\*Provenance and taint tracking\*\* for identifying untrusted text and matching recorded sources.

\- \*\*Deterministic recipient policies\*\* with case-insensitive matching and explicit rejection of disallowed or empty recipients.

\- \*\*Local semantic experiments\*\* using Ollama and `nomic-embed-text`.

\- \*\*Structured audit logging\*\* for security-related events.

\- \*\*Audit dashboard\*\* with a FastAPI backend and React frontend.

\- \*\*Regression and adversarial tests\*\* covering policy enforcement and detection behavior.

\- \*\*Reproducible evaluation artifacts\*\* containing datasets, scripts, and JSON reports.



\## Technology Stack



| Area | Technologies |

|---|---|

| Language | Python |

| Gateway and API | MCP, FastAPI |

| Semantic experiments | Ollama, `nomic-embed-text` |

| Dashboard | React, JavaScript |

| Security logic | Provenance tracking, deterministic policies |

| Audit storage | JSONL logs |

| Testing | pytest |

| Evaluation | Python, JSON datasets, cosine similarity |

| Version control | Git, GitHub |



\## Security Evaluation



TaintGate includes multiple evaluation experiments. The results below are measured on the project's current manually constructed datasets; they are not independent benchmarks or evidence of production-level protection.



\### Adversarial evaluation V2



Dataset: 25 examples — 10 labeled attacks and 15 labeled benign.



| Metric | Lexical detector | Semantic detector at 0.72 |

|---|---:|---:|

| Attacks detected | 3/10 (30%) | 10/10 (100%) |

| Attacks missed | 7/10 | 0/10 |

| Benign examples falsely flagged | 1/15 (6.7%) | 3/15 (20%) |



The semantic detector caught more attacks in this dataset, but it also falsely flagged more benign examples. A high detection rate on a small constructed dataset does not establish reliable real-world performance.



\### Threshold sensitivity



On the same 25-example dataset:



| Semantic threshold | Attacks detected | Benign false positives |

|---|---:|---:|

| 0.72 | 10/10 | 3/15 |

| 0.75 | 10/10 | 2/15 |

| 0.80 | 7/10 | 2/15 |

| 0.90 | 3/10 | 0/15 |



Changing the threshold changes the trade-off between detection and false positives. The threshold should not be treated as universally optimal.



\### Holdout evaluation



A separate, manually constructed 20-example dataset was used to explore generalization.



| Experimental rule | Attacks detected | Benign false positives |

|---|---:|---:|

| Semantic threshold ≥ 0.75 | 5/10 | 3/10 |

| Threshold ≥ 0.75 and prototype margin ≥ 0.09 | 2/10 | 0/10 |



The prototype-margin rule reduced false positives in this holdout set but missed more attacks. Its results on the initial dataset did not generalize. The holdout is also small and has not been independently audited.



\*\*Current conclusion:\*\* semantic similarity can be useful as an additional investigative signal, but the experiments do not justify using it alone to block or authorize actions. Provenance tracking, deterministic policies, and appropriate authorization checks remain essential.



\## Project Structure



```text

taintgate/

├── gateway/       # Gateway, taint tracking, and policy logic

├── policies/      # Policy configuration

├── manifests/     # Tool/source/sink manifests

├── rag/           # Local retrieval-augmented generation components

├── dashboard-ui/  # React audit dashboard

├── logs/          # Local audit logs

├── docs/          # Project documentation

├── eval/          # Earlier evaluation assets

├── evaluation/    # Datasets, evaluation scripts, and JSON reports

└── tests/         # Automated regression tests

```



\## Getting Started



\### Prerequisites



\- Python 3.13 or a compatible Python version supported by the project dependencies

\- Git

\- Node.js and npm for the dashboard

\- Ollama for running local embedding and generation models



\### Python environment



Clone the repository and enter the project directory:



```bash

git clone https://github.com/RufiyaTasneem/TaintGate.git

cd TaintGate

```



Create and activate a virtual environment.



\*\*Windows PowerShell:\*\*



```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

```



Install the project's Python dependencies using its dependency file, if present:



```powershell

pip install -r requirements.txt

```



If your local setup uses a different dependency file, follow that file's installation instructions.



\### Local embedding model



Install and start Ollama, then download the embedding model:



```powershell

ollama pull nomic-embed-text

```



Some evaluation scripts also use the local `qwen2.5:3b` model:



```powershell

ollama pull qwen2.5:3b

```



These models run locally and do not require a paid AI API. Hardware requirements and inference speed depend on your system.



\### Run the tests



From the repository root, with the virtual environment activated:



```powershell

python -m pytest -q

```



The current regression suite has passed \*\*23 tests\*\*. Rerun it after making changes to verify the latest code.



\### Run evaluations



From the repository root:



```powershell

python evaluation/adversarial\_eval\_v2.py

python evaluation/threshold\_analysis\_v2.py

python evaluation/prototype\_eval\_v2.py

python evaluation/margin\_analysis\_v2.py

python evaluation/holdout\_eval\_v1.py

```



These scripts use the local embedding service where required and generate JSON reports in the `evaluation/` directory. Ensure Ollama is running and the required model is available before executing them. Re-running an evaluation may overwrite its existing report.



Follow the project's dependency and configuration files for launching the gateway, API, RAG components, and dashboard.



\## Limitations and Future Work



\- Expand the evaluation datasets with independently reviewed examples.

\- Test on established prompt-injection benchmarks and report reproducible metrics.

\- Evaluate paraphrases, indirect instructions, quoted attacks, multilingual inputs, and benign security discussions.

\- Improve source provenance and tracking across transformations and tool outputs.

\- Test fail-closed behavior and authorization checks across every sensitive tool path.

\- Measure false-positive rates and attack detection on larger, held-out datasets.

\- Improve audit traceability and the dashboard's investigation workflow.

\- Document threat models, supported integrations, and known bypasses.



\## Project Status



TaintGate is an ongoing security research and engineering project. The current implementation includes a gateway prototype, taint tracking, deterministic recipient policies, local semantic experiments, audit components, a dashboard, and automated tests.



The evaluation results are exploratory. The project does not claim to eliminate prompt injection or guarantee that an agent cannot perform unsafe actions.



\## Author



\*\*Roofiya Tasneem Mohammad\*\*



\- GitHub: \[@RufiyaTasneem](https://github.com/RufiyaTasneem)



\---



\*Built to explore practical, testable defenses for tool-using AI systems.\*



