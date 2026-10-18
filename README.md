# SecOps Orchestrator MCP 🛡️

An autonomous DevSecOps orchestration daemon that bridges Model Context Protocol (MCP) servers. This tool ingests live SIEM telemetry, processes it through local LLMs (DeepSeek-R1 / Qwen), and dynamically deploys Zero-Trust network policies.

## Architecture

This orchestrator binds together two distinct MCP servers:
1. **soc-siem-mcp:** Reads high-priority threat alerts and telemetry from Wazuh/SentinelOne.
2. **illumio-flow-ops:** Pushes microsegmentation and quarantine policies to Illumio Core.

A local reasoning model acts as the decision engine in the middle, evaluating the threat context and synthesizing the exact JSON payload required for the containment tool.

## Prerequisites

* Python 3.10+
* Local inference engine (Ollama, vLLM, or equivalent API)
* Configured `soc-siem-mcp` and `illumio-flow-ops` Node.js servers

## Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/JoaquinHernandez/secops-orchestrator-mcp.git](https://github.com/JoaquinHernandez/secops-orchestrator-mcp.git)
   cd secops-orchestrator-mcp
