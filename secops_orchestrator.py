import asyncio
import json
import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Local model endpoint (vLLM / Ollama OpenAI-compatible API)
LOCAL_LLM_URL = "http://localhost:8000/v1/chat/completions"
MODEL_NAME = "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B"

async def run_orchestrator():
    # 1. Define Server Parameters for MCP instances
    siem_params = StdioServerParameters(
        command="node",
        args=["/opt/soc-siem-mcp/build/index.js"],
        env={"WAZUH_API_URL": "https://wazuh.internal:55000"}
    )
    illumio_params = StdioServerParameters(
        command="node",
        args=["/opt/illumio-flow-ops/build/index.js"],
        env={"ILLUMIO_PCE_HOST": "pce.internal:8443"}
    )

    async with stdio_client(siem_params) as (siem_read, siem_write), \
               stdio_client(illumio_params) as (illumio_read, illumio_write):

        async with ClientSession(siem_read, siem_write) as siem_session, \
                   ClientSession(illumio_read, illumio_write) as illumio_session:

            await siem_session.initialize()
            await illumio_session.initialize()

            print("[*] MCP Bridges Initialized. Polling for high-severity alerts...")

            # 2. Ingest alerts from Wazuh via soc-siem-mcp
            alerts = await siem_session.call_tool(
                "get_recent_alerts",
                arguments={"min_level": 10, "limit": 5}
            )

            alert_data = alerts.content[0].text
            if not alert_data or alert_data == "[]":
                print("[-] No high-priority alerts found.")
                return

            # 3. Pass telemetry to local model for decision reasoning
            print("[+] Ingested threat event. Passing to local reasoning engine...")
            remediation_plan = await analyze_threat_with_llm(alert_data)
            print(f"[+] Remediation Plan Synthesized:\n{remediation_plan}")

            # 4. Parse remediation and call Illumio tool
            action = json.loads(remediation_plan)
            if action.get("action") == "isolate_workload":
                print(f"[*] Enforcing microsegmentation on target: {action['workload_href']}")
                result = await illumio_session.call_tool(
                    "apply_quarantine_policy",
                    arguments={
                        "workload_href": action["workload_href"],
                        "block_egress": action.get("block_egress", True),
                        "reason": action.get("reason", "Automated IR containment")
                    }
                )
                print(f"[✓] Policy applied: {result.content[0].text}")

async def analyze_threat_with_llm(alert_json: str) -> str:
    system_prompt = (
        "You are an automated DevSecOps incident response engine. "
        "Analyze the provided Wazuh telemetry and identify the affected workload, "
        "threat severity, and required containment action. "
        "Return ONLY a valid JSON object matching this schema:\n"
        "{\n"
        '  "action": "isolate_workload" | "monitor" | "dismiss",\n'
        '  "workload_href": "<illumio_workload_href_or_ip>",\n'
        '  "block_egress": true,\n'
        '  "confidence": 0.0 to 1.0,\n'
        '  "reason": "<short justification>"\n'
        "}"
    )

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Telemetry:\n{alert_json}"}
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"}
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        res = await client.post(LOCAL_LLM_URL, json=payload)
        res_data = res.json()
        return res_data["choices"][0]["message"]["content"]

if __name__ == "__main__":
    asyncio.run(run_orchestrator())
