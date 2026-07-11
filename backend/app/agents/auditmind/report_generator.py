"""
AuditMind — Natural Language Incident Report Generator
Converts raw scan results into human-readable reports.
Basic tier: Ollama (local, free)
Pro tier:   Anthropic Claude API
"""

import os
import json
import requests
import anthropic
from dotenv import load_dotenv
from backend.app.logger import get_logger

load_dotenv(".env", override=False)
_tier = os.environ.get("CGAI_TIER", "basic")
load_dotenv(f".env.{_tier}", override=True)

logger        = get_logger("report_generator")
REPORT_ENGINE = os.environ.get("REPORT_ENGINE", "ollama")
OLLAMA_URL    = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL  = os.environ.get("OLLAMA_MODEL", "mistral")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")


def build_prompt(scan_result: dict) -> str:
    """Convert AuditMind scan result into a structured prompt."""

    summary  = scan_result.get("summary", {})
    alerts   = scan_result.get("alerts", [])
    timeline = scan_result.get("session_timeline", [])
    status   = scan_result.get("system_status", {})

    alert_lines = ""
    for a in alerts:
        alert_lines += f"- [{a['severity'].upper()}] {a['rule']}: {a['message']}\n"

    if not alert_lines:
        alert_lines = "- No alerts detected\n"

    prompt = f"""You are AuditMind, an AI security intelligence agent inside CloudGuard AI.

You have completed a deep log analysis scan. Here are the findings:

SYSTEM STATUS: {status.get('message', 'Unknown')}
PEAK RISK SCORE: {summary.get('peak_risk', 0)}/100

SUMMARY:
- User sessions detected: {summary.get('total_user_sessions', 0)}
- Account changes: {summary.get('account_changes', 0)}
- New scheduled tasks: {summary.get('new_scheduled_tasks', 0)}
- New services installed: {summary.get('new_services', 0)}
- Suspicious logons: {summary.get('suspicious_logons', 0)}

ALERTS TRIGGERED:
{alert_lines}
Write a concise professional incident report for a security analyst. Include:
1. Executive summary (2 sentences max)
2. Key findings and why they matter
3. Recommended immediate actions
4. Risk assessment

Keep it under 250 words. Be direct and actionable."""

    return prompt


def generate_with_ollama(prompt: str) -> str:
    """Generate report using local Ollama (Basic tier)."""

    payload = {
        "model":  OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=60)
        response.raise_for_status()
        return response.json().get("response", "Report generation failed.")

    except requests.exceptions.ConnectionError:
        return "ERROR: Ollama is not running. Start it with: ollama serve"

    except requests.exceptions.Timeout:
        return "ERROR: Ollama timed out. Model may still be loading."

    except Exception as e:
        return f"ERROR: Ollama failed — {str(e)}"


def generate_with_claude(prompt: str) -> str:
    """Generate report using Anthropic Claude API (Pro tier)."""

    try:
        client  = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        message = client.messages.create(
            model      = "claude-sonnet-4-6",
            max_tokens = 1024,
            messages   = [{"role": "user", "content": prompt}],
        )
        return message.content[0].text

    except Exception as e:
        logger.error(f"Claude API failed: {e}")
        return f"ERROR: Claude API failed — {str(e)}"


def generate_report(scan_result: dict) -> str:
    """Generate incident report using configured engine."""

    prompt = build_prompt(scan_result)

    logger.info(f"Generating report with engine: {REPORT_ENGINE}")

    if REPORT_ENGINE == "anthropic":
        report = generate_with_claude(prompt)
    else:
        report = generate_with_ollama(prompt)

    logger.info("Incident report generated successfully")
    return report