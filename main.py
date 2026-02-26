#!/usr/bin/env python3
"""
ai-phishing-detector: AI-powered phishing URL and email analyzer.
Analyzes URLs and email content for phishing indicators using heuristics
and AI-based reasoning.
"""

import re
import sys
import click
from urllib.parse import urlparse
from openai import OpenAI
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

client = OpenAI()
console = Console()


def extract_url_features(url: str) -> dict:
    """Extract structural features from a URL for analysis."""
    parsed = urlparse(url)
    features = {
        "scheme": parsed.scheme,
        "domain": parsed.netloc,
        "path": parsed.path,
        "query": parsed.query,
        "has_ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}", parsed.netloc)),
        "subdomain_count": len(parsed.netloc.split(".")) - 2,
        "url_length": len(url),
        "has_at_symbol": "@" in url,
        "has_double_slash": "//" in parsed.path,
        "suspicious_keywords": [kw for kw in
            ["login", "secure", "verify", "account", "update", "confirm", "banking", "paypal", "amazon"]
            if kw in url.lower()],
    }
    return features


@click.group()
def cli():
    """AI-powered phishing detection toolkit."""
    pass


@cli.command()
@click.argument("url")
def check_url(url: str):
    """Analyze a URL for phishing indicators."""
    console.print(Panel(f"[bold cyan]Analyzing URL: {url}[/bold cyan]", expand=False))

    features = extract_url_features(url)

    # Display feature table
    table = Table(title="URL Feature Analysis", show_header=True, header_style="bold magenta")
    table.add_column("Feature", style="cyan")
    table.add_column("Value")
    for k, v in features.items():
        table.add_row(str(k), str(v))
    console.print(table)

    prompt = f"""You are a cybersecurity expert specializing in phishing detection. Analyze the following URL and its extracted features for phishing indicators.

URL: {url}
Features: {features}

Provide:
1. **Verdict** – Is this URL likely phishing? (High/Medium/Low/Safe risk)
2. **Key Indicators** – What specific features raise suspicion?
3. **Spoofed Brand** – Is this impersonating a known brand?
4. **Recommended Action** – What should the user do?
5. **Technical Notes** – Any additional technical observations.

Format your response in Markdown."""

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are an expert in phishing detection and URL analysis."},
                {"role": "user", "content": prompt}
            ]
        )
        console.print(Markdown(response.choices[0].message.content))
    except Exception as e:
        console.print(f"[bold red]AI analysis error:[/bold red] {e}")


@cli.command()
@click.argument("email_file", type=click.Path(exists=True))
def check_email(email_file: str):
    """Analyze an email file (.eml or .txt) for phishing indicators."""
    with open(email_file, "r", errors="ignore") as f:
        email_content = f.read()

    console.print(Panel(f"[bold cyan]Analyzing email: {email_file}[/bold cyan]", expand=False))

    prompt = f"""You are a cybersecurity expert specializing in email phishing analysis. Analyze the following email content for phishing indicators.

Email Content:
---
{email_content[:6000]}
---

Provide:
1. **Verdict** – Is this email phishing? (High/Medium/Low/Safe risk)
2. **Social Engineering Tactics** – What psychological manipulation techniques are used?
3. **Suspicious Elements** – Headers, links, attachments, sender spoofing.
4. **Extracted IOCs** – Any URLs, IPs, or domains found.
5. **Recommended Action** – What should the recipient do?

Format your response in Markdown."""

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are an expert in email phishing analysis and social engineering detection."},
                {"role": "user", "content": prompt}
            ]
        )
        console.print(Markdown(response.choices[0].message.content))
    except Exception as e:
        console.print(f"[bold red]AI analysis error:[/bold red] {e}")


if __name__ == "__main__":
    cli()
