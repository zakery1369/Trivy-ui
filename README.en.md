# Trivy Docker Image Scanner UI

[فارسی](README.md) | [English](README.en.md)

[Contributing guide](CONTRIBUTING.md) | [Pull request template](.github/PULL_REQUEST_TEMPLATE.md)

![Trivy UI](https://raw.githubusercontent.com/zakery1369/pics/refs/heads/master/Trivy-UI.png)

A simple, modern, bilingual interface for scanning Docker images with [Trivy](https://github.com/aquasecurity/trivy). It lets you scan images, inspect vulnerabilities, export security reports, and request AI-assisted analysis and remediation advice without running Trivy commands directly.

## Features

### Docker image security scanning

- Persian (RTL) and English (LTR) interfaces with a persistent language switch
- Trivy version and Docker connection status
- Local Docker image discovery
- Remote registry image scanning
- Automatic image pull when an image is not available locally
- Manual Trivy database updates for faster repeat scans

Example images:

```text
nginx:latest
alpine:3.19
python:3.12-slim
ubuntu:22.04
```

### Scan results and reports

Findings are grouped by Critical, High, Medium, Low, and Unknown severity. You can filter and search the results, view a severity summary, and download HTML, JSON, SARIF, or TXT reports.

## AI-assisted Trivy analysis

After a scan, you can send a minimized report summary to a selected AI provider. The assistant can prioritize important vulnerabilities, explain risk, recommend fixes and mitigations, suggest base-image or dependency changes, and produce guidance for DevOps and security teams.

> AI analysis complements Trivy; it does not replace the scanner or independent security review.

### AI settings

- **API Key:** your provider credential, used for the request
- **Base URL:** the provider's OpenAI-compatible API URL, such as `https://api.openai.com/v1/`
- **Model:** the model used for analysis, such as `gpt-5.1-codex-mini`
- **Provider:** OpenAI, OpenRouter, Groq, DeepSeek, or a custom OpenAI-compatible service

The project is provider-independent and supports OpenAI-compatible APIs.

### Bilingual interface (English and Persian)

Trivy UI includes built-in internationalization for both **English** and **Persian (فارسی)**. Use the language button in the dashboard header to switch languages instantly—no page reload is required.

- Translates dashboard text, controls, status messages, filters, placeholders, tooltips, and accessibility labels
- Automatically changes the document language and layout direction: **LTR** for English and **RTL** for Persian
- Formats numbers for the selected locale (`en-US` or `fa-IR`)
- Saves the selected language in browser `localStorage`, so it remains active on the next visit
- Re-renders scan summaries, vulnerability tables, and dynamic messages after a language change
- Sends the selected language with AI remediation requests, so recommendations are returned in the same language as the interface
- Uses Persian as the default and fallback language when no saved English preference or translation is available

The language setting changes presentation and AI response language only. CVE identifiers, package names, versions, image references, and other technical values remain unchanged for accuracy.

## Requirements

- Docker
- Docker Compose

Verify the installation:

```bash
docker --version
docker compose version
```

## Installation and startup

```bash
git clone https://github.com/zakery1369/trivy-ui.git
cd trivy-ui-docker
docker compose up -d --build
```

Open `http://localhost:8569` after the service starts.

To rebuild after source changes:

```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

## Usage

### 1. Select a local Docker image

Choose an image from the list on the home page and start the scan.

### 2. Scan a remote image

Enter an image reference such as `nginx:latest`, `ubuntu:22.04`, `redis:7`, or `python:3.12-slim`. The application checks whether it exists locally, pulls it if required, and scans it with Trivy.

### 3. Update the Trivy database

The app does not update the vulnerability database before every scan. Use the dashboard button when you want to update it. This reduces scan time and avoids repeated downloads while leaving update timing under your control.

### 4. Analyze a report with AI

Run a Trivy scan, choose and configure an AI provider, then request recommendations. The response includes risk priorities, remediation suggestions, mitigations, and next steps in the currently selected interface language.

## Project structure

```text
trivy-ui-zakops/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
├── README.en.md
└── app/
    ├── main.py
    └── static/
        ├── index.html
        ├── styles.css
        ├── app.js
        ├── zak.png
        └── fonts/
            └── Vazirmatn.woff2
```

## Important security note

The application mounts the Docker socket to access local images:

```yaml
- /var/run/docker.sock:/var/run/docker.sock
```

The Docker socket grants powerful access to the host. Run this tool only in controlled environments such as a personal machine, test environment, internal network, DevOps server, or security lab. Do not expose it on a public server without appropriate access controls.

## Suggested test images

```text
alpine:3.19
nginx:latest
ubuntu:22.04
redis:7
python:3.12-slim
```

## Stop or clean up

Stop the service:

```bash
docker compose down
```

Remove containers and volumes:

```bash
docker compose down -v
```

## About Trivy

[Trivy](https://github.com/aquasecurity/trivy) is an open-source security scanner developed by Aqua Security. It supports container images, OS and library packages, filesystems, Git repositories, Kubernetes, and infrastructure-as-code misconfiguration scanning.

## AI architecture

AI analysis is provider-independent. Users supply their provider, API key, model, and API URL, allowing the feature to work across different environments and compatible services.

## Links

- GitHub: [zakery1369](https://github.com/zakery1369)
- Telegram: [Zakops](https://t.me/Zakops)
- Telegram: [DevOpsPersian](https://t.me/DevOpsPersian)
- Telegram: [DevOpsZakops](https://t.me/DevOpsZakops)
- Website: [zakops.com](https://zakops.com)

## License

Copyright (C) 2026 zakery1369

SPDX-License-Identifier: AGPL-3.0-or-later
