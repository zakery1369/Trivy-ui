# Contributing to Trivy UI

Thank you for your interest in contributing to Trivy UI.

Trivy UI is a free and open-source web interface for Trivy. The goal of this project is to make Trivy scan results easier to view, understand, filter, analyze, and use through a clean web interface, with optional AI-assisted features.

This project is an independent web UI for Trivy and is not affiliated with, endorsed by, or sponsored by Aqua Security or the official Trivy project.

The name "Trivy" belongs to its respective owners and is used here only to describe compatibility and integration with Trivy.

Contributions are welcome, including bug fixes, UI improvements, documentation updates, Trivy integration improvements, AI feature improvements, tests, performance improvements, and security-related enhancements.

## Project License

Trivy UI is released under the `AGPL-3.0-or-later` license.

By contributing to this project, you agree that your contribution will be distributed under the same license.

Any custom project name, logo, artwork, or branding included in this repository belongs to the original project maintainer unless otherwise stated.

## Before Contributing

Before opening a pull request, please:

- Check existing issues and pull requests to avoid duplicate work
- Keep changes focused and easy to review
- Avoid mixing unrelated changes in a single pull request
- Do not include secrets, tokens, API keys, private URLs, or sensitive scan data
- Follow the existing project structure and coding style
- Update documentation if your change affects setup, usage, configuration, or behavior
- Test your changes locally before submitting

## Types of Contributions

You can contribute in many ways:

- Fixing bugs
- Improving the UI or UX
- Improving Trivy result parsing and rendering
- Adding filters, views, or dashboard improvements
- Improving vulnerability detail pages
- Improving misconfiguration result views
- Improving secret scanning result views
- Improving SBOM or dependency views
- Improving report export features
- Improving AI-assisted explanations, summaries, or recommendations
- Improving Docker or deployment configuration
- Adding or improving tests
- Improving documentation
- Reporting issues
- Suggesting new features

## Development Guidelines

When working on Trivy UI, please keep the following principles in mind:

- The original Trivy finding should always remain accessible
- AI-generated content should not replace, hide, or modify the original Trivy result
- AI output should be presented as assistance, not as guaranteed security advice
- User scan data should be handled carefully
- Scan data should not be sent to external AI services without clear user action or configuration
- Unsafe default configurations should be avoided
- Unnecessary dependencies should be avoided
- UI changes should make security review easier, not more confusing
- Features should be clear, practical, and useful for users reviewing Trivy scan results

## Working with Trivy Output

If your change affects Trivy integration, please mention the following in your pull request:

- Trivy version used for testing
- Output format tested
- Affected scan type
- Example output format, if relevant

Common Trivy output formats may include:

- JSON
- SARIF
- CycloneDX
- SPDX
- Table output

Common affected areas may include:

- Vulnerability scanning
- Misconfiguration scanning
- Secret scanning
- License scanning
- SBOM results
- Dependency results
- Container image results
- Filesystem scan results
- Repository scan results

Please avoid committing private scan reports, real customer data, internal project data, or sensitive vulnerability reports.

Use sanitized sample data whenever possible.

## Working with AI Features

If your change affects AI prompts, AI summaries, AI recommendations, AI configuration, or AI-assisted analysis, please make sure that:

- No API keys or credentials are committed
- Sensitive scan data is not sent without clear user action or configuration
- Prompt changes are reviewed for security and privacy risks
- AI output does not hide, remove, or alter the original Trivy finding
- Users can still verify the original scan result
- AI-generated output is clearly presented as assistance only
- AI-generated suggestions are not presented as final or guaranteed security decisions

AI-generated output should be treated as helpful context, not as a replacement for expert review.

## Pull Request Process

Before submitting a pull request:

1. Create a new branch for your change
2. Make your changes
3. Test your changes locally
4. Update documentation if needed
5. Open a pull request using the provided [pull request template](.github/PULL_REQUEST_TEMPLATE.md)

Please make sure your pull request includes:

- A clear summary of the change
- The reason for the change
- Testing details
- Screenshots or demos for UI changes
- Trivy version and output format if relevant
- Notes about AI behavior if relevant
- Any breaking changes

## Branch Naming

Please use clear branch names.

Good examples:

```text
fix/severity-badge-rendering
feature/vulnerability-filter
feature/ai-summary-panel
docs/update-docker-setup
refactor/trivy-parser
```

Avoid vague branch names like:

```text
test
fix
update
new
changes
```

## Commit Messages

Please use clear and meaningful commit messages.

Good examples:

```text
Fix vulnerability severity badge rendering
Add filter for critical Trivy findings
Improve AI summary prompt for misconfigurations
Update Docker setup documentation
Refactor Trivy JSON parser
```

Avoid vague commit messages like:

```text
fix
update
changes
stuff
final
```

## Reporting Bugs

When reporting a bug, please include:

- A clear description of the issue
- Steps to reproduce
- Expected behavior
- Actual behavior
- Screenshots or logs if helpful
- Browser and operating system
- Trivy version
- Trivy UI version or commit hash
- Output format used, if relevant
- Whether the issue affects UI, backend, Docker, Trivy parsing, or AI features

Please do not include sensitive scan data, API keys, tokens, private URLs, internal IP addresses, or confidential project information.

## Requesting Features

Feature requests are welcome.

When suggesting a feature, please explain:

- What problem it solves
- Who would benefit from it
- How it should work
- Whether it relates to Trivy output, UI, AI, reporting, filtering, export, deployment, or configuration
- Any possible security or privacy concerns

## Security Notes

Trivy UI is provided as a free and open-source project without warranty, official security support, or any commitment to fix reported issues.

Please do not include sensitive information in public issues, pull requests, discussions, screenshots, or logs.

Sensitive information includes:

- API keys
- Access tokens
- Passwords
- Secrets
- Private keys
- Private URLs
- Internal IP addresses
- Customer scan data
- Private project scan results
- Full vulnerability reports from private projects
- Full SBOM outputs from private projects

For more details, see `SECURITY.md`.

## No Warranty

Trivy UI is provided as is, without any warranty or support commitment.

By using or contributing to this project, you understand that the project maintainer is not responsible for any damage, data leakage, incorrect decision, service disruption, security incident, misuse, or direct or indirect consequence resulting from the use of this project.

Users and contributors are responsible for reviewing, testing, configuring, and validating the project before using it in any environment.

## Code of Conduct

Please be respectful and constructive when participating in this project.

Discussions, issues, and pull requests should stay focused on improving Trivy UI.

Harassment, abusive behavior, spam, intentionally harmful contributions, or disrespectful communication are not welcome.

## Maintainer Rights

The project maintainer may close issues or pull requests that are:

- Out of scope
- Incomplete
- Unsafe
- Unmaintainable
- Duplicated
- Not aligned with the project goals
- Not compatible with the project license
- Not respectful or constructive

The maintainer may also request changes, reject changes, or edit contributions before merging.

## Thank You

Thank you for helping improve Trivy UI.
