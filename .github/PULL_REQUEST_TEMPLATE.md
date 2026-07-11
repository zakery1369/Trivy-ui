# قالب Pull Request / Pull Request Template

این قالب دوزبانه است؛ می‌توانید پاسخ‌ها را به فارسی یا انگلیسی بنویسید.
This template is bilingual; responses may be written in Persian or English.

## خلاصه Pull Request / Pull Request Summary

Please provide a clear and concise summary of what this pull request changes.

## چه چیزی تغییر کرده است؟ / What Changed?

*
*
*

## چرا این تغییر لازم است؟ / Why Is This Needed?

Explain the problem, improvement, or use case this PR addresses.

Examples:

* Improves the Trivy scan result UI
* Adds a new filter or dashboard view
* Fixes a bug in vulnerability rendering
* Improves AI-assisted analysis
* Updates documentation or setup flow

## Issue مرتبط / Related Issue

Closes #

## نوع تغییر / Type of Change

* [ ] Bug fix
* [ ] New feature
* [ ] UI/UX improvement
* [ ] Trivy integration improvement
* [ ] AI feature / AI prompt update
* [ ] Security improvement
* [ ] Performance improvement
* [ ] Documentation update
* [ ] Refactor
* [ ] Test / CI update
* [ ] Other

## بخش تحت تأثیر / Area Affected

* [ ] Dashboard
* [ ] Scan results page
* [ ] Vulnerability details
* [ ] Misconfiguration results
* [ ] Secret scanning results
* [ ] SBOM / dependency view
* [ ] Report export
* [ ] Authentication / authorization
* [ ] API / backend
* [ ] AI assistant / AI analysis
* [ ] Settings / configuration
* [ ] Documentation
* [ ] Other

## سازگاری با Trivy / Trivy Compatibility

Please mention the Trivy version or output format this change was tested with.

```text
Trivy version:
Output format tested:
Example: JSON / table / SARIF / CycloneDX / SPDX
```

## تصویر یا نمایش / Screenshots or Demo

For UI changes, please add screenshots, screen recordings, or before/after examples.

Before:

After:

## آزمایش / Testing

Describe how you tested this change.

```bash
# commands used for testing
```

Tested environment:

```text
OS:
Browser:
Node.js version:
Backend/runtime version:
Trivy version:
```

## چک‌لیست قابلیت AI / AI Feature Checklist

Complete this section if the PR changes anything related to AI features, prompts, summaries, recommendations, or report analysis.

* [ ] This PR does not send sensitive scan data to AI without clear user action or configuration
* [ ] AI output is presented as assistance, not as guaranteed security truth
* [ ] Prompt changes were reviewed for security and privacy risks
* [ ] No API keys, tokens, credentials, or private endpoints are exposed
* [ ] AI-generated explanations do not hide or remove the original Trivy findings
* [ ] Users can still access the raw Trivy result or source finding

## چک‌لیست امنیت / Security Checklist

* [ ] No secrets, tokens, passwords, private keys, or credentials are included
* [ ] No unsafe default configuration was introduced
* [ ] No unnecessary external dependency was added
* [ ] User-provided scan data is handled safely
* [ ] Vulnerability data is not exposed to unauthorized users
* [ ] Security-related behavior is documented where needed

## تغییرات ناسازگار / Breaking Changes

* [ ] This PR does not introduce breaking changes
* [ ] This PR introduces breaking changes

If this PR introduces breaking changes, explain them here:

## مستندات / Documentation

* [ ] Documentation was updated
* [ ] Documentation update is not needed
* [ ] README was updated
* [ ] Setup or configuration docs were updated
* [ ] Screenshots or examples were updated

## مجوز و برند / License and Branding

By submitting this pull request, I confirm that:

* [ ] My contribution can be distributed under the AGPL-3.0-or-later license
* [ ] I have the right to contribute this code
* [ ] I understand that the project name, logo, and branding are not automatically licensed for use in unofficial forks or modified versions

## چک‌لیست نهایی / Final Checklist

* [ ] My code follows the project style
* [ ] I have tested my changes locally
* [ ] I have checked for linting or formatting issues
* [ ] I have updated tests where needed
* [ ] I have updated documentation where needed
* [ ] This PR is ready for review

## توضیحات تکمیلی / Additional Notes

Add any extra context, limitations, concerns, or review notes here.
