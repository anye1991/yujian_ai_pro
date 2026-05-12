# Contributing to YujianAI Pro

Thank you for your interest in contributing to YujianAI Pro! This document outlines
 the process for contributing to this project.

## How to Contribute

We welcome contributions in the following ways:
- **Reporting bugs** : Open an issue describing the problem, including steps to 
reproduce and your environment.
- **Suggesting features** : Open an issue with the `enhancement` label and 
describe your use case.
- **Submitting code** : Fork the repository and submit a pull request (PR).

## Contribution Process

1. **Fork the repository** to your own GitHub account.
2. **Create a feature branch** from `main` (e.g., `git checkout -b feature/your-
feature-name`).
3. **Make your changes**, following the coding standards below.
4. **Test your changes** to ensure existing functionality is not broken.
5. **Commit your changes** using clear, descriptive commit messages.
6. **Push to your fork** and submit a pull request to the `main` branch.
7. **Participate in code review** – maintainers will review your PR and may 
request changes.

All contributions will be reviewed for quality, security implications, and 
alignment with the project's goals.

## Coding Standards

Please adhere to the following coding standards when contributing:

- **Python code** : Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) 
style guidelines.
- **Docstrings** : Use Google-style docstrings for all public functions and 
classes.
- **Type hints** : Include type annotations where possible (Python 3.8+).
- **File structure** : Maintain the existing module organization:

attack_modules/ # Attack modules for CMS, API, auth, etc.
wordlists/ # Dictionaries for scanning
results/ # Output reports
logs/ # Execution logs


- **Configuration** : Use `config.yaml` for user-configurable settings; avoid 
hardcoding values.
- **Error handling** : Use try-except blocks appropriately; log errors using the 
existing logging system.

## Security Considerations

Since YujianAI Pro is a penetration testing platform, security is paramount:

- **Do NOT include** hardcoded credentials, API keys, or sensitive data in 
commits.
- **Sanitize inputs** when processing external data to avoid injection issues.
- **Respect rate limits** in scanner modules to avoid overwhelming targets.

## Pull Request Requirements

- PRs must pass basic validation (code must be syntactically correct).
- PR title should summarize the change (e.g., "Add WordPress brute force module" 
or "Fix XSS detection false positive").
- Link related issues in the PR description (e.g., "Closes #123").
- One PR should focus on one logical change; avoid mixing multiple features/fixes.

## Questions?

If you have questions about contributing, please open an issue with the 
`question` label, or contact the maintainer via GitHub.

Thank you for helping make YujianAI Pro better!
