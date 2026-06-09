# Security Policy

## Supported Versions

We take security seriously. The following versions of SSHX are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.0.7   | :white_check_mark: |
| 0.0.6   | :white_check_mark: |
| 0.0.5   | :white_check_mark: |
| < 0.0.5 | :x:                |

## Reporting a Vulnerability

We appreciate your efforts to responsibly disclose your findings and will make every effort to acknowledge your contributions.

### How to Report

If you discover a security vulnerability in SSHX, please report it by **one** of the following methods:

1. **GitHub Security Advisories** (Recommended)

   - Navigate to the [Security tab](https://github.com/talkincode/sshx/security/advisories)
   - Click "Report a vulnerability"
   - Fill in the details of the vulnerability

2. **Email**
   - Send an email to the project maintainers
   - Include detailed information about the vulnerability
   - If possible, include steps to reproduce the issue

### What to Include

When reporting a vulnerability, please include:

- **Description**: A clear description of the vulnerability
- **Impact**: What an attacker could potentially do with this vulnerability
- **Reproduction Steps**: Detailed steps to reproduce the issue
- **Affected Versions**: Which versions are affected
- **Suggested Fix**: If you have suggestions for fixing the issue (optional)
- **Proof of Concept**: Any code or screenshots demonstrating the issue (optional)

### What to Expect

- **Initial Response**: We will acknowledge receipt of your report within **48 hours**
- **Status Updates**: We will provide regular updates on the progress (typically every 5-7 days)
- **Resolution Timeline**: We aim to resolve critical vulnerabilities within **30 days**
- **Disclosure**: Once the vulnerability is fixed, we will:
  - Release a security patch
  - Credit you in the release notes (unless you prefer to remain anonymous)
  - Publish a security advisory with details

### Security Update Process

1. **Triage**: We evaluate the severity and impact of the reported vulnerability
2. **Fix Development**: We develop and test a fix
3. **Release**: We release a patched version
4. **Notification**: We notify users through:
   - GitHub Security Advisories
   - Release notes
   - CHANGELOG updates

## Security Best Practices

When using SSHX, we recommend:

- **Keep Updated**: Always use the latest version with security patches
- **Secure Credentials**: Use the built-in password management feature to store SSH credentials securely in system keyring
- **Password Key Management**: Use meaningful and unique password key names for different servers (e.g., `server-A`, `prod-web`, `dev-db`)
- **SSH Keys**: Prefer SSH key authentication over password authentication when possible
- **Review Commands**: Always review commands before execution, especially with the `--force` flag
- **Limit Permissions**: Run SSHX with minimum required privileges
- **Network Security**: Use SSHX only on trusted networks when handling sensitive credentials
- **Avoid Inline Passwords**: Never use inline passwords in commands (e.g., `--password-set=key:password`); always use interactive prompts

## Known Security Considerations

### Command Validation

SSHX includes built-in validation to prevent dangerous commands (e.g., `rm -rf /`, `:(){ :|:& };:`). However:

- The `--force` flag bypasses these checks
- Always review commands before using `--force`
- Be cautious when executing scripts from untrusted sources

### Credential Storage

- Passwords are stored securely in the system keyring:
  - **macOS**: Keychain Access
  - **Windows**: Credential Manager
  - **Linux**: Secret Service (GNOME Keyring / KDE Wallet)
- Use the `-pk` / `--password-key` parameter to specify different password keys for different servers
- SSH private keys should have appropriate file permissions (600)
- Never commit credentials to version control
- Never share password key names that might reveal server infrastructure details

## Contact

For security-related questions or concerns that are not vulnerabilities, please open a regular issue on GitHub or contact the maintainers directly.

---

**Note**: Please do not publicly disclose security vulnerabilities until we have had a chance to address them.
