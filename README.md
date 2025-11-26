# SHA1-HULUD Scanner

A comprehensive bash scanner to detect compromised npm packages from the SHA1-HULUD pt 2 supply chain attack.

## 🚨 About SHA1-HULUD pt 2

SHA1-HULUD pt 2 is a supply chain attack targeting 288+ npm packages including:
- PostHog packages (`@posthog/*`, `posthog-node`, etc.)
- Zapier packages (`@zapier/*`)
- AsyncAPI packages (`@asyncapi/*`)
- Postman packages (`@postman/*`)
- ENS Domains packages (`@ensdomains/*`, `ethereum-ens`)
- MCP packages (`mcp-use`, `@mcp-use/*`)
- And many more...

**More information:** [HelixGuard Blog Post](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)

## ✨ Features

- ✅ Scans **288+ compromised packages** from SHA1-HULUD pt 2
- ✅ **Recursive scanning** for monorepos and nested projects
- ✅ Multi-package manager support: **npm**, **yarn**, **bun**, **pnpm**
- ✅ 4-stage scanning:
  - Direct dependencies (`package.json`)
  - Transitive dependencies (`node_modules`)
  - Lockfiles (all package managers)
  - SHA1 markers detection
- ✅ **False positive filtering** for legitimate packages like `@aws-crypto/sha1-browser`
- ✅ Shows **specific package names** when SHA1 markers detected
- ✅ Clear color-coded output with actionable remediation steps

## 📦 Installation

```bash
git clone https://github.com/standujar/sha1-hulud-scanner.git
cd sha1-hulud-scanner
chmod +x sha1-hulud-scanner.sh
```

## 🚀 Usage

```bash
./sha1-hulud-scanner.sh [options] <project_directory>
```

### Options

| Option | Description |
|--------|-------------|
| `-r, --recursive` | Scan all nested Node.js projects in the directory |
| `-h, --help` | Show help message |

### Examples

```bash
# Scan a single project
./sha1-hulud-scanner.sh /path/to/your/project

# Scan a monorepo (all nested projects)
./sha1-hulud-scanner.sh -r /path/to/monorepo

# Scan all projects in a workspace
./sha1-hulud-scanner.sh --recursive ~/Projects

# Scan current directory
./sha1-hulud-scanner.sh .

# Scan all projects in current directory
./sha1-hulud-scanner.sh -r .
```

## 📊 Output Example

### Single Project Scan

```
🔍 SHA1-HULUD Scanner v2.2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📂 Root: /path/to/project
🔄 Recursive mode: false
📋 288 packages to check
📋 5 known false positives to exclude

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Scanning: /path/to/project
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔎 [1/4] Scanning direct dependencies (package.json)...
  ✓ No compromised packages in direct dependencies

🔎 [2/4] Scanning node_modules (transitive)...
  ✓ No compromised packages installed

🔎 [3/4] Scanning lockfiles...
  ✓ No compromised packages in lockfiles

🔎 [4/4] Scanning for SHA1-HULUD markers...
  ✓ No SHA1-HULUD markers detected

  ✓ Project clean

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 SCAN SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ NO COMPROMISE DETECTED

All projects are clean — no SHA1-HULUD packages found.

📊 Statistics:
   • 1 project(s) scanned
   • 288 packages checked per project
   • 0 compromised packages
```

### Recursive Scan (Monorepo)

```
🔍 SHA1-HULUD Scanner v2.2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📂 Root: /path/to/monorepo
🔄 Recursive mode: true
📋 288 packages to check
📋 5 known false positives to exclude

🔎 Finding Node.js projects...
📦 Found 5 project(s)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Scanning: /path/to/monorepo
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
... (scan output) ...
  ✓ Project clean

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Scanning: /path/to/monorepo/packages/app
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
... (scan output) ...
  ✓ Project clean

... (more projects) ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 SCAN SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ NO COMPROMISE DETECTED

All projects are clean — no SHA1-HULUD packages found.

📊 Statistics:
   • 5 project(s) scanned
   • 288 packages checked per project
   • 0 compromised packages
```

## 🛡️ What it Checks

### Stage 1: Direct Dependencies
Scans `package.json` for any compromised packages in `dependencies` and `devDependencies`.

### Stage 2: Node Modules
Checks if compromised packages are actually installed in `node_modules/` (including transitive dependencies).

### Stage 3: Lockfiles
Scans lockfiles for all package managers:
- `package-lock.json` (npm)
- `yarn.lock` (yarn)
- `bun.lock` (bun - binary format)
- `pnpm-lock.yaml` (pnpm)

### Stage 4: SHA1 Markers
Detects packages with "sha1" in their name, which is a signature of the attack. Filters out known false positives like AWS crypto packages.

## ⚠️ If Compromised Packages Found

The scanner will show detailed remediation steps:

1. 🛑 **STOP** all builds/CI immediately
2. 🔒 **Isolate** CI runners (if self-hosted)
3. 🔑 **Rotate ALL** sensitive keys:
   - GitHub tokens (PAT, fine-grained, App)
   - AWS credentials (if non-OIDC)
   - NPM tokens
   - API keys (PostHog, Stripe, etc.)
4. 🗑 **Delete** `node_modules` and lockfiles
5. 📝 **Update** dependencies to clean versions
6. 🔍 **Audit** CI logs from last 48 hours

## 📋 Requirements

- Bash 4.0+
- `grep`, `strings`, `sed` (standard Unix tools)
- Package manager lockfiles present in project

## 🔧 Known False Positives

The scanner automatically excludes these legitimate packages:
- `@aws-crypto/sha1-browser` - AWS SDK for S3 checksums
- `@aws-crypto/sha256-browser` - AWS crypto utilities
- `@aws-crypto/sha256-js` - AWS crypto utilities
- `sha1` - Legitimate crypto library
- `sha.js` - Legitimate crypto library

## 📝 Package List

The scanner checks against 288 compromised packages defined in `sha1-hulud-packages.txt`.

To update the list:
```bash
# Edit sha1-hulud-packages.txt
# One package per line, comments supported with #
```

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 🙏 Acknowledgments

This project is based on the original [sha1-hulud-scanner](https://github.com/standujar/sha1-hulud-scanner) by [@standujar](https://github.com/standujar). Thank you for creating and sharing this essential security tool!

## 📜 License

MIT License - Feel free to use this scanner to protect your projects.

## 🔗 Resources

- [HelixGuard SHA1-HULUD Analysis](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)
- [npm Advisory Database](https://npmjs.com/advisories)

## ⚡ Quick Start

```bash
# Clone and run
git clone https://github.com/standujar/sha1-hulud-scanner.git
cd sha1-hulud-scanner
chmod +x sha1-hulud-scanner.sh

# Scan a single project
./sha1-hulud-scanner.sh /path/to/your/project

# Scan all projects in a monorepo/workspace
./sha1-hulud-scanner.sh -r /path/to/monorepo
```

---

**Stay safe! Scan your projects regularly.** 🛡️
