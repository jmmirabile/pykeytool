# PyKeyTool

A sane alternative to Java's keytool for certificate management. No more cryptic error messages, chain validation failures, or "why won't this just work?" moments.

## Why PyKeyTool?

If you've ever tried to use Java's keytool, you know the pain:
- `Failed to establish chain from reply` - What does this even mean?
- Can't specify custom truststores for certificate imports.
- Can't import a cert into keystore without having the chain, but are in possession of the private key? Ridiculous!
- Can't export private keys you already own.
- Confusing parameter combinations and unclear error messages.
- Forces you to mix CA certificates with private keys! What? Why?
  - What happened to separation of concerns? 
  - A person or process updating the CA certs would then need the password to the keystore? No way!

PyKeyTool fixes all of this with a clean, intuitive interface that just works. Written with Python, deployed as a 
single file. No python imports, etc. Run it locally for testing or on your servers. 

## Features

✅ **No stupid validation** - If you want to store a certificate, it stores it  
✅ **Configurable organization templates** - Set your company's DN format once  
✅ **PKCS12 by default** - Modern format that works everywhere  
✅ **Clear error messages** - Know exactly what went wrong  
✅ **Cross-platform** - Linux, macOS, Windows  
✅ **Single executable** - No runtime dependencies  

## Quick Start

```bash
# Generate a certificate with your organization's template
pykeytool --new-cert --org-template client --cn myapp-prod

# Import the signed certificate (no chain validation nonsense!)
pykeytool --import-cert myapp-prod-signed.crt

# Use with Java applications
java -Djavax.net.ssl.keyStore=myapp-prod.p12 -Djavax.net.ssl.keyStoreType=PKCS12 MyApp
```

## Installation

### Option 1: Download Pre-built Binary

**Latest Release:** [![GitHub release](https://img.shields.io/github/v/release/yourusername/pykeytool)](https://github.com/yourusername/pykeytool/releases/latest)

| Platform | Download                                                                                                                  |
|----------|---------------------------------------------------------------------------------------------------------------------------|
| **Linux (x64)** | [pykeytool-linux-x64](https://github.com/jmmirabile/pykeytool/releases/latest/download/pykeytool-linux-x64)               |
| **macOS (Intel)** | [pykeytool-macos-intel](https://github.com/jmmirabile/pykeytool/releases/latest/download/pykeytool-macos-intel)         |
| **macOS (Apple Silicon)** | [pykeytool-macos-arm64](https://github.com/jmmirabile/pykeytool/releases/latest/download/pykeytool-macos-arm64)         |
| **Windows (x64)** | [pykeytool-windows-x64.exe](https://github.com/jmmirabile/pykeytool/releases/latest/download/pykeytool-windows-x64.exe) |


### Option 2: Build from Source
```bash
git clone https://github.com/yourusername/pykeytool.git
cd pykeytool
pip install -r requirements.txt
pyinstaller pykeytool-linux.spec
```

## Configuration

PyKeyTool uses organization templates to standardize your certificates:

```bash
# Create default configuration
pykeytool --init-config

# List available templates
pykeytool --list-templates
```

### Config File Locations
PyKeyTool looks for configuration in this order:
1. `$PYKEYTOOL_CONFIG` (environment variable)
2. `./pykeytool.conf` (current directory)
3. `/etc/pykeytool/pykeytool.conf` (system-wide, Linux/macOS)
4. `~/.config/pykeytool/pykeytool.conf` (user config)

### Server Installation
```bash
sudo mkdir /etc/pykeytool
sudo pykeytool --init-config  # Creates system-wide config
```

## Usage

### Generate New Certificate
```bash
# Basic usage
pykeytool --new-cert --org-template client --cn myserver.example.com

# Override organization fields
pykeytool --new-cert --org-template server --cn api.example.com --o "My Company"
```

### Import Signed Certificate
```bash
# Just works - no chain validation headaches
pykeytool --import-cert signed-certificate.crt --keystore myserver.p12
```

### Export Private Key
```bash
# Export what you own (unlike keytool!)
pykeytool --export-key --keystore myserver.p12
```

### List Keystore Contents
```bash
pykeytool --list --keystore myserver.p12
```

## Configuration Example

```yaml
org_templates:
  client:
    OU: "Client Certificates"
    O: "Acme Corporation"
    C: "US"
  server:
    OU: "Server Certificates"
    O: "Acme Corporation" 
    C: "US"
  ca:
    OU: "Certificate Authority"
    O: "Acme Corporation"
    C: "US"

defaults:
  keystore_type: "PKCS12"
  key_size: 2048
  validity_days: 365
```

## Command Reference

| Command | Description |
|---------|-------------|
| `--new-cert` | Generate new certificate key and CSR |
| `--import-cert CERTFILE` | Import signed certificate |
| `--export-key` | Export private key and certificate |
| `--list` | List keystore contents |
| `--list-templates` | Show available organization templates |
| `--init-config` | Create default configuration file |

### Common Options
| Option | Description | Default |
|--------|-------------|---------|
| `--org-template` | Organization template to use | Required |
| `--cn` | Common Name for certificate | Required |
| `--keystore` | Keystore file path | `{cn}.p12` |
| `--alias` | Certificate alias | `mykey` |
| `--storepass` | Keystore password | `changeit` |

### DN Override Options
| Option | Description |
|--------|-------------|
| `--o` | Organization (O) |
| `--ou` | Organizational Unit (OU) |
| `--c` | Country (C) |
| `--st` | State/Province (ST) |
| `--l` | Locality (L) |

## Why Not Just Use OpenSSL?

OpenSSL is powerful but has its own complexity. PyKeyTool bridges the gap between "easy to use" and "works with Java applications" by:
- Generating PKCS12 keystores that Java loves
- Providing templates for consistent certificate DNs
- Handling the Java keystore ecosystem properly
- Being a single executable with no dependencies

## Company-Specific Workflows

PyKeyTool is designed to be wrapped by your own scripts for company-specific certificate naming:

```bash
#!/bin/bash
# mycert - Company wrapper for PyKeyTool
PARTNER="$1"
APP="$2" 
ENV="$3"
CN="${PARTNER}-${APP}-${ENV}"

pykeytool --new-cert --org-template client --cn "$CN"
```

## Requirements

- Python 3.7+ (for building from source)
- No runtime dependencies (pre-built binaries)

## Dependencies (Source)

```
cryptography>=41.0.0
PyYAML>=6.0
pyinstaller>=5.0  # For building
```

## Contributing

Found a bug or want a feature? Please open an issue or submit a pull request!

## License

MIT License - see LICENSE file for details.

## About

Built by someone who got tired of keytool's nonsense and decided to fix it properly. 

From the team behind enterprise certificate management solutions - because if you're going to solve a problem, solve it right.

---

**Need enterprise certificate management?** Check out our [certificate lifecycle platform](https://yourplatform.com) for automated enrollment, renewal, and multi-organization certificate orchestration.