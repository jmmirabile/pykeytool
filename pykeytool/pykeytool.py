#!/usr/bin/env python3
"""
PyKeyTool - A sane alternative to Java's keytool
Simple syntax, no stupid validation requirements.
"""

import argparse
import sys
import os
import yaml
import getpass
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12


def get_config_path():
    """Get config file path following system conventions"""
    # 1. Environment variable override (highest priority)
    if 'PYKEYTOOL_CONFIG' in os.environ:
        return Path(os.environ['PYKEYTOOL_CONFIG'])

    # 2. Current directory (for local/project-specific configs)
    local_config = Path('./pykeytool.conf')
    if local_config.exists():
        return local_config

    # 3. System config directory (for servers/system-wide configs)
    if os.name == 'posix':
        system_config = Path('/etc/pykeytool/pykeytool.conf')
        if system_config.exists():
            return system_config

    # 4. User config directory (fallback for desktop use)
    if os.name == 'posix':  # Linux/macOS
        user_config_dir = Path.home() / '.config' / 'pykeytool'
    else:  # Windows
        user_config_dir = Path(os.environ.get('APPDATA', Path.home())) / 'pykeytool'

    user_config_dir.mkdir(parents=True, exist_ok=True)
    return user_config_dir / 'pykeytool.conf'


def create_default_config(config_path):
    """Create default configuration file"""
    default_config = {
        'org_templates': {
            'client': {
                'OU': 'Client Certificates',
                'O': 'Example Corporation',
                'C': 'US'
            },
            'server': {
                'OU': 'Server Certificates',
                'O': 'Example Corporation',
                'C': 'US'
            },
            'ca': {
                'OU': 'Certificate Authority',
                'O': 'Example Corporation',
                'C': 'US'
            }
        },
        'defaults': {
            'keystore_type': 'PKCS12',
            'key_size': 2048,
            'validity_days': 365
        }
    }

    with open(config_path, 'w') as f:
        yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)


def load_config():
    """Load configuration from pykeytool.conf"""
    config_path = get_config_path()

    if not config_path.exists():
        create_default_config(config_path)
        print(f"Created default config file: {config_path}")

    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def build_dn_from_template(config, template_name, cn, overrides=None):
    """Build DN from org template + CN"""
    if template_name not in config['org_templates']:
        available = ', '.join(config['org_templates'].keys())
        raise ValueError(f"Unknown org template '{template_name}'. Available templates: {available}")

    template = config['org_templates'][template_name].copy()

    # Apply any overrides
    if overrides:
        template.update(overrides)

    # Build DN attributes
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]

    if 'OU' in template:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, template['OU']))
    if 'O' in template:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, template['O']))
    if 'L' in template:
        attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, template['L']))
    if 'ST' in template:
        attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, template['ST']))
    if 'C' in template:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, template['C']))

    return x509.Name(attributes)


def main():
    parser = argparse.ArgumentParser(
        description='PyKeyTool - Easy certificate keystore management',
        epilog="""
Installation suggestion:
  sudo cp pykeytool /usr/local/bin/

Config file locations (checked in order):
  1. $PYKEYTOOL_CONFIG (environment variable)
  2. ./pykeytool.conf (current directory)
  3. /etc/pykeytool/pykeytool.conf (system-wide, Linux/macOS)
  4. ~/.config/pykeytool/pykeytool.conf (user config, Linux/macOS)
  4. %%APPDATA%%/pykeytool/pykeytool.conf (user config, Windows)

Server installation:
  sudo mkdir /etc/pykeytool
  sudo pykeytool --init-config  # Creates /etc/pykeytool/pykeytool.conf

Use --init-config to create a default config file.

- It's best to always set the --alias option to the CN of the cert for all keystore related commands. As the CN(common name) 
  is typically unique. In practice, store a single key pair in the pkcs12 files. Storing multiple key pairs in the same 
  file, implies that the keystore is shared by more than one system or process, which implies access to more than one private key.
  
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Primary operations (mutually exclusive)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--new-cert', action='store_true', help='Generate new certificate key+CSR')
    group.add_argument('--import-cert', metavar='CERTFILE', help='Import signed certificate')
    group.add_argument('--export-key', action='store_true', help='Export private key')
    group.add_argument('--list', action='store_true', help='List keystore contents')
    group.add_argument('--list-templates', action='store_true', help='List available org templates')
    group.add_argument('--init-config', action='store_true', help='Create default config file')
    group.add_argument('--change-password', action='store_true', help='Change keystore password')

    # Certificate parameters
    cert_group = parser.add_argument_group('certificate parameters')
    cert_group.add_argument('--org-template', help='Organization template for RDN (e.g., client, server, ca)')
    cert_group.add_argument('--cn', help='Common Name for the certificate')

    # DN overrides
    override_group = parser.add_argument_group('DN overrides',
                                               'Override specific DN fields from the org template')
    override_group.add_argument('--o', help='Organization (O)')
    override_group.add_argument('--ou', help='Organizational Unit (OU)')
    override_group.add_argument('--c', help='Country (C)')
    override_group.add_argument('--st', help='State/Province (ST)')
    override_group.add_argument('--l', help='Locality (L)')

    # Common options
    parser.add_argument('--keystore', default='keystore.p12', help='Keystore file (default: keystore.p12)')
    #parser.add_argument('--keystore', help='Keystore file (default: [cn].p12)')
    parser.add_argument('--alias', default='mykey', help='Key alias (default: mykey)')
    #parser.add_argument('--storepass', default='changeit',
    #                    help='Current keystore password (default: changeit, will prompt for --change-password)')

    args = parser.parse_args()

    # Handle init-config before loading config
    if args.init_config:
        config_path = get_config_path()
        # For system-wide config on servers
        if os.geteuid() == 0 and os.name == 'posix':  # Running as root on Unix
            system_config_dir = Path('/etc/pykeytool')
            system_config_dir.mkdir(parents=True, exist_ok=True)
            config_path = system_config_dir / 'pykeytool.conf'

        create_default_config(config_path)
        print(f"Created default config file: {config_path}")
        print(f"\nEdit this file to customize your organization templates:")
        print(f"  {config_path}")
        return

    # Load configuration
    try:
        config = load_config()
    except Exception as e:
        print(f"Error loading config: {e}")
        sys.exit(1)

    try:
        if args.list_templates:
            print("Available organization templates:")
            for template_name, template_data in config['org_templates'].items():
                print(f"\n  {template_name}:")
                for key, value in template_data.items():
                    print(f"    {key}: {value}")
            return

        elif args.new_cert:
            # Must have org-template and cn
            if not args.org_template:
                print("Error: --new-cert requires --org-template")
                sys.exit(1)

            if not args.cn:
                print("Error: --new-cert requires --cn")
                sys.exit(1)

            cn = args.cn
            cert_name = args.cn
            print(f"Generating certificate using template '{args.org_template}' for CN: {cn}")

            # Build DN overrides from command line args
            overrides = {}
            if args.o: overrides['O'] = args.o
            if args.ou: overrides['OU'] = args.ou
            if args.c: overrides['C'] = args.c
            if args.st: overrides['ST'] = args.st
            if args.l: overrides['L'] = args.l

            subject = build_dn_from_template(config, args.org_template, cn, overrides)

            # Generate key
            key_size = config['defaults']['key_size']
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

            # Create CSR
            csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())

            # Save CSR file
            csr_file = f"{cert_name}.csr"
            with open(csr_file, 'wb') as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))

            # Get keystore password
            #if args.storepass:
            password = "changeit"
            if args.keystore:
                password = getpass.getpass(f"Enter password for keystore {cn}.p12: ")

            # Create empty PKCS12 with just the private key
            p12_data = pkcs12.serialize_key_and_certificates(
                name=cert_name.encode(),
                key=private_key,
                cert=None,  # No cert yet
                cas=None,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )

            # Use cert name as keystore name if not specified
            keystore_name = args.keystore if args.keystore != 'keystore.p12' else f"{cert_name}.p12"

            with open(keystore_name, 'wb') as f:
                f.write(p12_data)

            print(f"✓ Private key saved to keystore: {keystore_name}")
            print(f"✓ CSR saved to: {csr_file}")
            print(f"✓ Key size: {key_size} bits")
            print(f"✓ Full DN: {subject.rfc4514_string()}")
            print(f"→ Send {csr_file} to your CA, then use --import-cert to add the signed certificate")

        elif args.import_cert:
            print(f"Importing certificate from: {args.import_cert}")

            # Get keystore password
            #if args.storepass:
            #    password = args.storepass
            password = getpass.getpass(f"Enter password for keystore {args.keystore}: ")

            # Load existing keystore
            with open(args.keystore, 'rb') as f:
                private_key, _, _ = pkcs12.load_key_and_certificates(f.read(), password.encode())

            # Load certificate
            with open(args.import_cert, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())

            alias = ""
            if args.alias:
                alias = args.alias
            else:
                cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                if cn:
                    alias = cn[0].value

            # Create new PKCS12 with key + cert
            p12_data = pkcs12.serialize_key_and_certificates(
                name=alias.encode(),
                key=private_key,
                cert=cert,
                cas=None,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            )

            with open(args.keystore, 'wb') as f:
                f.write(p12_data)

            print(f"✓ Certificate imported to keystore: {args.keystore}")
            print(f"✓ Ready to use with: -Djavax.net.ssl.keyStore={args.keystore} -Djavax.net.ssl.keyStoreType=PKCS12")

        elif args.export_key:
            print(f"Exporting private key from: {args.keystore}")

            # Get keystore password
            #if args.storepass:
            #    password = args.storepass
            #else:
            password = getpass.getpass(f"Enter password for keystore {args.keystore}: ")

            with open(args.keystore, 'rb') as f:
                private_key, cert, _ = pkcs12.load_key_and_certificates(f.read(), password.encode())

            if private_key:
                key_file = f"{args.alias}.key"
                with open(key_file, 'wb') as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                print(f"✓ Private key exported to: {key_file}")

            if cert:
                cert_file = f"{args.alias}.crt"
                with open(cert_file, 'wb') as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                print(f"✓ Certificate exported to: {cert_file}")

        elif args.list:
            print(f"Keystore: {args.keystore}")

            if not Path(args.keystore).exists():
                print("Keystore does not exist")
                return

            # Get keystore password
            #if args.storepass:
            #password = args.storepass
            #else:
            password = getpass.getpass(f"Enter password for keystore {args.keystore}: ")

            with open(args.keystore, 'rb') as f:
                private_key, cert, ca_certs = pkcs12.load_key_and_certificates(f.read(), password.encode())

            print(f"Alias: {args.alias}")
            if private_key:
                print("  ✓ Private key present")
            if cert:
                print(f"  ✓ Certificate: {cert.subject.rfc4514_string()}")
                print(f"      Expires: {cert.not_valid_after}")
            if ca_certs:
                print(f"  ✓ CA certificates: {len(ca_certs)}")

        elif args.change_password:
            print(f"Changing password for keystore: {args.keystore}")

            # Always prompt for current password (we don't know what it is)
            current_password = getpass.getpass("Enter current keystore password: ")

            # Get new password with confirmation
            while True:
                new_password = getpass.getpass("Enter new keystore password: ")
                if not new_password:
                    print("Password cannot be empty. Please try again.")
                    continue

                confirm_password = getpass.getpass("Confirm new keystore password: ")
                if new_password == confirm_password:
                    break
                else:
                    print("Passwords do not match. Please try again.")

            # Load keystore with current password
            try:
                with open(args.keystore, 'rb') as f:
                    private_key, cert, ca_certs = pkcs12.load_key_and_certificates(f.read(), current_password.encode())
            except Exception as e:
                print(f"Error: Unable to load keystore with provided password: {e}")
                sys.exit(1)

            # Re-save with new password
            p12_data = pkcs12.serialize_key_and_certificates(
                name=args.alias.encode(),
                key=private_key,
                cert=cert,
                cas=ca_certs,
                encryption_algorithm=serialization.BestAvailableEncryption(new_password.encode())
            )

            with open(args.keystore, 'wb') as f:
                f.write(p12_data)

            print(f"✓ Password changed successfully")
            print(f"✓ Keystore: {args.keystore}")

    except FileNotFoundError as e:
        print(f"Error: File not found - {e.filename}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()