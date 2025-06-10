import base64
from datetime import datetime
from typing import Dict, List, Optional, Any
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa

def parse_certificate_info(cert_pem_content: str) -> Dict:
    """
    Parse certificate information from PEM format certificate.
    
    Args:
        cert_pem_content: PEM format certificate string
    
    Returns:
        Dictionary containing all certificate information
    """
    
    try:
        # Parse the PEM certificate
        cert = x509.load_pem_x509_certificate(cert_pem_content.encode(), default_backend())
        
        # Structure like the example
        cert_data = {
            "Certificate": {
                "Data": {
                    "Version": f"{cert.version.value} (0x{cert.version.value:x})",
                    "Serial Number": format_serial_number(cert.serial_number),
                    "Signature Algorithm": cert.signature_algorithm_oid._name,
                    "Issuer": format_name_attributes(cert.issuer),
                    "Validity": {
                        "Not Before": cert.not_valid_before.strftime("%b %d %H:%M:%S %Y GMT"),
                        "Not After": cert.not_valid_after.strftime("%b %d %H:%M:%S %Y GMT")
                    },
                    "Subject": format_name_attributes(cert.subject),
                    "Subject Public Key Info": format_public_key_info(cert.public_key()),
                    "X509v3 extensions": format_extensions(cert)
                },
                "Signature Algorithm": cert.signature_algorithm_oid._name,
                "Signature": format_signature(cert.signature)
            }
        }
        
        return cert_data
        
    except Exception as e:
        return {'error': f"Failed to parse certificate: {str(e)}"}

def format_serial_number(serial_num: int) -> str:
    """Format serial number in hex with colons"""
    hex_str = f"{serial_num:x}"
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    return ":".join([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])

def format_name_attributes(name: x509.Name) -> Dict[str, Any]:
    """Format X.509 name attributes"""
    attributes = {}
    for attribute in name:
        attr_name = attribute.oid._name
        if attr_name == "commonName":
            attributes["commonName"] = attribute.value
        elif attr_name == "organizationName":
            attributes["organizationName"] = attribute.value
        elif attr_name == "countryName":
            attributes["countryName"] = attribute.value
        elif attr_name == "organizationalUnitName":
            attributes["organizationalUnitName"] = attribute.value
        elif attr_name == "localityName":
            attributes["localityName"] = attribute.value
        elif attr_name == "stateOrProvinceName":
            attributes["stateOrProvinceName"] = attribute.value
    return attributes

def format_public_key_info(public_key) -> Dict[str, Any]:
    """Format public key information"""
    key_info = {}
    
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        key_info["Public Key Algorithm"] = "id-ecPublicKey"
        key_size = public_key.curve.key_size
        key_info["Public-Key"] = f"({key_size} bit)"
        
        # Get public key bytes
        try:
            key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            formatted_bytes = format_hex_bytes(key_bytes.hex())
            key_info["pub"] = formatted_bytes
        except Exception:
            key_info["pub"] = ["Unable to format public key"]
        
        # Curve information
        curve_name = public_key.curve.name
        key_info["ASN1 OID"] = curve_name
        
        if curve_name == "secp256r1":
            key_info["NIST CURVE"] = "P-256"
        elif curve_name == "secp384r1":
            key_info["NIST CURVE"] = "P-384"
        elif curve_name == "secp521r1":
            key_info["NIST CURVE"] = "P-521"
    
    elif isinstance(public_key, rsa.RSAPublicKey):
        key_info["Public Key Algorithm"] = "rsaEncryption"
        key_info["RSA Public-Key"] = f"({public_key.key_size} bit)"
        
        # Get RSA modulus and exponent
        try:
            public_numbers = public_key.public_numbers()
            modulus_hex = format(public_numbers.n, 'x')
            key_info["Modulus"] = format_hex_bytes(modulus_hex)
            key_info["Exponent"] = str(public_numbers.e)
        except Exception:
            key_info["Modulus"] = ["Unable to format modulus"]
            key_info["Exponent"] = "Unknown"
        
    return key_info

def format_hex_bytes(hex_string: str) -> List[str]:
    """Format hex string with proper line breaks"""
    hex_upper = hex_string.upper()
    lines = []
    for i in range(0, len(hex_upper), 30):  # 15 bytes per line
        line = hex_upper[i:i+30]
        formatted_line = ":".join([line[j:j+2] for j in range(0, len(line), 2)])
        if i + 30 < len(hex_upper):
            formatted_line += ":"
        lines.append(formatted_line)
    return lines

def format_extensions(cert: x509.Certificate) -> Dict[str, Any]:
    """Format X.509v3 extensions"""
    extensions = {}
    
    for ext in cert.extensions:
        ext_name = ext.oid._name
        critical = " critical" if ext.critical else ""
        
        if ext.oid == x509.oid.ExtensionOID.KEY_USAGE:
            usage_list = []
            if ext.value.digital_signature:
                usage_list.append("Digital Signature")
            if ext.value.key_encipherment:
                usage_list.append("Key Encipherment")
            if ext.value.key_agreement:
                usage_list.append("Key Agreement")
            if ext.value.key_cert_sign:
                usage_list.append("Certificate Sign")
            if ext.value.crl_sign:
                usage_list.append("CRL Sign")
            extensions[f"X509v3 Key Usage{critical}"] = usage_list
            
        elif ext.oid == x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
            usage_list = []
            for usage in ext.value:
                if usage == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                    usage_list.append("TLS Web Server Authentication")
                elif usage == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                    usage_list.append("TLS Web Client Authentication")
                else:
                    usage_list.append(usage._name)
            extensions[f"X509v3 Extended Key Usage{critical}"] = usage_list
            
        elif ext.oid == x509.oid.ExtensionOID.BASIC_CONSTRAINTS:
            ca_value = "TRUE" if ext.value.ca else "FALSE"
            extensions[f"X509v3 Basic Constraints{critical}"] = f"CA:{ca_value}"
            
        elif ext.oid == x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            ski = ext.value.digest.hex().upper()
            formatted_ski = ":".join([ski[i:i+2] for i in range(0, len(ski), 2)])
            extensions[f"X509v3 Subject Key Identifier{critical}"] = formatted_ski
            
        elif ext.oid == x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
            if ext.value.key_identifier:
                aki = ext.value.key_identifier.hex().upper()
                formatted_aki = ":".join([aki[i:i+2] for i in range(0, len(aki), 2)])
                extensions[f"X509v3 Authority Key Identifier{critical}"] = {
                    "keyid": formatted_aki
                }
                
        elif ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            san_list = []
            for name in ext.value:
                if isinstance(name, x509.DNSName):
                    san_list.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    san_list.append(f"IP:{name.value}")
            extensions[f"X509v3 Subject Alternative Name{critical}"] = san_list
            
        elif ext.oid == x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
            aia_list = []
            for access_desc in ext.value:
                if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    aia_list.append(f"CA Issuers - URI:{access_desc.access_location.value}")
                elif access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    aia_list.append(f"OCSP - URI:{access_desc.access_location.value}")
            extensions[f"Authority Information Access{critical}"] = aia_list
            
        elif ext.oid == x509.oid.ExtensionOID.CERTIFICATE_POLICIES:
            policies = []
            for policy in ext.value:
                policies.append(f"Policy: {policy.policy_identifier.dotted_string}")
            extensions[f"X509v3 Certificate Policies{critical}"] = policies
            
        elif ext.oid == x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS:
            crl_points = []
            for point in ext.value:
                if point.full_name:
                    for name in point.full_name:
                        crl_points.append(f"Full Name:\n  URI:{name.value}")
            extensions[f"X509v3 CRL Distribution Points{critical}"] = crl_points
            
        elif ext.oid == x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS:
            extensions[f"CT Precertificate SCTs{critical}"] = "Present (detailed parsing not implemented)"
    
    return extensions

def format_signature(signature: bytes) -> List[str]:
    """Format certificate signature"""
    hex_sig = signature.hex()
    lines = []
    for i in range(0, len(hex_sig), 30):  # 15 bytes per line
        line = hex_sig[i:i+30]
        formatted_line = ":".join([line[j:j+2] for j in range(0, len(line), 2)])
        if i + 30 < len(hex_sig):
            formatted_line += ":"
        lines.append(formatted_line)
    return lines

def format_certificate_info(cert_info: Dict) -> Dict:
    """
    Return the certificate information as-is for JSON output.
    """
    return cert_info