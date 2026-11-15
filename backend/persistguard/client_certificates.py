import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key, load_pem_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


CLIENT_CERTIFICATE_LIFETIME = timedelta(hours=24)


class CertificateIssuanceError(Exception):
    pass


def issue_client_certificate(endpoint_id: UUID, device_public_key: bytes) -> x509.Certificate:
    cert_file = os.getenv("PERSISTGUARD_AGENT_CA_CERT_FILE")
    key_file = os.getenv("PERSISTGUARD_AGENT_CA_KEY_FILE")
    if not cert_file or not key_file:
        raise CertificateIssuanceError("Agent CA is not configured")

    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        issuer = x509.load_pem_x509_certificate(Path(cert_file).read_bytes())
        signer = load_pem_private_key(Path(key_file).read_bytes(), password=None)
        device_key = load_der_public_key(device_public_key)
        constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
        if not constraints.ca or not usage.key_cert_sign:
            raise CertificateIssuanceError("Agent CA certificate cannot sign certificates")
        if not issuer.not_valid_before_utc <= now < issuer.not_valid_after_utc:
            raise CertificateIssuanceError("Agent CA is outside its validity period")
        if not isinstance(signer, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise CertificateIssuanceError("Agent CA must use RSA or ECDSA")
        if isinstance(signer, rsa.RSAPrivateKey) and signer.key_size < 2048:
            raise CertificateIssuanceError("Agent CA RSA key is too small")
        issuer_key = issuer.public_key()
        issuer_key_der = issuer_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        signer_key_der = signer.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if signer_key_der != issuer_key_der:
            raise CertificateIssuanceError("Agent CA key does not match its certificate")
        if not isinstance(device_key, ec.EllipticCurvePublicKey) or not isinstance(device_key.curve, ec.SECP256R1):
            raise CertificateIssuanceError("Registered device key must use ECDSA P-256")

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(endpoint_id))])
        identity = x509.UniformResourceIdentifier(f"urn:persistguard:endpoint:{endpoint_id}")
        key_usage = x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=None, decipher_only=None,
        )
        try:
            issuer_key_id = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            authority_key_id = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_key_id)
        except x509.ExtensionNotFound:
            authority_key_id = x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key)

        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer.subject)
            .public_key(device_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(min(now + CLIENT_CERTIFICATE_LIFETIME, issuer.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([identity]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(key_usage, critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(device_key), critical=False)
            .add_extension(authority_key_id, critical=False)
            .sign(signer, hashes.SHA256())
        )
    except (OSError, TypeError, ValueError, UnsupportedAlgorithm, x509.ExtensionNotFound, x509.DuplicateExtension) as error:
        raise CertificateIssuanceError("Invalid agent CA configuration or device public key") from error
