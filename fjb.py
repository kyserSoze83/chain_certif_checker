#
#   File: fjb.py
#   Author: Jean-Baptiste Relave
#   Date : 16/02/2024
#

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from vclib import certificat

def initCertif(certificat_format, certificat_path):
    certificat_obj = certificat(certificat_format, certificat_path)

    try:
        with open(certificat_path, "rb") as f:
            cert_data = f.read()

        # Charger le certificat
        if certificat_format == 0:
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        else:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())

        # Numéro de série
        certificat_obj.id = cert.serial_number

        # Algorithme de chiffrement et fonction de hachage
        certificat_obj.signAlgo = cert.signature_hash_algorithm

        # Signature
        certificat_obj.sign = cert.signature

        # TBS
        certificat_obj.tbs = cert.tbs_certificate_bytes

        # Dates de validité
        certificat_obj.dateBefore = cert.not_valid_before_utc
        certificat_obj.dateAfter = cert.not_valid_after_utc

        # Subject et Issuer
        certificat_obj.subject = cert.subject
        certificat_obj.issuer = cert.issuer

        # Clé publique
        certificat_obj.kpub = cert.public_key()

        # KeyUsage
        extensions = cert.extensions
        certificat_obj.keyUsage = None

        for ext in extensions:
            if isinstance(ext.value, x509.KeyUsage):
                certificat_obj.keyUsage = ext.value
                break

        certificat_obj.print()
    except:
        return None
    
    certificat_obj.valid = certificat_obj.checkSign()

    return certificat_obj