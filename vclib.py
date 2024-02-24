#
#   File: validate-cert.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 16/02/2024
#

# ----------------- Imports -----------------
import os
import sys
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography import x509 
from datetime import datetime


# ----------------- Class -----------------
class certificat:
    def __init__(self, _format, _path):
        self.format = _format
        self.path = _path
        self.id = None
        self.signAlgo = None
        self.sign = None
        self.tbs = None
        self.dateBefore = None
        self.dateAfter = None
        self.expired = False
        self.subject = None
        self.issuer = None
        self.kpub = None
        self.keyUsage = None
        self.keyUsageValid = True
        self.autoSign = False
        self.isCA = False
        self.valid = False


    def checkSign(self):
        # Récupérer la clé publique du certificat
        cle_publique = self.kpub

        # Vérifier la signature
        try:
            cle_publique.verify(
                self.sign,
                self.tbs,
                padding.PKCS1v15(),
                self.signAlgo
            )

            self.valid = True
            return True
        except:
            pass

        try:
            cle_publique.verify(
                self.sign,
                self.tbs,
                ec.ECDSA(self.signAlgo)
            )

            self.valid = True
            return True
        except:
            pass

        return False 


    def checkParam(self):
        # Récupérer la date actuelle
        date_actuelle = datetime.now()

        # ici on vérifie que la date actuelle se trouve bien après la date de début et avant la date de fin
        if not (date_actuelle < self.dateAfter and date_actuelle > self.dateBefore):
            self.expired = True
            return False
        else:
            #ici on vérifie que le sujet et l'emmeteur sont les mêmes
            if self.issuer == self.subject:
                self.autoSign = True
                if not self.isCA:
                    return False

            #ici on vérifie les usages de la clé qui a servi a signer le certificat (la clé ne doit pas servir à signer et à chiffrer à la fois)
            if not (self.keyUsage.key_encipherment==False and self.keyUsage.data_encipherment==False and self.keyUsage.key_agreement==False and self.keyUsage.key_cert_sign==True and self.keyUsage.crl_sign==True):
                self.keyUsageValid = False
                return False
            
        return True

    def displayJson(self):
        sign_algo_str = str(self.signAlgo.name)

        sign_hex = self.sign.hex()

        date_before_str = self.dateBefore.strftime("%Y-%m-%d %H:%M:%S")
        date_after_str = self.dateAfter.strftime("%Y-%m-%d %H:%M:%S")

        kpub_pem = self.kpub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        issuer_str = self.issuer.rfc4514_string()
        subject_str = self.subject.rfc4514_string()

        key_usage_str = str(self.keyUsage)

        cert_json = {
            "id": str(self.id),
            "format": str(self.format),
            "crt_id": str(self.id),
            "signAlgo": sign_algo_str,
            "sign": sign_hex,
            "dateBefore": date_before_str,
            "dateAfter": date_after_str,
            "expired": str(self.expired),
            "subject": subject_str,
            "issuer": issuer_str,
            "kpub": kpub_pem,
            "keyUsage": key_usage_str,
            "keyUsageValid": str(self.keyUsageValid),
            "autoSign": str(self.autoSign),
            "IsCA": str(self.isCA),
            "valid": str(self.valid)
        }

        cert_json_str = json.dumps(cert_json, indent=4)
        print(cert_json_str)


# ----------------- Functions -----------------
def checkArgs():
    if len(sys.argv)-1 !=3:
        return -1
    if sys.argv[1]!="-format":
        return -1
    if sys.argv[2]!= "DER" and sys.argv[2]!= "PEM":
        return -1
    if os.path.exists(sys.argv[3]) == False:
        return -1
    #si le format est PEM on renvoie 0, si c'est DER on renvoie 1
    if sys.argv[2]== "DER":
        format = 1
    elif sys.argv[2]== "PEM":
        format = 0
    else:
        return -1
  
    info=[format,sys.argv[3]]
    return info


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
        certificat_obj.dateBefore = cert.not_valid_before
        certificat_obj.dateAfter = cert.not_valid_after

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
            elif isinstance(ext.value, x509.BasicConstraints):
                if ext.value.ca:
                    certificat_obj.isCA = True

    except:
        return None
    
    certificat_obj.checkSign()
    return certificat_obj