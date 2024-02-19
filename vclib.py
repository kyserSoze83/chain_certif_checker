#
#   File: validate-cert.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 16/02/2024
#

# ----------------- Imports -----------------
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509 


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
        self.subject = None
        self.issuer = None
        self.kpub = None
        self.keyUsage = None
        self.rca = False
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
                #padding.PSS(
                #   mgf=padding.MGF1(hashes.SHA256),
                #  salt_length=padding.PSS.MAX_LENGTH
                #),
                self.signAlgo
                #hashes.SHA256()
            )
            return True
        except:
            print("Signature invalide")


    def checkParam(self):
        return True
    
    def print(self):
        print('---------------------------------')
        print('Format: ', self.format)
        print('Path: ', self.path)
        print('ID: ', self.id)
        print('SignAlgo: ', self.signAlgo)
        print('Sign: ', self.sign)
        print('DateBefore: ', self.dateBefore)
        print('DateAfter: ', self.dateAfter)
        print('Subject: ', self.subject)
        print('Issuer: ', self.issuer)
        print('Kpub: ', self.kpub)
        print('KeyUsage: ', self.keyUsage)
        print('RCA: ', self.rca)
        print('Valid: ', self.valid)
        print('---------------------------------')


# ----------------- Functions -----------------
def checkArgs():
    if len(sys.argv)-1 !=3:
        return -1
    if sys.argv[1]!="-format":
        print(sys.argv[1])
        return -1
    if sys.argv[2]!= "DER" and sys.argv[2]!= "PEM":
        print(sys.argv[2])
        return -1
    if os.path.exists(sys.argv[3]) == False:
        print(sys.argv[3])
        return -1
    #si le format est PEM on renvoie 0, si c'est DER on renvoie 1
    if sys.argv[2]== "DER":
        format = 1
    elif sys.argv[2]== "PEM":
        format = 0
    else:
        print("Format de certificat non reconnu.")
        print(sys.argv[3])
        return -1
  
    info=[format,sys.argv[3]]
    return info


def displayJson(certificat_obj):
    if certificat_obj == None:
        pass # Afficher l'invalidité (erreur)
    else:
        pass # Afficher les données du certif


def initCertif(certificat_format, certificat_path):
    certificat_obj = certificat(certificat_format, certificat_path)

    try:
        with open(certificat_path, "rb") as f:
            cert_data = f.read()
            print("Fichier : ", cert_data)

        # Charger le certificat
        if certificat_format == 0:
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        else:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())

        # Numéro de série
        certificat_obj.id = cert.serial_number
        print("ID du certif : ",certificat_obj.id)
        print("\n")

        # Algorithme de chiffrement et fonction de hachage
        certificat_obj.signAlgo = cert.signature_hash_algorithm
        print("algo de hash du certif : ",certificat_obj.signAlgo)
        print("\n")

        # Signature
        certificat_obj.sign = cert.signature
        print("Signature : ", certificat_obj.sign)
        print("\n")

        # TBS
        certificat_obj.tbs = cert.tbs_certificate_bytes
        print("TBS : ", certificat_obj.tbs)
        print("\n")

        # Dates de validité
        certificat_obj.dateBefore = cert.not_valid_before
        certificat_obj.dateAfter = cert.not_valid_after
        print("Date avant : ", certificat_obj.dateBefore)
        print("\n")
 
        print("Date après : ",certificat_obj.dateAfter)
        print("\n")

        # Subject et Issuer
        certificat_obj.subject = cert.subject
        certificat_obj.issuer = cert.issuer
        print("subject : ", certificat_obj.subject)
        print("\n")

        print("issuer : ",certificat_obj.issuer )
        print("\n")


        # Clé publique
        certificat_obj.kpub = cert.public_key()
        print("Kpub : ", certificat_obj.kpub)

        # KeyUsage
        extensions = cert.extensions
        certificat_obj.keyUsage = None

        for ext in extensions:
            if isinstance(ext.value, x509.KeyUsage):
                certificat_obj.keyUsage = ext.value
                break

    except:
        return None
    
    certificat_obj.valid = certificat_obj.checkSign()
    print("valid :", certificat_obj.valid)
    certificat_obj.print()

    return certificat_obj