#
#   File: validate-cert.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 16/02/2024
#

# ----------------- Imports -----------------
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate

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
        #self.kpub

        # Vérifier la signature
        cle_publique.verify(
            self.sign,
            self.tbs,
            padding.PKCS1v15(),
            self.signAlgo
        )
        return True

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
def checkArgs(args):
    return True

def displayJson(certificat_obj):
    if certificat_obj == None:
        pass # Afficher l'invalidité (erreur)
    else:
        pass # Afficher les données du certif