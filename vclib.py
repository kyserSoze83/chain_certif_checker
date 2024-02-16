#
#   File: validate-cert.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 16/02/2024
#
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
        self.dateBefore = None
        self.dateAfter = None
        self.subject = None
        self.issuer = None
        self.kpub = None
        self.keyUsage = None
        self.rca = False
        self.valid = False


    def checkSign(self):
        # Charger le certificat et la signature depuis des fichiers
        with open("certificat.der", "rb") as f_certificat, open("signature.bin", "rb") as f_signature:
            certificat = f_certificat.read()
            #signature = f_signature.read()
        # Charger le certificat X.509
        if(self.format=="DER"):
            certificat = load_der_x509_certificate(certificat, default_backend())
        elif (self.format=="PEM"):
            certificat = load_pem_x509_certificate(certificat, default_backend())
    
        # Récupérer l'algorithme de hachage utilisé pour la signature
        algorithme_hachage = certificat.signature_hash_algorithm
    
        # Récupérer la clé publique du certificat
        cle_publique = certificat.public_key()
        #self.kpub
    
        # Vérifier la signature
        try:
            cle_publique.verify(
                self.sign,
                certificat.signature,
                padding.PKCS1v15(),
                algorithme_hachage
            )
            return True
        except Exception as e:
            print(f"Erreur lors de la vérification de la signature : {e}")
            return False

        

    def checkParam(self):
        return True


# ----------------- Functions -----------------
def checkArgs(args):
    return True

def displayJson(certificat_obj):
    if certificat_obj == None:
        pass # Afficher l'invalidité (erreur)
    else:
        pass # Afficher les données du certif