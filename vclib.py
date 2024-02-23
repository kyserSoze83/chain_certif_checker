#
#   File: validate-cert.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 16/02/2024
#

# ----------------- Imports -----------------
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
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
                self.signAlgo
            )
            print("Signature RSA valide")
            return True
        except:
            print("Signature RSA invalide")
        try:
            cle_publique.verify(self.sign,
                                self.tbs,
                                ec.ECDSA(self.signAlgo))
            print("Signature ECDSA valide")
            return True
        except:
            print("Signature ECDSA invalide")
        return False 


    def checkParam(self):
        # Récupérer la date actuelle
        date_actuelle = datetime.now()
        # ici on vérifie que la date actuelle se trouve bien après la date de début et avant la date de fin
        if not (date_actuelle < self.dateAfter and date_actuelle > self.dateBefore):
            print("La date du certificat est soit expirée soit pas encore effective")
            return False
        else:
            #ici on vérifie que le sujet et l'emmeteur sont les mêmes
            if not self.issuer==self.subject:
                print("L'emmeteur et le sujet du certificat sont différents")
                return False
            else:
                #ici on vérifie les usages de la clé qui a servi a signer le certificat (la clé ne doit pas servir à signer et à chiffrer à la fois)
                if not (self.keyUsage.key_encipherment==False and self.keyUsage.data_encipherment==False and self.keyUsage.key_agreement==False and self.keyUsage.key_cert_sign==True and self.keyUsage.crl_sign==True):
                    print("Les usages de la clé sont mauvais")
                    return False
                else:
                    self.rca=True
                    self.print()
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