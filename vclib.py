#
#   File: validate-cert.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 16/02/2024
#

# ----------------- Imports -----------------
import sys
import json
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509 
from cryptography.x509 import ocsp
from datetime import datetime
from pyasn1.codec.der import decoder
import binascii

# ----------------- Class -----------------
class chain:
    def __init__(self, _certs):
        self.certs = _certs
        self.isValid = False

    def checkChain(self):
        # Vérifier la validité de la chaîne
        for i in range(len(self.certs)-1):
            if self.certs[i].subject != self.certs[i+1].issuer:
                return False

        self.isValid = True
        return True
    
    def displayJson(self):
        chain_json = {
            "id": 1,
            "valid": str(self.isValid),
        }

        chain_json_str = json.dumps(chain_json, indent=4)
        print(chain_json_str)

class certificat:
    def __init__(self, _format, _path):
        self.cert = None
        self.format = _format
        self.path = _path
        self.id = None
        self.signAlgo = None
        self.cypherAlgo = None
        self.sign = None
        self.tbs = None
        self.dateBefore = None
        self.dateAfter = None
        self.expired = False
        self.ocspUrls = None
        self.revoked = False
        self.subject = None
        self.issuer = None
        self.kpub = None
        self.keyUsage = None
        self.keyUsageValid = True
        self.autoSign = False
        self.isCA = False
        self.valid = False

    def checkSignEC(self, _kpub=None):
        return False

    def checkSignRSA(self, _kpub=None):
        # Récupérer la clé publique du certificat:
        if _kpub != None:
            cle_publique = _kpub
        else:
            cle_publique = self.kpub

        # Récupérer la signature:
        e = int(hex(cle_publique.public_numbers().e), 16) # Exposant
        n = int(hex(cle_publique.public_numbers().n), 16) # Modulus
        s = int(hex(int.from_bytes(self.sign, byteorder='big')), 16) # Signature

        # Déchiffrer la signature:
        decypher = pow(s, e, n)
        decypherHex = str(hex(decypher))

        # Supprimer le padding:
        while decypherHex[0] != "3":
            decypherHex = decypherHex[1:]

        try:
            # Récupérer le hash signé en décodant l'ASN.1:
            binary_data = binascii.unhexlify(decypherHex)
            decoded_data, _ = decoder.decode(binary_data)
            hash_sign = decoded_data["field-1"].prettyPrint()

            # hasher le TBS:
            hasher = hashes.Hash(self.signAlgo, default_backend())
            hasher.update(self.tbs)
            message_hash = hex(int.from_bytes(hasher.finalize(), byteorder='big'))

            # Comparer les hashs:
            if int(hash_sign, 16) == int(message_hash, 16):
                self.valid = True
                return True
            else:
                return False
        except:
            return False
        

    def checkSign(self, _kpub=None):
        # Récupérer la clé publique du certificat
        if _kpub != None:
            cle_publique = _kpub
        else:
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

    def checkRevoke(self, _issuerObj=None):
        if self.ocspUrls == None:
            return False
        if _issuerObj == None:
            return False
        
        # Construire une demande OCSP
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(self.cert, _issuerObj.cert, self.signAlgo)
        ocsp_request = builder.build()

        # Envoyer la demande OCSP au serveur OCSP
        ocsp_response = requests.post(self.ocspUrls, data=ocsp_request.public_bytes(serialization.Encoding.DER),
                                    headers={'Content-Type': 'application/ocsp-request'})

        # Vérifier la réponse OCSP
        ocsp_response = ocsp.load_der_ocsp_response(ocsp_response.content)

        if ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
            for response in ocsp_response.responses:
                print(response)
                if response == ocsp.OCSPCertStatus.GOOD:
                    return False
                elif response == ocsp.OCSPCertStatus.REVOKED:
                    return True
        else:
            return True

        return True

    def checkParam(self):
        return_value = True

        # Récupérer la date actuelle
        date_actuelle = datetime.now()

        # ici on vérifie que la date actuelle se trouve bien après la date de début et avant la date de fin
        if not (date_actuelle < self.dateAfter and date_actuelle > self.dateBefore):
            self.expired = True
            self.valid = False
            return_value = False

        #ici on vérifie que le sujet et l'emmeteur sont les mêmes
        if self.issuer == self.subject:
            self.autoSign = True
            if not self.isCA:
                self.valid = False
                return_value = False

        #ici on vérifie les usages de la clé qui a servi a signer le certificat (la clé ne doit pas servir à signer et à chiffrer à la fois)
        if self.isCA and ( self.keyUsage == None or ((self.keyUsage.key_cert_sign or self.keyUsage.crl_sign) and (self.keyUsage.data_encipherment or self.keyUsage.key_encipherment)) ):
            self.keyUsageValid = False
            self.valid = False
            return_value = False
        elif not self.isCA and ( self.keyUsage.key_cert_sign==True or self.keyUsage.crl_sign==True ):
            self.keyUsageValid = False
            self.valid = False
            return_value = False

        return return_value

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
            "id": 0,
            "format": str(self.format),
            "crt_id": str(self.id),
            "signAlgo": sign_algo_str,
            "cypherAlgo": str(self.cypherAlgo),
            "sign": sign_hex,
            "dateBefore": date_before_str,
            "dateAfter": date_after_str,
            "expired": str(self.expired),
            "revoked": str(self.revoked),
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
def initChain(certs):
    return chain(certs)

def checkArgs():
    if len(sys.argv)-1 <3:
        return -1
    if sys.argv[1]!="-format":
        return -1
    if sys.argv[2]!= "DER" and sys.argv[2]!= "PEM":
        return -1

    if sys.argv[2]== "DER":
        format = 1
    elif sys.argv[2]== "PEM":
        format = 0
    else:
        return -1
    
    info=[format]

    for arg in sys.argv[3:]:
        info.append(arg)
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

        certificat_obj.cert = cert

        # Numéro de série
        certificat_obj.id = cert.serial_number

        # Algorithme de chiffrement et fonction de hachage
        certificat_obj.signAlgo = cert.signature_hash_algorithm

        # Récupérer l'OID de l'algorithme de signature
        signature_algorithm_oid = cert.signature_algorithm_oid

        # Vérifier si c'est RSA ou ECDSA
        if "RSA" in signature_algorithm_oid._name:
            certificat_obj.cypherAlgo = "RSA"
        elif "ECDSA" in signature_algorithm_oid._name:
            certificat_obj.cypherAlgo = "ECDSA"
        else:
            certificat_obj.cypherAlgo = "DSA"

        # Signature
        certificat_obj.sign = cert.signature

        # TBS
        certificat_obj.tbs = cert.tbs_certificate_bytes

        # Dates de validité
        certificat_obj.dateBefore = cert.not_valid_before
        certificat_obj.dateAfter = cert.not_valid_after

        # Récupérer l'extension AIA du certificat s'il existe
        try:
            aia_extension = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        
            # Parcourir les descriptions d'URL AIA pour trouver l'URL OCSP
            for description in aia_extension.value:
                if description.access_method == x509.AuthorityInformationAccessOID.OCSP:
                    certificat_obj.ocspUrls = description.access_location.value
        except:
            pass

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

    except Exception as e:
        print(e)
        return None
    
    return certificat_obj