#
#   File: vclib.py
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
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509 
from cryptography.x509 import CertificateRevocationList
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import ocsp
from cryptography.x509 import load_der_x509_crl, load_pem_x509_crl
from datetime import datetime
from pyasn1.codec.der import decoder
from pyasn1.type.univ import ObjectIdentifier
from pyasn1.codec.der import decoder
from pyasn1.type.univ import Sequence
#from pyasn1.modules import rfc5480
from pyasn1.type import univ, namedtype
from ecdsa import VerifyingKey, curves, NIST256p, NIST384p, NIST521p, ellipticcurve, numbertheory
from ecdsa.util import sigdecode_der

import subprocess
import re
import binascii

class ECDSASignature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer())
    )

# ----------------- Class -----------------
class chain:
    def __init__(self, _certs, _forceIsValide):
        self.certs = _certs
        self.isValid = False
        self.forceIsValide = _forceIsValide

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
            "valid": str(self.isValid and not self.forceIsValide),
        }

        chain_json_str = json.dumps(chain_json, indent=4)
        return chain_json_str

class certificat:
    def __init__(self, _format, _path):
        _path = _path.replace("\\", "/")
        self.fileName = "".join(_path.split("/")[-1].split("__RNDCERTNAME__")[1:])
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

    def getId(self):
        return self.id

    def checkSignEC(self, _kpub=None):
        if _kpub==None:
            public_key=self.kpub
        else:
            public_key=_kpub
        
        
        # yQ=self.kpub.y
        # gen= courbe.generator
        curve_name=public_key.curve.name
       
        # Faites le mapping entre le nom de la courbe de 'cryptography' et les objets de courbe dans 'ecdsa'
        curve_mapping = {
            'secp192r1': curves.NIST192p,
            'secp224r1': curves.NIST224p,
            'secp256r1': curves.NIST256p,
            'secp384r1': curves.NIST384p,
            'secp521r1': curves.NIST521p,
            'secp112r1': curves.SECP112r1,
            'secp112r2': curves.SECP112r2,
            'secp128r1': curves.SECP128r1,
            'secp160r1': curves.SECP160r1,
            'secp256k1': curves.SECP256k1,
            'brainpoolP160r1': curves.BRAINPOOLP160r1,
            'brainpoolP192r1': curves.BRAINPOOLP192r1,
            'brainpoolP224r1': curves.BRAINPOOLP224r1,
            'brainpoolP256r1': curves.BRAINPOOLP256r1,
            'brainpoolP320r1': curves.BRAINPOOLP320r1,
            'brainpoolP512r1': curves.BRAINPOOLP512r1,
            'brainpoolP320r1': curves.BRAINPOOLP320r1,
        }
        ecdsa_curve = curve_mapping.get(curve_name.lower())
        if ecdsa_curve is None:
                raise ValueError(f"Unsupported curve: {curve_name}")

        g = ecdsa_curve.generator
        n= ecdsa_curve.order
        q=public_key.public_numbers()
        pub_points_ecdsa=VerifyingKey.from_public_point(
            ellipticcurve.Point(ecdsa_curve.curve, q.x, q.y),
            curve=ecdsa_curve
            )
        q2=pub_points_ecdsa.pubkey.point


        r,s=sigdecode_der(self.sign, ecdsa_curve.order)

        # hasher le TBS:
        hasher = hashes.Hash(self.signAlgo, default_backend())
        hasher.update(self.tbs)
        message_hash = hasher.finalize()
        message_hash=int.from_bytes(message_hash, byteorder='big')

        u1=(message_hash*pow(s, -1, n))%n
        u2=(r*pow(s, -1, n))%n
        p=u1*g+u2*q2
        # bigp=p%n

        if (p.x() - r) % n == 0:
            self.valid=True

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
            "file_name": str(self.fileName),
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
        return cert_json_str


# ----------------- Functions -----------------
        
def mod_inverse(x,m):
    for n in range(m):
        if (x * n) % m == 1:
            return n
            break

        elif n == m - 1:
            return "Null"
        else:
            continue

def extraire_coordonnees_xy(hex_octets):
        # Convertir la chaîne d'octets hexadécimaux en une liste d'octets
        octets = bytes.fromhex(hex_octets)

        # Sauter le premier octet (0x04 pour un point non compressé)
        octets_sans_prefixe = octets[1:]

        # Séparer la liste en deux parties égales pour x et y
        longueur = len(octets_sans_prefixe) // 2
        x = octets_sans_prefixe[:longueur]
        y = octets_sans_prefixe[longueur:]

        return x, y

# def parse_ecdsa_signature(signature_bytes):
#     # Decode ASN.1 DER encoded signature
#     signature, _ = decoder.decode(signature_bytes, asn1Spec=ECDSASignature())
#     r = int(signature[0])
#     s = int(signature[1])
#     return r, s


def initChain(certs, forceIsValid):
    return chain(certs, forceIsValid)

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
        return None
    
    return certificat_obj

def is_certificate_not_revoked(cert):
        # Charger le certificat
        crl_path="./liste_revocation.pem"
        # Charger la CRL
        with open(crl_path, 'rb') as crl_file:
            crl_data = crl_file.read()
            try:
                crl = load_pem_x509_crl(crl_data, default_backend())
            except ValueError:
            # Si le chargement en tant que PEM échoue, essayez de charger en tant que DER
                crl = load_der_x509_crl(crl_data, default_backend())
        # Vérifier si le certificat est révoqué
        revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.id)
        if revoked_cert is not None:
            return False
        else:
            return True

def is_not_revoked(cert_path,cert_child):
    not_revoked=False
    with open(cert_path, 'rb') as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    output_filename="liste_revocation.pem"
    try:
        crl_distribution_points = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        if crl_distribution_points:
            for url in crl_distribution_points:
                crl_url = url.full_name[0].value
                #crl_url = crl_distribution_points[0].full_name[0].value
                # Téléchargement de la CRL
                response = requests.get(crl_url)
                if response.status_code == 200:
                    with open(output_filename, 'wb') as output_file:
                        output_file.write(response.content)
                    if is_certificate_not_revoked(cert_child):
                        not_revoked=True
                        return not_revoked
                    else:
                        cert_child.revoked=True
        return not_revoked
    except:
        pass