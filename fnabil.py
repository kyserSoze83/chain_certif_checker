import os
from asn1crypto import pem
def est_format_der(certificat):
    # Vérifier si le certificat est au format DER
    try:
        pem_certificat = pem.unarmor(certificat)
        return pem_certificat is not None
    except ValueError:
        return False

def est_format_pem(certificat):
    # Vérifier si le certificat est au format PEM
    try:
        pem_certificat = pem.unarmor(certificat)
        return pem_certificat is not None and pem_certificat[1] == b"CERTIFICATE"
    except ValueError:
        return False
def checkArgs(tab):
    if len(tab)!=3:
        return -1
    if tab[0]!="-format":
        print(tab[0])
        return -1
    if tab[1]!= "DER" and tab[1]!= "PEM":
        print(tab[1])
        return -1
    if os.path.exists(tab[2]) == False:
        print(tab[2])
        return -1
    #si le format est PEM on renvoie 0, si c'est DER on renvoie 1
    with open("/home/nabil/documents/certif.der", "rb") as f:
        certificat = f.read()
    if est_format_der(certificat):
        format = 1
    elif est_format_pem(certificat):
        format = 0
    else:
        print("Format de certificat non reconnu.")
        return -1
  
    info=[format,tab[2]]
    return info

test=["-format","DER","/home/nabil/documents/certif.der"]
print(checkArgs(test))


