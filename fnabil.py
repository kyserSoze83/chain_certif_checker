import os
import sys
# from asn1crypto import pem
# def est_format_der(certificat):
#     # Vérifier si le certificat est au format DER
#     try:
#         pem_certificat = pem.unarmor(certificat)
#         return pem_certificat is not None
#     except ValueError:
#         return False

# def est_format_pem(certificat):
#     # Vérifier si le certificat est au format PEM
#     try:
#         pem_certificat = pem.unarmor(certificat)
#         return pem_certificat is not None and pem_certificat[1] == b"CERTIFICATE"
#     except ValueError:
#         return False
    
    
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
    with open("/home/nabil/documents/certif.der", "rb") as f:
        certificat = f.read()
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

