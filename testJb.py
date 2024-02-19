#
#   File: testJb.py
#   Author: Jean-Baptiste Relave
#   Date : 16/02/2024
#

import vclib
import fjb

def main():
    check=vclib.checkArgs()
    print("check : ", check)
    if check==-1:
        return -1
    certificat_obj = vclib.initCertif(check[0], check[1]) # Générer un objet certificat
    print(certificat_obj)

    if certificat_obj == None:
        print("Certificat file is invalid...")
    # else:
    #     # Vérifier la signature du certifcat:
    #     if not certificat_obj.checkSign():
    #         print("Certificat signature is invalid...")
    #     else:
    #         # Vérifier les paramètres du certificat:
    #         if not certificat_obj.checkParam():
    #             print("Certificat parameters are invalid...")

if __name__ == '__main__':
    main()