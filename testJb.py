#
#   File: testJb.py
#   Author: Jean-Baptiste Relave
#   Date : 16/02/2024
#

import vclib
import fjb

def main():
    certificat_obj = fjb.initCertif(0, "./certs/educ.isen-mediterranee.fr.crt") # Générer un objet certificat

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