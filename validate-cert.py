#
#   File: validate-cert.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 16/02/2024
#

import sys
import vclib
import fnabil
import fjb

def main():
    arguments = sys.argv
    arguments = arguments[1:]
    certificat_obj = None
    
    # Vérifier les arguments et récupérer le format du certificat et le chemin vers le fichier:
    certificat_args = checkArgs(args)
    if certificat_args == -1:
        print("Certificat format is invalid or file is missing...")
    else:
        certificat_format = certificat_args[0]
        certificat_path = certificat_args[1]
        certificat_obj = initCertif(certificat_format, certificat_path) # Générer un objet certificat

        if certificat_obj == None:
            print("Certificat file is invalid...")
        else:
            # Vérifier la signature du certifcat:
            if not certificat_obj.checkSign():
                print("Certificat signature is invalid...")
            else:
                # Vérifier les paramètres du certificat:
                if not certificat_obj.checkParam():
                    print("Certificat parameters are invalid...")

    # Renvoyer le résultat de notre vérification au format JSON:
    displayJson(certificat_obj)

if __name__ == '__main__':
    main()