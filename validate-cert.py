#
#   File: validate-cert.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 16/02/2024
#

import sys
import vclib
import json

def display_error(msg):
    output_json = {
        "id": -1,
        "message": msg
    }

    output_json_str = json.dumps(output_json)
    print(output_json_str)

def main():
    arguments = sys.argv
    arguments = arguments[1:]
    certificat_obj = None
    
    # Vérifier les arguments et récupérer le format du certificat et le chemin vers le fichier:
    certificat_args = vclib.checkArgs()
    if certificat_args == -1:
        display_error("Invalid arguments")
    else:
        certificat_format = certificat_args[0]
        certificat_path = certificat_args[1]
        certificat_obj = vclib.initCertif(certificat_format, certificat_path) # Générer un objet certificat

        if certificat_obj == None:
            display_error("Certificat format is invalid...")
        else:
            # Vérifier la signature du certifcat:
            if certificat_obj.checkSign():
                # Vérifier les paramètres du certificat:
                if not certificat_obj.checkParam():
                    certificat_obj.valid = False

            # Renvoyer le résultat de notre vérification au format JSON:
            certificat_obj.displayJson()

if __name__ == '__main__':
    main()