#
#   File: validate-cert.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 16/02/2024
#

import vclib
import json

def displayError(msg):
    output_json = {
        "id": -1,
        "message": msg
    }

    output_json_str = json.dumps(output_json)
    print(output_json_str)

def main():
    certificat_obj = None
    
    # Vérifier les arguments et récupérer le format du certificat et le chemin vers le fichier:
    certificat_args = vclib.checkArgs()
    if certificat_args == -1:
        displayError("Invalid arguments")
    else:
        certificat_format = certificat_args[0]
        certificat_path = certificat_args[1]
        certificat_obj = vclib.initCertif(certificat_format, certificat_path) # Générer un objet certificat

        if certificat_obj == None:
            displayError("Certificat format is invalid...")
        else:
            # Vérifier la signature du certificat:
            if certificat_obj.checkSign():
                # Vérifier les paramètres du certificat:
                certificat_obj.checkParam()

            # Renvoyer le résultat de notre vérification au format JSON:
            certificat_obj.displayJson()

if __name__ == '__main__':
    main()