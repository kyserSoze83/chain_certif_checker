#
#   File: validate-cert-chain.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 24/02/2024
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
    # Vérifier les arguments et récupérer le format des certificats et les chemins vers les fichiers:
    certificats_args = vclib.checkArgs()
    certs = []
    invalid_chain = False
    
    if certificats_args == -1:
        displayError("Invalid arguments")
    else:
        certificat_format = certificats_args[0]
        certificats_paths = certificats_args[1:]
        last_ca_kpub = None

        for cert_path in certificats_paths:
            certificat_obj = vclib.initCertif(certificat_format, cert_path) # Générer un objet certificat

            if certificat_obj == None:
                displayError(f"({cert_path}) Certificat format is invalid...")
                invalid_chain = True
                break
            else:
                # Vérifier la signature du certificat:
                if certificat_obj.checkSign(last_ca_kpub):
                    # Vérifier les paramètres du certificat:
                    if not certificat_obj.checkParam():
                        displayError(f"({cert_path}) Certificat parameters are invalid...")
                        invalid_chain = True
                        break
                    else:
                        if certificat_obj.isCA:
                            last_ca_kpub = certificat_obj.kpub
                        certs.append(certificat_obj)
                else:
                    displayError(f"({cert_path}) Certificat signature is invalid...")
                    invalid_chain = True
                    break

        if not invalid_chain:
            chain_obj = vclib.initChain(certs)
            if chain_obj == None:
                displayError("Chain is invalid...")
            else:
                chain_obj.checkChain()
                chain_obj.displayJson()

if __name__ == '__main__':
    main()