#
#   File: validate-cert-chain.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 24/02/2024
#

import vclib
import json

finalJson = ""

def displayError(id, msg):
    global finalJson

    output_json = {
        "id": -1,
        "certId": str(id),
        "message": msg
    }

    output_json_str = json.dumps(output_json)
    finalJson += (output_json_str + ',')

def displayJson():
    global finalJson

    if finalJson[-1] == ',':
        finalJson = finalJson[:-1]
    print(finalJson)

def main():
    global finalJson

    # Vérifier les arguments et récupérer le format des certificats et les chemins vers les fichiers:
    certificats_args = vclib.checkArgs()
    certs = []
    invalid_chain = False
    
    if certificats_args == -1:
        displayError(None, "Invalid arguments")
    else:
        certificat_format = certificats_args[0]
        certificats_paths = certificats_args[1:]
        last_ca_kpub = None
        last_issuer = None

        for cert_path in certificats_paths:
            certificat_obj = vclib.initCertif(certificat_format, cert_path) # Générer un objet certificat

            if certificat_obj == None:
                displayError(cert_path, f"Certificat format is invalid...")
                invalid_chain = True
                return
            else:
                # Vérifier la signature du certificat:
                check_sign_result = False

                if certificat_obj.cypherAlgo == "RSA":
                    check_sign_result = certificat_obj.checkSignRSA(last_ca_kpub)
                elif certificat_obj.cypherAlgo == "ECDSA":
                    check_sign_result = certificat_obj.checkSignEC(last_ca_kpub)
                elif certificat_obj.cypherAlgo == "DSA":
                    displayError(certificat_obj.getId() or cert_path, f"DSA is not supported...")
                    invalid_chain = True
                    #break

                if check_sign_result:
                    # Vérifier les paramètres du certificat:
                    if not certificat_obj.checkParam():
                        displayError(certificat_obj.getId() or cert_path, f"Certificat parameters are invalid...")
                        invalid_chain = True
                        #break
                    else:
                        if last_issuer != None and last_issuer.autoSign==False:
                            if not vclib.is_not_revoked(last_issuer.path, certificat_obj): 
                                displayError(certificat_obj.getId() or cert_path, f"Certificat is revoked...")
                                invalid_chain = True
                        else:
                            if certificat_obj.isCA:
                                last_issuer = certificat_obj
                                last_ca_kpub = certificat_obj.kpub
                            certs.append(certificat_obj)
                else:
                    displayError(certificat_obj.getId() or cert_path, f"Certificat signature is invalid...")
                    invalid_chain = True
                    #break
            finalJson += (certificat_obj.displayJson() + ',')

        # if not invalid_chain:
        chain_obj = vclib.initChain(certs, invalid_chain)
        if chain_obj == None:
            displayError(None, "Chain is invalid...")
        else:
            chain_obj.checkChain()
            finalJson += (chain_obj.displayJson() + ',')

if __name__ == '__main__':
    print("[")
    main()
    displayJson()
    print("]")