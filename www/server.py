from flask import Flask, render_template, send_from_directory, request, json, jsonify
import os
import subprocess
import secrets
import string
from urllib.parse import unquote

app = Flask(__name__, template_folder=os.path.dirname(os.path.realpath(__file__)))

pythonV = "python"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/valid_cert', methods=['POST'])
def valid_cert():
    certificats_paths = []  # Liste pour stocker les chemins des fichiers

    json_data = json.loads(unquote(request.data)[5:])

    for certificat in json_data:
        # Enregistrer le fichier sur le serveur
        caracteres = string.ascii_letters + string.digits
        random_string = ''.join(secrets.choice(caracteres) for i in range(8))
    
        certs_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "certs", "upload_" + random_string + "__RNDCERTNAME__" + certificat['name'])

        with open(certs_path, "wb") as f:
            f.write(certificat['content'].encode())

        print(f"Le fichier {certs_path} a été enregistré avec succès.")
        certificats_paths.append(certs_path)  # Ajouter le chemin du fichier à la liste
    
    # Spécifiez le chemin complet du script et le chemin complet du répertoire des certificats
    script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "validate-cert-chain.py")

    certificats_paths_str = ""#.join(certificats_paths)
    for certificat in certificats_paths:
        certificats_paths_str+='"'+certificat+'" '
    print(certificats_paths_str)
    commande = f"{pythonV} {script_path} -format PEM {certificats_paths_str}"
    
    try:
        sortie = subprocess.check_output(commande, shell=True)

        for cert_path in certificats_paths:
            if os.path.exists(cert_path):
                os.remove(cert_path)

        return sortie.decode()
    except subprocess.CalledProcessError as e:
        return jsonify({"id": "0", "message": f"Erreur lors de l'exécution du script : {e}"})


@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(os.path.join(os.path.dirname(os.path.realpath(__file__))), filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
