from flask import Flask, render_template, send_from_directory, request, jsonify
import os
import subprocess
import secrets
import string

app = Flask(__name__, template_folder=os.path.dirname(os.path.realpath(__file__)))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/valid_cert', methods=['POST'])
def valid_cert():
    # Vérifier si un fichier a été envoyé
    if 'certificat_input' not in request.files:
        return jsonify({"id": "0", "message": "Aucun fichier n'a ete envoye."})
    
    certificat = request.files['certificat_input']
    
    # Vérifier si le nom de fichier est vide
    if certificat.filename == '':
        return jsonify({"id": "0", "message": "Nom de fichier vide."})
    
    # Enregistrer le fichier sur le serveur
    caracteres = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(caracteres) for i in range(8))

    certs_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "certs", "upload_" + random_string + certificat.filename)
    certificat.save(certs_path)
    
    # Spécifiez le chemin complet du script et le chemin complet du répertoire des certificats
    script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "validate-cert.py")
    commande = f"python {script_path} -format PEM {certs_path}"
    
    try:
        sortie = subprocess.check_output(commande, shell=True)

        if os.path.exists(certs_path):
            os.remove(certs_path)

        return sortie.decode()
    except subprocess.CalledProcessError as e:
        return jsonify({"id": "0", "message": f"Erreur lors de l'exécution du script : {e}"})

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(os.path.join(os.path.dirname(os.path.realpath(__file__))), filename)

if __name__ == '__main__':
    app.run(debug=True)
