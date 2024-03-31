# Chain Certificate Checker

## Instructions pour exécuter le projet

1. Construire l'image Docker à partir du Dockerfile :

   ```bash
   docker build -t certif_cert_chain .
   ```

2. Exécuter le conteneur Docker en spécifiant le mapping du port :

   ```bash
   docker run -p 5000:5000 certif_cert_chain
   ```

Assurez-vous d'avoir Docker installé sur votre machine avant d'exécuter ces commandes.
