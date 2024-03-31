# Élements à vérifier pour dire que les paramètres du certificats sont bons

## - Date before et after pour voir si le certificat est valide en terme de date
## - Vérifier que l'issuer et le subject sont les mêmes
## - Vérifier dans les keyusages que la clé priv a servi uniquement à signer et non pas a chiffrer
## - À la fin penser à modifier la valeur de la variable rca à True
