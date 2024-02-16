#
#   File: validate-cert.py
#   Author: Jean-Baptiste Relave & Nabil Sarhiri
#   Date : 16/02/2024
#

# ----------------- Class -----------------
class certificat:
    def __init__(self, _format):
        self.format = _format
        self.id = None
        self.signAlgo = None
        self.dateBefore = None
        self.dateAfter = None
        self.subject = None
        self.issuer = None
        self.kpub = None
        self.keyUsage = None
        self.rca = False
        self.valid = False

    def checkSign(self):
        return True

    def checkParam(self):
        return True


# ----------------- Functions -----------------
def checkArgs(args):
    return True

def displayJson(certificat_obj):
    if certificat_obj == None:
        pass # Afficher l'invalidité (erreur)
    else:
        pass # Afficher les données du certif