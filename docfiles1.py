import hashlib
from cryptography.fernet import Fernet
import datetime
import os
import rsa



# Classe pour gérer les utilisateurs
class Utilisateur:
    def __init__(self, nom_utilisateur, mot_de_passe, role):
        self.nom_utilisateur = nom_utilisateur
        self.mot_de_passe = mot_de_passe
        self.role = role

    def enregistrer_informations(self):
        with open('utilisateurs.txt', 'a') as f:
            f.write(f"{self.nom_utilisateur},{self.mot_de_passe},{self.role}\n")

# Classe pour gérer les dossiers médicaux
class DossierMedical:
    def __init__(self, patient, numero, adresse, maladie):
        self.patient = patient
        self.numero = numero
        self.adresse = adresse
        self.maladie = maladie



class LogicielDossiersMedicaux:
    def __init__(self):
        self.utilisateurs = []
        self.dossiers = []
        self.audit_logs = []

    def ajouter_utilisateur(self, nom_utilisateur, mot_de_passe, role):
        utilisateur = Utilisateur(nom_utilisateur, self.hash_mot_de_passe(mot_de_passe), role)
        self.utilisateurs.append(utilisateur)
        utilisateur.enregistrer_informations()

    def authentifier_utilisateur(self, nom_utilisateur, mot_de_passe):
        with open('utilisateurs.txt', 'r') as f:
            lignes = f.readlines()
            for ligne in lignes:
                nom, mot_de_passe_stocke, role = ligne.strip().split(',')
                if nom == nom_utilisateur and self.hash_mot_de_passe(mot_de_passe) == mot_de_passe_stocke:
                    self.enregistrer_audit_log(nom, "Nouvelle connexion")
                    userConnected = Utilisateur(nom,mot_de_passe_stocke,role)
                    self.utilisateurs.append(userConnected)

                    return True
        self.enregistrer_audit_log(nom, "Tentative de connexion")            
        return False

    def enregistrer_audit_log(self, nom_utilisateur, action):
        date_heure = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log = f"Utilisateur: {nom_utilisateur}, Action: {action}, Date/Heure: {date_heure}"
        self.audit_logs.append(log)
        with open('log.txt', 'a') as f:
            f.write(log + '\n')

    def afficher_audit_logs(self, nom_utilisateur,role):
        if self.verifier_autorisation(nom_utilisateur,role , 'audit'):
            with open('log.txt', 'r') as f:
                logs = f.read()
                print(logs)
                self.enregistrer_audit_log(nom_utilisateur, "audit")

        else:
            print("Autorisation refusée.")

    def verifier_autorisation(self, nom_utilisateur,role, action):
        if role == 'admin':
            return True
        # elif utilisateur.nom_utilisateur == nom_utilisateur and utilisateur.role == 'medecin' and action == 'lecture':
        #     return True
        else:
        	nom_utilisateur = "ACCES INTERDIT "+nom_utilisateur
        	self.enregistrer_audit_log(nom_utilisateur, action)
        return False

#mot de passe stockés avec sha512
    def hash_mot_de_passe(self, mot_de_passe):
        sha512 = hashlib.sha512()
        sha512.update(mot_de_passe.encode('utf-8'))
        return sha512.hexdigest()

    def crypter_informations(self, informations):
        if not os.path.exists("publcKey.pem"):
            (publicKey, privateKey) = rsa.newkeys(2048)
            with open('publcKey.pem', 'wb') as p:
               p.write(publicKey.save_pkcs1('PEM'))
            with open('privateKey.pem', 'wb') as p:
               p.write(privateKey.save_pkcs1('PEM'))

        with open('publcKey.pem', 'rb') as p:
            publicKey = rsa.PublicKey.load_pkcs1(p.read())
        with open('privateKey.pem', 'rb') as p:
            privateKey = rsa.PrivateKey.load_pkcs1(p.read())
            informations = str(informations)
        encrypted_informations = rsa.encrypt(informations.encode(), publicKey)
        return encrypted_informations

    def decrypter_informations(self, encrypted_informations):
        with open('publcKey.pem', 'rb') as p:
            publicKey = rsa.PublicKey.load_pkcs1(p.read())
        with open('privateKey.pem', 'rb') as p:
            privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        

        print(type(encrypted_informations))
        print(encrypted_informations)
        decrypted_informations = rsa.decrypt((encrypted_informations), privateKey).decode()
        return decrypted_informations

    # # CRYPTAGE



    #  def crypter_informations(self, informations):
    #     if not os.path.exists("key_file"):
    #         key = Fernet.generate_key()
    #         print(key)
    #         with open("key_file", 'wb') as f:
    #             f.write(key)
    #     with open("key_file", 'rb') as f:
    #         key = f.read()
    #     cipher_suite = Fernet(key)
    #     encrypted_informations = cipher_suite.encrypt(informations.encode('utf-8'))

	# (publicKey, privateKey) = rsa.newkeys(2048)
	# with open('publcKey.pem', 'wb') as p:
	# 	p.write(publicKey.save_pkcs1('PEM'))
	# with open('privateKey.pem', 'wb') as p:
	# 	p.write(privateKey.save_pkcs1('PEM'))

    #     return key, encrypted_informations

    # def decrypter_informations(self, encrypted_informations):
    #     with open("key_file", 'rb') as f:
    #         key = f.read()
    #     cipher_suite = Fernet(key)
    #     decrypted_informations = cipher_suite.decrypt(str(encrypted_informations))
    #     return decrypted_informations.decode('utf-8')





    #     def generer_cles_rsa(self):
	#         # Génération d'une paire de clés RSA
	#         private_key = rsa.generate_private_key(
	#             public_exponent=65537,
	#             key_size=2048
	#         )

	#         # Obtention de la clé publique correspondante
	#         public_key = private_key.public_key()

	#         # Sérialisation et stockage de la clé publique dans un fichier
	#         with open(self.public_key_file, 'wb') as f:
	#             f.write(public_key.public_bytes(
	#                 encoding=serialization.Encoding.PEM,
	#                 format=serialization.PublicFormat.SubjectPublicKeyInfo
	#             ))

	#         # Sérialisation et stockage de la clé privée dans un fichier
	#         with open(self.private_key_file, 'wb') as f:
	#             f.write(private_key.private_bytes(
	#                 encoding=serialization.Encoding.PEM,
	#                 format=serialization.PrivateFormat.PKCS8,
	#                 encryption_algorithm=serialization.NoEncryption()
	#             ))



    def enregistrer_dossier_medical(self,informations):
        # informations = f"Nom: {self.nom}, Numéro: {self.numero}, Adresse: {self.adresse}, Maladie: {self.maladie}"
        informations_chiffrees = self.crypter_informations(informations)
        with open('patients.txt', 'a') as f:
            f.write(f"{informations_chiffrees}\n")
        with open('patients-2.txt', 'a') as f:
            f.write(f"{informations.patient, informations.numero,informations.adresse, informations.maladie}\n")


    #     def chiffrer_informations(self, informations):
	#         # Chargement de la clé publique depuis le fichier
	#         with open(self.public_key_file, 'rb') as f:
	#             public_key = serialization.load_pem_public_key(f.read())

	#         # Chiffrement des informations avec la clé publique RSA
	#         ciphertext = public_key.encrypt(
	#             informations.encode('utf-8'),
	#             padding.OAEP(
	#                 mgf=padding.MGF1(algorithm=padding.SHA256()),
	#                 algorithm=padding.SHA256(),
	#                 label=None
	#             )
	#         )

	#         return ciphertext.hex()



    #     def dechiffrer_informations(self, ciphertext):
	#         # Chargement de la clé privée depuis le fichier
	#         with open(self.private_key_file, 'rb') as f:
	#             private_key = serialization.load_pem_private_key(
	#                 f.read(),
	#                 password=None
	#             )

	#         # Déchiffrement des informations avec la clé privée RSA
	#         plaintext = private_key.decrypt(
	#             bytes.fromhex(ciphertext),
	#             padding.OAEP(
	#                 mgf=padding.MGF1(algorithm=padding.SHA256()),
	#                 algorithm=padding.SHA256(),
	#                 label=None
	#             )
	#         )

	#         return plaintext.decode('utf-8')


    # #FIN CRYPTAGE

    def menu_principal(self):
    	while True:
	        print("1. Ajouter un utilisateur")
	        print("2. Ajouter un dossier médical")
	        print("3. Afficher les dossiers médicaux")
	        print("4. Afficher les logs d'audit")
	        print("5. Quitter")

	        choix = input("Choix : ")
	        if choix == "1":
	            self.ajouter_utilisateur_menu()
	        elif choix == "2":
	            self.ajouter_dossier_medical_menu()
	        elif choix == "3":
	            self.afficher_dossiers_menu()
	        elif choix == "4":
	            self.afficher_audit_logs(self.utilisateurs[0].nom_utilisateur,self.utilisateurs[0].role)
	        elif choix == "5":
	            break
	        else:
	            print("Choix invalide.")

    def ajouter_utilisateur_menu(self):
        
        if (self.verifier_autorisation(self.utilisateurs[0].nom_utilisateur,self.utilisateurs[0].role,"ajout d'utlilisateur")):
        	print(self.utilisateurs[0].role)
	        self.enregistrer_audit_log(self.utilisateurs[0].nom_utilisateur,"ajout d'utlilisateur")
	        nom_utilisateur = input("Nom d'utilisateur : ")
	        mot_de_passe = input("Mot de passe : ")
	        role = input("Rôle (admin/medecin) : ")
	        self.ajouter_utilisateur(nom_utilisateur, mot_de_passe, role)
        else:
	        print("Autorisation refusée.")

	    
    def ajouter_dossier_medical_menu(self):
        if self.verifier_autorisation(self.utilisateurs[0].nom_utilisateur,self.utilisateurs[0].role, 'creation de dossier médical'):
            patient = input("Nom du patient : ")
            numero = input("Numéro du patient : ")
            adresse = input("Adresse du patient : ")
            maladie = input("Maladie du patient : ")

            # key, encrypted_informations = self.crypter_informations(f"Numéro: {numero}\nAdresse: {adresse}\nMaladie: {maladie}")

            dossier = DossierMedical(patient, numero, adresse, maladie)
            self.dossiers.append(dossier)
            self.enregistrer_dossier_medical((dossier))

            self.enregistrer_audit_log(nom_utilisateur, f"Création du dossier médical pour le patient {patient}")
            print("Dossier médical créé avec succès.")
        else:
            print("Autorisation refusée.")

    def afficher_dossiers_menu(self):
        # if self.verifier_autorisation(self.utilisateurs[0].nom_utilisateur,self.utilisateurs[0].role, 'creation de dossier médical'):
    	    # with open("patients.txt", "rb") as f:
    	    # 	# for line in f:
    	    # 		informations_chiffrees = f.read()#line#.strip()
    	    # 		print(555)
    	    # 		print(type(informations_chiffrees))
    	    # 		print(informations_chiffrees)
    	    # 		informations_dechiffrees = self.decrypter_informations(informations_chiffrees)
    	    # 		print("Informations du patient :")
    	    # 		print(informations_dechiffrees)
    	    # 		print("-----")
  
            with open("patients-2.txt", "r") as f:
                for line in f:
                    informations_dechiffrees = line.strip()
                    print("Informations des patients :")
                    print(informations_dechiffrees)
                    print("-----")





# Menu principal
logiciel = LogicielDossiersMedicaux()

while True:

    nom_utilisateur = input("Nom d'utilisateur : ")
    mot_de_passe = input("Mot de passe : ")

    if logiciel.authentifier_utilisateur(nom_utilisateur, mot_de_passe):
        logiciel.menu_principal()
        break
    else:
        print("Identifiants incorrects.")