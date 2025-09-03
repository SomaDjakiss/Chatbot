import os
import re
import json
import datetime
from typing import Dict, List, Optional
import uuid
from pymongo import MongoClient
import streamlit as st
from langchain.prompts import PromptTemplate
from langchain.chat_models import ChatOpenAI
import pandas as pd
import streamlit as st
from functools import reduce
import operator
from pymongo import MongoClient
from bson import ObjectId
import hashlib
import bcrypt

#created_at = datetime.now()
# 🎨 Configuration de la page
st.set_page_config(page_title="🎓 Analyse Scolaire", layout="wide")

# 🔧 Configuration MongoDB
@st.cache_resource
def init_mongodb():
    try:
        # Remplacez par votre URI MongoDB (local ou Atlas)
        client = MongoClient("mongodb://mongo:JiwSbeZEXWiILqHARYsOnvkCOenDSKoY@shuttle.proxy.rlwy.net:28806")
        db = client.chatbot_scolaire
        
        # Test de connexion
        client.admin.command('ping')
        return db
    except Exception as e:
        st.error(f"Erreur de connexion à MongoDB: {e}")
        return None

# 🔐 Classe pour gérer l'authentification
class AuthManager:
    def __init__(self, db):
        self.db = db
        self.users = db.users
        
    def hash_password(self, password: str) -> str:
        """Hache le mot de passe avec bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Vérifie le mot de passe"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def create_user(self, username: str, password: str, email: str = "", role: str = "Enseignant") -> bool:
        """Crée un nouvel utilisateur"""
        # Vérifier si l'utilisateur existe déjà
        if self.users.find_one({"username": username}):
            return False
        
        # Créer l'utilisateur
        user_data = {
            "username": username,
            "password": self.hash_password(password),
            "email": email,
            "role": role,
            "created_at": datetime.datetime.now(),
            "last_login": None,
            "is_active": True
        }
        
        self.users.insert_one(user_data)
        return True
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authentifie un utilisateur"""
        user = self.users.find_one({"username": username, "is_active": True})
        
        if user and self.verify_password(password, user["password"]):
            # Mettre à jour la dernière connexion
            self.users.update_one(
                {"_id": user["_id"]},
                {"$set": {"last_login": datetime.datetime.now()}}
            )
            
            # Retourner les données utilisateur (sans le mot de passe)
            user_data = {
                "user_id": str(user["_id"]),
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "created_at": user["created_at"],
                "last_login": datetime.datetime.now()
            }
            return user_data
        
        return None
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        """Récupère un utilisateur par son ID"""
        try:
            user = self.users.find_one({"_id": ObjectId(user_id)})
            if user:
                return {
                    "user_id": str(user["_id"]),
                    "username": user["username"],
                    "email": user["email"],
                    "role": user["role"],
                    "created_at": user["created_at"],
                    "last_login": user.get("last_login")
                }
        except:
            pass
        return None

# 🗃️ Classe pour gérer la mémoire et l'historique (mise à jour)
class ChatbotMemory:
    def __init__(self, db):
        self.db = db
        self.conversations = db.conversations
        self.user_profiles = db.user_profiles
        self.user_context = db.user_context
        self.chat_sessions = db.chat_sessions
        
    def create_new_chat_session(self, user_id: str) -> str:
        """Crée une nouvelle session de chat"""
        session_data = {
            "user_id": user_id,
            "created_at": datetime.datetime.now(),
            "is_active": True,
            "title": f"Chat du {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M')}"
        }
        
        result = self.chat_sessions.insert_one(session_data)
        return str(result.inserted_id)
    
    def get_user_chat_sessions(self, user_id: str, limit: int = 20) -> List[Dict]:
        """Récupère les sessions de chat d'un utilisateur"""
        return list(self.chat_sessions.find(
            {"user_id": user_id}
        ).sort("created_at", -1).limit(limit))
    
    def get_session_conversations(self, session_id: str) -> List[Dict]:
        """Récupère les conversations d'une session"""
        return list(self.conversations.find(
            {"session_id": session_id}
        ).sort("timestamp", 1))
    
    def save_conversation(self, user_id: str, session_id: str, question: str, response: str, metadata: Dict = None):
        """Sauvegarde une conversation avec la session"""
        conversation_data = {
            "user_id": user_id,
            "session_id": session_id,
            "question": question,
            "response": response,
            "timestamp": datetime.datetime.now(),
            "metadata": metadata or {}
        }
        return self.conversations.insert_one(conversation_data)
    
    def get_conversation_history(self, user_id: str, limit: int = 50):
        """Récupère l'historique global des conversations"""
        return list(self.conversations.find(
            {"user_id": user_id}
        ).sort("timestamp", -1).limit(limit))
    
    def get_user_context(self, user_id: str):
        """Récupère le contexte utilisateur"""
        return self.user_context.find_one({"user_id": user_id}) or {}
    
    def update_user_context(self, user_id: str, context_data: Dict):
        """Met à jour le contexte utilisateur"""
        self.user_context.update_one(
            {"user_id": user_id},
            {"$set": {**context_data, "last_updated": datetime.datetime.now()}},
            upsert=True
        )
    
    def save_user_profile(self, user_id: str, profile_data: Dict):
        """Sauvegarde le profil utilisateur"""
        profile_data["last_updated"] = datetime.datetime.now()
        self.user_profiles.update_one(
            {"user_id": user_id},
            {"$set": profile_data},
            upsert=True
        )
    
    def get_user_profile(self, user_id: str):
        """Récupère le profil utilisateur"""
        return self.user_profiles.find_one({"user_id": user_id}) or {}
    
    def add_recent_entity(self, user_id: str, entity_type: str, entity_id: str, entity_name: str):
        """Ajoute une entité récemment consultée"""
        context = self.get_user_context(user_id)
        recent_key = f"recent_{entity_type}"
        
        if recent_key not in context:
            context[recent_key] = []
        
        # Supprimer l'entité si elle existe déjà
        context[recent_key] = [item for item in context[recent_key] if item['id'] != entity_id]
        
        # Ajouter en début de liste
        context[recent_key].insert(0, {
            'id': entity_id,
            'name': entity_name,
            'timestamp': datetime.datetime.now()
        })
        
        # Limiter à 20 éléments
        context[recent_key] = context[recent_key][:20]
        
        self.update_user_context(user_id, context)
    
    def update_session_title(self, session_id: str, title: str):
        """Met à jour le titre d'une session"""
        self.chat_sessions.update_one(
            {"_id": ObjectId(session_id)},
            {"$set": {"title": title}}
        )

# 🔐 Interface de connexion
def show_login_page(auth_manager):
    """Affiche la page de connexion/inscription"""
    st.title("🎓 Chatbot Scolaire - Connexion")
    
    tab1, tab2 = st.tabs(["🔑 Connexion", "👤 Inscription"])
    
    with tab1:
        st.header("Se connecter")
        
        with st.form("login_form"):
            username = st.text_input("Nom d'utilisateur")
            password = st.text_input("Mot de passe", type="password")
            submit_login = st.form_submit_button("Se connecter")
            
            if submit_login:
                if username and password:
                    user = auth_manager.authenticate_user(username, password)
                    if user:
                        st.session_state.user = user
                        st.session_state.authenticated = True
                        st.success(f"Bienvenue {user['username']} !")
                        st.rerun()
                    else:
                        st.error("Nom d'utilisateur ou mot de passe incorrect")
                else:
                    st.error("Veuillez saisir tous les champs")
    
    with tab2:
        st.header("Créer un compte")
        
        with st.form("register_form"):
            new_username = st.text_input("Nom d'utilisateur", key="reg_username")
            new_email = st.text_input("Email (optionnel)", key="reg_email")
            new_password = st.text_input("Mot de passe", type="password", key="reg_password")
            confirm_password = st.text_input("Confirmer le mot de passe", type="password", key="reg_confirm")
            new_role = st.selectbox("Rôle", ["Enseignant", "Directeur", "Inspecteur", "Autre"], key="reg_role")
            submit_register = st.form_submit_button("Créer le compte")
            
            if submit_register:
                if new_username and new_password and confirm_password:
                    if new_password != confirm_password:
                        st.error("Les mots de passe ne correspondent pas")
                    elif len(new_password) < 6:
                        st.error("Le mot de passe doit contenir au moins 6 caractères")
                    else:
                        if auth_manager.create_user(new_username, new_password, new_email, new_role):
                            st.success("Compte créé avec succès ! Vous pouvez maintenant vous connecter.")
                        else:
                            st.error("Ce nom d'utilisateur existe déjà")
                else:
                    st.error("Veuillez saisir tous les champs obligatoires")

# ✅ Chargement et cache des données
df=pd.read_csv("https://raw.githubusercontent.com/SomaDjakiss/Projet_ChatBot_Kix_Seeds/main/data_kix_seeds.csv",encoding="ISO-8859-1",sep=";")
df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
df_finale = df
# ✅ Clé API OpenAI depuis secrets
#openai_api_key = st.secrets["OPENAI_API_KEY"]
try:
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        openai_api_key = st.secrets["OPENAI_API_KEY"]
except:
    st.error("❌ Clé API OpenAI introuvable")
    st.stop()

# ✅ Modèle GPT via LangChain
llm = ChatOpenAI(
    model_name="gpt-4",
    temperature=0.7,
    openai_api_key=openai_api_key
)

# 📋 Template prompt amélioré avec mémoire
#def get_enhanced_prompt_template():
prompt_template=PromptTemplate(
    input_variables=["question", "donnees", "historique", "contexte_utilisateur"],
    template="""
Tu es un expert en analyse pédagogique, conçu pour fournir des réponses précises, structurées et basées sur des données scolaires.
Voici des données sur les performances scolaires d'élèves. Utilise ces informations pour réaliser une analyse pédagogique approfondie selon le type de demande.

## ANALYSE AU NIVEAU ÉLÈVE
Si la question concerne un élève spécifique (par nom, prénom ou ID) :

### Profil de l'élève
- Informations personnelles : nom_eleve, prenom_eleve, nom_complet_eleve, date_naissance_eleve, lieu_naissance_eleve, genre_eleve (1:masculin, 2:féminin)
- Statut: est_redoublant, statut_eleve (vérifie si PDI statut_eleve =2), eleve_a_handicap
- Contexte familial: vit_avec_parents, vit_au_domicile_parents, vit_avec_tuteur, profession_pere, profession_mere, niveau_education_pere, niveau_education_mere
### Performances académiques
- Notes et moyennes : notes_matieres, moyenne_t1, moyenne_t2, moyenne_t3, moyenne_annuelle_t1, moyenne_annuelle_t2, moyenne_annuelle_t3
- Classement : rang_t1, rang_t2, rang_t3, rang_annuel_t1, rang_annuel_t2, rang_annuel_t3
- Progression : Analyse l'évolution entre les trimestres (amélioration, détérioration, stabilité)
- Comparaison avec la classe : Positionne l'élève par rapport à moyenne_classe_t1, moyenne_classe_t2, moyenne_classe_t3
- Matières : Identifie les forces (notes ≥ 7/10) et faiblesses (notes < 5/10)
### Assiduité et comportement
- Présence : type_presence (présent, absent, retard), motif_absence, date_debut_absence, date_fin_absence
- Conduite : appreciation_conduite_t1, appreciation_conduite_t2, conduite_label_t3, sanction_disciplinaire_t1, sanction_disciplinaire_t2, sanction_t3
- Appréciations : appreciation_enseignant_t1, appreciation_enseignant_t2, appreciation_t3
###Contexte de vie et bien-être
- Logistique scolaire : distance_domicile, mode_transport, residence_eleve
- Équipement éducatif : possede_bureau, possede_livres, possede_tableaux, possede_tablette, possede_autres_materiels
- Contexte familial : menage_a_television, menage_a_radio, menage_a_internet, menage_a_electricite
- Bien-être et sécurité : dort_sous_moustiquaire, victime_violence, victime_violence_physique, victime_stigmatisation, victime_violence_sexuelle, victime_violence_emotionnelle, victime_autre_violence
### Recommandations personnalisées
- Soutien académique : Propose des stratégies d'amélioration pour les matières faibles
- Soutien socio-éducatif : Conseils adaptés aux conditions de vie et au contexte familial
- Suivi spécifique : Si élève vulnérable (PDI, handicap, victime de violence), propose un accompagnement adapté

## ANALYSE AU NIVEAU CLASSE
Si la question concerne une classe spécifique :
### Profil de la classe
- Informations générales : nom_salle_classe, effectif_classe_t1, effectif_classe_t2, effectif_t3
- Composition : Répartition par genre_eleve (1:masculin, 2:féminin)
- Statuts particuliers : Nombre d'élèves est_redoublant, PDI (statut_eleve=2), eleve_a_handicap
### Performances globales
- Moyennes de la classe : moyenne_classe_t1, moyenne_classe_t2, moyenne_classe_t3
- Dispersion : Écart entre moyenne_la_plus_elevee_t1/t2 et moyenne_la_plus_basse_t1/t2, max_moyenne_t3 et min_moyenne_t3
- Taux de réussite : Pourcentage d'élèves avec moyenne (moyenne_t1, moyenne_t2, moyenne_t3) ≥ 5/10, analyse par genre genre_eleve
- Progression : Évolution des résultats entre les trimestres
- Analyse par matière : Matières avec meilleurs et moins bons résultats
### Assiduité et comportement
- Présence : Statistiques sur type_presence (présences, absences, retards)
- Motifs d'absence : Analyse des motif_absence les plus fréquents
- Abandons : Analyse des date_abandon si existantes
### Analyse comparative
- Par genre : Compare les performances moyennes_t1/t2/t3 selon le genre_eleve
- Par statut : Compare les performances des élèves ordinaires vs PDI vs avec handicap
- Par contexte familial : Analyse l'impact des conditions familiales sur les résultats
### Recommandations pédagogiques
- Renforcement : Stratégies pour consolider les acquis dans les matières réussies
- Remédiation : Approches pour améliorer les résultats dans les matières faibles
- Accompagnement : Mesures pour soutenir les élèves en difficulté
- Dynamique de classe : Suggestions pour améliorer la cohésion et l'environnement d'apprentissage

## ANALYSE AU NIVEAU ÉCOLE
Si la question concerne une école spécifique :
### Profil de l'établissement
- Informations générales : nom_ecole, code_ecole, type_ecole, statut_ecole, milieu_ecole (urbain/rural)
- Localisation : region_ecole, province_ecole, commune_ecole, ceb_ecole, secteur_village_ecole
- Administration : nom_complet_directeur, sexe_directeur, poste_directeur, responsabilites_directeur
- Structure : Nombre total d'élèves, nombre total d'enseignants, répartition par genre
### Infrastructure et équipement
- Bâtiments : Nombre de salles de classe, état des infrastructures
- Équipements essentiels : Présence de cantine, latrines/toilettes/WC, fontaine/pompe/eau potable, électricité
- Ressources pédagogiques : Disponibilité de matériels didactiques
### Performances par classe
- Moyennes : moyenne_classe_t1, moyenne_classe_t2, moyenne_classe_t3 pour chaque nom_salle_classe
- Taux de réussite : Pourcentage d'élèves avec moyenne ≥ 5/10 par nom_salle_classe et par genre_eleve  genre 
- Progression : Évolution des résultats entre les trimestres par classe
- Analyse comparative : Classement des classes selon leurs performances
### Statistiques socio-éducatives
- Présence*: Statistiques globales sur type_presence (présences, absences, retards)
- Statuts particuliers : Proportion de PDI (statut_eleve=2), élèves avec handicap
- Bien-être : Cas signalés de violence (victime_violence, types de violences)
### Recommandations institutionnelles
- Gestion : Suggestions pour l'amélioration de la gouvernance scolaire
- Pédagogie : Stratégies pour renforcer la qualité de l'enseignement
- Équité : Mesures pour réduire les disparités de performance
- Bien-être : Actions pour améliorer l'environnement scolaire et la sécurité

## ANALYSE AU NIVEAU CEB OU COMMUNE
Si la question concerne une CEB ou une commune :
### Cartographie éducative
- Structure : Nombre d'écoles dans la CEB/commune, répartition par type_ecole et statut_ecole
- Personnel : Nombre total d'enseignants, répartition par sexe_directeur et genre des enseignants
- Population scolaire : Nombre total d'élèves, répartition par genre_eleve
- Ratios : Élèves/enseignant par école, élèves/classe
### Infrastructure territoriale
- Équipements essentiels : Proportion d'écoles avec/sans cantine, latrines, eau potable, électricité
- Accessibilité : Analyse des distance_domicile et mode_transport dominants
- Ressources : Disponibilité et distribution des matériels didactiques
### Performances comparatives
- Moyennes : Classement des écoles selon moyenne_classe_t1, moyenne_classe_t2, moyenne_classe_t3
- Taux de réussite : Comparaison du pourcentage d'élèves avec moyenne ≥ 5/10 par école
- Disparités : Identification des écarts de performance significatifs
- Facteurs explicatifs : Analyse des corrélations entre performances et facteurs contextuels
### Vulnérabilités et inclusion
- Populations spécifiques : Nombre de PDI (statut_eleve=2), élèves avec handicap par école
- Violences et protection : Cartographie des signalements de victime_violence et types
- Abandons : Analyse comparative des taux d'abandon par école
### Recommandations territoriales
- Planification : Stratégies pour une meilleure répartition des ressources
- Formation : Besoins en renforcement des capacités des enseignants
- Infrastructures : Priorités d'investissement dans les équipements essentiels
- Protection : Mesures coordonnées pour améliorer la sécurité des élèves

## DIRECTIVES GÉNÉRALES
### Format de réponse
- Structure claire : Utilise des titres, sous-titres et listes pour organiser l'information
- Visualisation : Propose des tableaux synthétiques pour les données comparatives
- Progressivité : Commence par les constats, puis analyse, puis recommandations
- Concision : Privilégie la pertinence à l'exhaustivité
### Méthodologie d'analyse
- Objectivité : Base toutes les affirmations sur les données disponibles
- Prudence : Signale clairement les données manquantes ou incomplètes
- Contextualisation : Tiens compte des spécificités locales (milieu_ecole, etc.)
- Équité : Analyse systématiquement les disparités de genre et les vulnérabilités
### Recommandations
- Pragmatisme : Propose des solutions réalistes et adaptées au contexte
- Progressivité : Distingue les actions à court, moyen et long terme
- Responsabilisation : Identifie les acteurs concernés par chaque recommandation
- Inclusivité : Veille à l'adaptation des recommandations aux besoins spécifiques

**Ne jamais inventer de données**. Si les données sont manquantes, indique-le clairement.


Question : {question}

Données :
{donnees}

Fais une réponse claire et structurée.
"""
    )

# 🔍 Fonction de détection de filtre améliorée
def extraire_filtre(question, valeurs_connues):
    question_lower = question.lower()
    for val in valeurs_connues:
        if val and str(val).lower() in question_lower:
            return val
    return None

# 🔁 Fonction principale améliorée
def get_response_from_dataframe(question, df, memory, user_id, session_id,nb_eleves=150):
    question_lower = question.lower()
    
    # 🧠 Détection des références contextuelles
    references_contextuelles = [
        "cet élève", "cette élève", "l'élève", "il", "elle", "lui", "son", "sa", "ses",
        "cette classe", "la classe", "cette école", "l'école", "même élève", "même classe", "même école"
    ]
    
    utilise_contexte = any(ref in question_lower for ref in references_contextuelles)
    
    # Extraction des filtres explicites
    from functools import reduce
    import operator
    reponses = []

    if not question:
        return "Veuillez poser une question."
    
    # Récupération du contexte utilisateur
    historique = memory.get_conversation_history(user_id, 5)
    contexte_utilisateur = memory.get_user_context(user_id)
    
    # Formatage de l'historique
    historique_text = ""
    if historique:
        historique_text = "Conversations récentes :\n"
        for conv in reversed(historique[-3:]):  # 3 dernières conversations
            historique_text += f"Q: {conv['question'][:100]}...\n"
            historique_text += f"R: {conv['response'][:150]}...\n\n"
    
    # Formatage du contexte utilisateur
    contexte_text = ""
    if contexte_utilisateur:
        recent_eleves = contexte_utilisateur.get('recent_eleves', [])
        recent_classes = contexte_utilisateur.get('recent_classes', [])
        recent_ecoles = contexte_utilisateur.get('recent_ecoles', [])
        
        if recent_eleves:
            contexte_text += f"Élèves récemment consultés: {', '.join([e['name'] for e in recent_eleves[:5]])}\n"
        if recent_classes:
            contexte_text += f"Classes récemment consultées: {', '.join([c['name'] for c in recent_classes[:5]])}\n"
        if recent_ecoles:
            contexte_text += f"Écoles récemment consultées: {', '.join([e['name'] for e in recent_ecoles[:5]])}\n"

    question_lower = question.lower()

    # Recherche des filtres possibles
    id_eleve = extraire_filtre(question_lower, df['id_eleve'].astype(str).unique())
    identifiant_unique = extraire_filtre(question_lower, df['identifiant_unique_eleve'].astype(str).unique())
    id_classe = extraire_filtre(question_lower, df['id_classe'].astype(str).unique())
    code_classe = extraire_filtre(question_lower, df['code_classe'].astype(str).unique())
    nom_classe = extraire_filtre(question_lower, df['nom_classe'].astype(str).unique())
    nom_ecole = extraire_filtre(question_lower, df['nom_ecole'].astype(str).unique())
    code_ecole = extraire_filtre(question_lower, df['code_ecole'].astype(str).unique())
    ceb = extraire_filtre(question_lower, df['ceb_ecole'].astype(str).unique())
    commune = extraire_filtre(question_lower, df['commune_ecole'].astype(str).unique())
    #ecole_id = extraire_filtre(question_lower, df['ecole_id'].astype(str).unique())

    # 🔍 Élève
    if id_eleve or identifiant_unique:
        ident = id_eleve or identifiant_unique
        ligne = df[(df['id_eleve'].astype(str) == ident) | (df['identifiant_unique_eleve'].astype(str) == ident)]
        if not ligne.empty:
            ligne = ligne.iloc[0]
            donnees_texte = "\n".join([f"{col} : {ligne[col]}" for col in df.columns if col in ligne])
            prompt = prompt_template.format(question=question, donnees=donnees_texte,historique=historique_text, contexte_utilisateur=contexte_text)
            resultat = llm.invoke(prompt)
            return resultat.content if hasattr(resultat, 'content') else resultat

    # 🔍 Classe / écoles
    filtres = []
    if nom_ecole: filtres.append(df['nom_ecole'].str.lower() == nom_ecole.lower())
    if code_ecole: filtres.append(df['code_ecole'].astype(str) == str(code_ecole))
    if ceb: filtres.append(df['ceb_ecole'].astype(str) == str(ceb))
    if commune: filtres.append(df['commune_ecole'].astype(str) == str(commune))
    if code_classe: filtres.append(df['code_classe'].astype(str) == str(code_classe))
    if nom_classe: filtres.append(df['nom_classe'].str.lower() == nom_classe.lower())
    if id_classe: filtres.append(df['id_classe'].astype(str) == str(id_classe))
    #if ecole_id: filtres.append(df['ecole_id'].astype(str) == str(ecole_id))

    if filtres:
        condition = reduce(operator.and_, filtres)
        df_filtre = df[condition]
        if df_filtre.empty:
            return "Aucune donnée trouvée avec les critères spécifiés."

        # 🎯 Analyse par classe
        if "classe" in question_lower or "classes" in question_lower:
            classes = df_filtre['nom_classe'].unique()
            for classe in classes:
                df_classe = df_filtre[df_filtre['nom_classe'] == classe]
                df_classe = df_classe.head(nb_eleves)
                resume = {col: df_classe[col].mean() for col in df_classe.columns if df_classe[col].dtype != 'object'}
                donnees_texte = f"Classe : {classe}\n" + "\n".join([f"{k} : {v:.2f}" for k, v in resume.items()])
                prompt = prompt_template.format(question=question, donnees=donnees_texte,historique=historique_text,contexte_utilisateur=contexte_text)
                resultat = llm.invoke(prompt)
                if hasattr(resultat, 'content'):
                    resultat = resultat.content
                reponses.append(f"Classe {classe} :\n{resultat}")
            return "\n\n---\n\n".join(reponses)

        # 🎯 Analyse globale de l'école
        elif "école" in question_lower or "ecole" in question_lower or "établissement" in question_lower:
            df_limite = df_filtre.head(nb_eleves)
            resume = {col: df_limite[col].mean() for col in df_limite.columns if df_limite[col].dtype != 'object'}
            donnees_texte = f"Ecole : {df_limite['nom_ecole'].iloc[0]}\n" + "\n".join([f"{k} : {v:.2f}" for k, v in resume.items()])
            prompt = prompt_template.format(question=question, donnees=donnees_texte,historique=historique_text,contexte_utilisateur=contexte_text)
            resultat = llm.invoke(prompt)
            return resultat.content if hasattr(resultat, 'content') else resultat

        # 🔄 Sinon : traitement élève par élève
        df_limite = df_filtre.head(nb_eleves)
        for _, ligne in df_limite.iterrows():
            donnees_texte = "\n".join([f"{col} : {ligne[col]}" for col in df.columns if col in ligne])
            prompt = prompt_template.format(question=question, donnees=donnees_texte,historique=historique_text,contexte_utilisateur=contexte_text)
            resultat = llm.invoke(prompt)
            if hasattr(resultat, 'content'):
                resultat = resultat.content
            reponses.append(str(resultat))
        return "\n\n---\n\n".join(reponses)
    
    # 🎯 Si aucun filtre explicite mais référence contextuelle détectée
    if not any([id_eleve, identifiant_unique, id_classe, nom_classe, nom_ecole]) and utilise_contexte:
        # Récupérer le dernier élément consulté selon le contexte
        historique = memory.get_conversation_history(user_id, 5)
        
        if historique:
            derniere_conversation = historique[0]  # Plus récente
            metadata = derniere_conversation.get('metadata', {})
            
            # Si la dernière consultation concernait un élève
            if metadata.get('type') == 'eleve' and metadata.get('eleve_id'):
                id_eleve = metadata['eleve_id']
                st.info(f"🔍 Référence contextuelle détectée : consultation de l'élève {id_eleve}")
            
            # Si la dernière consultation concernait une classe
            elif metadata.get('type') == 'classe' and metadata.get('classe'):
                nom_classe = metadata['classe']
                st.info(f"🔍 Référence contextuelle détectée : consultation de la classe {nom_classe}")
            
            # Si la dernière consultation concernait une école
            elif metadata.get('type') == 'ecole' and metadata.get('ecole'):
                nom_ecole = metadata['ecole']
                st.info(f"🔍 Référence contextuelle détectée : consultation de l'école {nom_ecole}")
    
    
    # Initialisation du template
    #prompt_template = get_enhanced_prompt_template()
    
    # 🎯 Traitement par élève
    if id_eleve or identifiant_unique:
        ident = id_eleve or identifiant_unique
        ligne = df[(df['id_eleve'].astype(str) == ident) | (df['identifiant_unique_eleve'].astype(str) == ident)]
        
        if not ligne.empty:
            ligne = ligne.iloc[0]
            
            # Enregistrer l'élève dans le contexte
            memory.add_recent_entity(user_id, 'eleves', ident, f"Élève {ident}")
            
            # Préparer les données
            donnees_texte = "\n".join([f"{col}: {ligne[col]}" for col in df.columns if col in ligne])
            
            # Générer la réponse
            #llm = init_llm()
            prompt = prompt_template.format(
                question=question,
                donnees=donnees_texte,
                historique=historique_text,
                contexte_utilisateur=contexte_text
            )
            
            resultat = llm.invoke(prompt)
            response = resultat.content if hasattr(resultat, 'content') else str(resultat)
            
            # Sauvegarder la conversation avec métadonnées enrichies
            metadata = {
                'type': 'eleve',
                'eleve_id': ident,
                'ecole': ligne.get('nom_ecole', ''),
                'classe': ligne.get('nom_classe', ''),
                'sujet': 'general'
            }
            memory.save_conversation(user_id, session_id, question, response, metadata)
            
            return response
    
    return "Aucun filtre détecté dans la question. Veuillez spécifier un élève, une classe ou une école."

# 🎨 Interface Streamlit améliorée
def main():
    # Initialisation de la session
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    
    if "user" not in st.session_state:
        st.session_state.user = None
    
    # Initialisation MongoDB
    db = init_mongodb()
    if db is None:
        st.error("Impossible de se connecter à la base de données.")
        return
    
    auth_manager = AuthManager(db)
    
    # Vérifier l'authentification
    if not st.session_state.authenticated:
        show_login_page(auth_manager)
        return
    
    # Interface principale pour utilisateur connecté
    st.title("🎓 Chatbot Scolaire - Analyse des Performances")
    st.subheader(f"👋 Bienvenue {st.session_state.user['username']} !")
    
    # Initialisation des services
    memory = ChatbotMemory(db)
    #df_finale = load_data()
    df_finale = df
    
    if df_finale.empty:
        st.error("Aucune donnée disponible.")
        return
    
    user_id = st.session_state.user['user_id']
    
    # Initialisation des sessions
    if "current_session_id" not in st.session_state:
        st.session_state.current_session_id = memory.create_new_chat_session(user_id)
    
    if "current_chat_history" not in st.session_state:
        st.session_state.current_chat_history = []
    
    # 📋 Barre latérale améliorée
    with st.sidebar:
        st.header("🗂️ Menu")
        
        # Informations utilisateur
        st.subheader("👤 Profil")
        st.write(f"**Nom:** {st.session_state.user['username']}")
        st.write(f"**Rôle:** {st.session_state.user['role']}")
        st.write(f"**Email:** {st.session_state.user.get('email', 'Non renseigné')}")
        
        # Bouton de déconnexion
        if st.button("🚪 Se déconnecter"):
            st.session_state.authenticated = False
            st.session_state.user = None
            st.rerun()
        
        st.markdown("---")
        
        # Gestion des sessions de chat
        st.subheader("💬 Sessions de Chat")
        
        # Bouton nouveau chat
        if st.button("🆕 Nouveau Chat"):
            st.session_state.current_session_id = memory.create_new_chat_session(user_id)
            st.session_state.current_chat_history = []
            st.success("Nouveau chat créé !")
            st.rerun()
        
        # Liste des sessions précédentes
        st.subheader("📜 Historique des Sessions")
        sessions = memory.get_user_chat_sessions(user_id, 10)
        
        for session in sessions:
            session_id = str(session['_id'])
            session_title = session.get('title', f"Chat {session['created_at'].strftime('%d/%m')}")
            
            # Bouton pour charger la session
            if st.button(f"📄 {session_title}", key=f"session_{session_id}"):
                st.session_state.current_session_id = session_id
                # Charger l'historique de cette session
                conversations = memory.get_session_conversations(session_id)
                st.session_state.current_chat_history = []
                for conv in conversations:
                    st.session_state.current_chat_history.append({"role": "user", "content": conv['question']})
                    st.session_state.current_chat_history.append({"role": "assistant", "content": conv['response']})
                st.rerun()
        
        st.markdown("---")
        
        # Contexte utilisateur
        st.subheader("🔍 Consultés récemment")
        context = memory.get_user_context(user_id)
        
        # Élèves récents
        recent_eleves = context.get('recent_eleves', [])
        if recent_eleves:
            st.write("**Élèves:**")
            for eleve in recent_eleves[:3]:
                st.write(f"• {eleve['name']}")
        
        # Classes récentes
        recent_classes = context.get('recent_classes', [])
        if recent_classes:
            st.write("**Classes:**")
            for classe in recent_classes[:3]:
                st.write(f"• {classe['name']}")
        
        # Écoles récentes
        recent_ecoles = context.get('recent_ecoles', [])
        if recent_ecoles:
            st.write("**Écoles:**")
            for ecole in recent_ecoles[:3]:
                st.write(f"• {ecole['name']}")
    
    # 💬 Zone de chat principale
    st.subheader(f"Session actuelle: {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M')}")
    
    # Affichage de l'historique du chat actuel
    for message in st.session_state.current_chat_history:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    # Saisie utilisateur
    user_input = st.chat_input("Pose ta question sur les performances scolaires...")
    
    if user_input:
        # Affichage de la question
        with st.chat_message("user"):
            st.write(user_input)
        
        # Génération et affichage de la réponse
        with st.chat_message("assistant"):
            with st.spinner("Analyse en cours..."):
                response = get_response_from_dataframe(
                    user_input, 
                    df_finale, 
                    memory, 
                    user_id, 
                    st.session_state.current_session_id
                )
                st.write(response)
        
        # Ajout à l'historique de session
        st.session_state.current_chat_history.append({"role": "user", "content": user_input})
        st.session_state.current_chat_history.append({"role": "assistant", "content": response})
        
        # Mettre à jour le titre de la session si c'est la première question
        if len(st.session_state.current_chat_history) == 2:
            # Utiliser les 50 premiers caractères de la question comme titre
            title = user_input[:50] + "..." if len(user_input) > 50 else user_input
            memory.update_session_title(st.session_state.current_session_id, title)
    
    # 💡 Suggestions
    with st.expander("💡 Suggestions"):
        st.write("• Analyser les performances d'un élève spécifique")
        st.write("• Comparer les résultats entre trimestres")
        st.write("• Identifier les élèves en difficulté")
        st.write("• Analyser les tendances d'une classe")
        st.write("• Consulter les statistiques d'une école")

if __name__ == "__main__":

    main()





