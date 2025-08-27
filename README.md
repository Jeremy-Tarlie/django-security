# Application Django Sécurisée - TP-01

## Description

Application Django d'authentification sécurisée conforme aux standards OWASP Top 10 et au modèle CIA (Confidentialité, Intégrité, Disponibilité). Cette application implémente un système complet d'inscription/connexion avec des protections avancées contre les attaques courantes.

## Fonctionnalités

### 🔐 Authentification Sécurisée
- **Inscription** : Formulaire avec validation robuste des mots de passe
- **Connexion** : Authentification par username ou email
- **Déconnexion** : Invalidation sécurisée de session
- **Tableau de bord** : Page protégée accessible uniquement après authentification

### 🛡️ Protections de Sécurité

#### Anti-Brute Force
- Rate limiting : 5 tentatives/15 min par IP pour la connexion
- Verrouillage automatique de compte après 5 échecs
- Déverrouillage automatique après 15 minutes

#### Anti-Enumeration
- Messages d'erreur génériques pour éviter la divulgation d'informations
- Validation sécurisée des emails et usernames

#### Protection CSRF/XSS
- Tokens CSRF obligatoires sur tous les formulaires
- Échappement automatique des données utilisateur
- Headers de sécurité configurés

#### Google reCAPTCHA v3
- Protection anti-bot invisible sur les formulaires
- Score de confiance configurable (0.85 par défaut)
- Intégration transparente pour les utilisateurs
- Validation côté serveur sécurisée

#### Chiffrement et Mots de Passe
- Hash Argon2 pour les mots de passe
- Validation robuste : minimum 12 caractères
- Politique de complexité configurée

#### Cookies et Sessions
- Cookies HttpOnly et SameSite configurés
- Sessions sécurisées avec expiration automatique
- Protection contre le vol de session

## Installation

### Prérequis
- Python 3.10+
- pip

### Étapes d'installation

1. **Cloner le projet**
```bash
git clone <repository-url>
cd secure-auth-django
```

2. **Créer un environnement virtuel**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows
```

3. **Installer les dépendances**
```bash
pip install -r requirements.txt
```

4. **Configurer l'environnement**
```bash
cp env.example .env
# Éditer .env avec vos paramètres
```

5. **Configurer reCAPTCHA (optionnel mais recommandé)**
   - Aller sur https://www.google.com/recaptcha/admin
   - Créer un nouveau site
   - Choisir reCAPTCHA v3
   - Ajouter vos domaines
   - Copier les clés dans votre fichier `.env`

6. **Appliquer les migrations**
```bash
python manage.py makemigrations
python manage.py migrate
```

7. **Créer un superutilisateur**
```bash
python manage.py createsuperuser
```

8. **Lancer le serveur**
```bash
python manage.py runserver
```

## Configuration

### Variables d'environnement (.env)

```env
# Clé secrète Django (générer une nouvelle pour la production)
SECRET_KEY=your-secret-key-here

# Configuration de base
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1

# Base de données
DATABASE_URL=sqlite:///db.sqlite3

# Sécurité
SECURE_SSL_REDIRECT=False
SECURE_HSTS_SECONDS=0
SESSION_COOKIE_SECURE=False
CSRF_COOKIE_SECURE=False

# Logs
LOG_LEVEL=INFO
LOG_FILE=auth.log

# reCAPTCHA (obligatoire pour la production)
RECAPTCHA_PUBLIC_KEY=your-recaptcha-public-key
RECAPTCHA_PRIVATE_KEY=your-recaptcha-private-key
```

### Configuration reCAPTCHA

#### Clés de test (développement uniquement)
Pour le développement, l'application utilise des clés de test par défaut :
- **Clé publique** : `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI`
- **Clé privée** : `6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe`

#### Clés de production
Pour la production, vous devez obtenir vos propres clés :
1. Aller sur https://www.google.com/recaptcha/admin
2. Créer un nouveau site
3. Choisir reCAPTCHA v3
4. Ajouter vos domaines autorisés
5. Copier les clés dans votre fichier `.env`

### Configuration de production

Pour la production, utilisez le fichier `secure_auth/settings/prod.py` :

```bash
export DJANGO_SETTINGS_MODULE=secure_auth.settings.prod
```

## Utilisation

### URLs principales
- `/` - Redirection vers la page de connexion
- `/accounts/register/` - Inscription
- `/accounts/login/` - Connexion
- `/accounts/dashboard/` - Tableau de bord (protégé)
- `/accounts/logout/` - Déconnexion
- `/admin/` - Interface d'administration

### Création d'un compte
1. Accéder à `/accounts/register/`
2. Remplir le formulaire avec :
   - Nom d'utilisateur unique
   - Email valide et unique
   - Mot de passe robuste (12+ caractères)
   - Accepter les CGU
   - Passer la vérification reCAPTCHA (automatique)
3. Valider l'inscription

### Connexion
1. Accéder à `/accounts/login/`
2. Saisir username ou email + mot de passe
3. Passer la vérification reCAPTCHA (optionnelle)
4. Accéder au tableau de bord

## Tests

### Exécuter les tests
```bash
python manage.py test accounts
```

### Tests de sécurité inclus
- ✅ Protection CSRF
- ✅ Protection XSS
- ✅ Anti-brute force
- ✅ Anti-enumeration
- ✅ Validation des mots de passe
- ✅ Rate limiting
- ✅ Google reCAPTCHA v3
- ✅ Logging des événements

## Sécurité

### Conformité OWASP Top 10

| OWASP | Protection | Implémentation |
|-------|------------|----------------|
| A01 | Contrôle d'accès | `@login_required`, vérifications d'autorisation |
| A02 | Authentification | Argon2, validation robuste, verrouillage de compte |
| A03 | Injection | ORM uniquement, validation des entrées |
| A05 | Configuration | Headers de sécurité, cookies sécurisés |
| A06 | Dépendances | Versions gelées, `requirements.txt` |
| A07 | Identification | Rate limiting, messages d'erreur génériques, reCAPTCHA |
| A09 | Logging | Logs détaillés, rotation automatique |

### Modèle CIA

- **Confidentialité** : Chiffrement des mots de passe, sessions sécurisées
- **Intégrité** : Validation des données, protection CSRF
- **Disponibilité** : Rate limiting, protection contre les attaques

### Headers de sécurité
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`

### Protection reCAPTCHA

#### reCAPTCHA v3
- **Invisible** : Aucune interaction utilisateur requise
- **Score de confiance** : 0.85 par défaut (configurable)
- **Protection** : Détection automatique des bots
- **Performance** : Impact minimal sur l'expérience utilisateur

#### Configuration avancée
```python
# Dans settings.py
RECAPTCHA_REQUIRED_SCORE = 0.85  # Score minimum requis
RECAPTCHA_USE_SSL = True         # Utiliser HTTPS
```

## Monitoring et Logs

### Fichier de logs
Les événements sont enregistrés dans `auth.log` :
- Tentatives de connexion (réussies/échouées)
- Verrouillages de compte
- Inscriptions
- Déconnexions
- Tentatives reCAPTCHA échouées

### Exemple de logs
```
INFO 2024-01-15 10:30:15 accounts.views Connexion réussie: user123 depuis l'IP 192.168.1.100
WARNING 2024-01-15 10:31:20 accounts.views Tentative de connexion échouée pour: user123
WARNING 2024-01-15 10:32:45 accounts.models Compte verrouillé pour l'utilisateur user123 jusqu'à 2024-01-15 10:47:45
INFO 2024-01-15 10:35:00 accounts.views reCAPTCHA validation réussie pour l'IP 192.168.1.100
```

## Développement

### Structure du projet
```
secure_auth/
├── accounts/           # Application d'authentification
│   ├── models.py      # Modèle User personnalisé
│   ├── forms.py       # Formulaires sécurisés avec reCAPTCHA
│   ├── views.py       # Vues avec protection
│   ├── urls.py        # URLs de l'application
│   └── tests.py       # Tests complets
├── secure_auth/       # Configuration du projet
│   ├── settings/      # Paramètres par environnement
│   │   ├── base.py    # Configuration de base
│   │   ├── dev.py     # Configuration développement
│   │   └── prod.py    # Configuration production
│   └── urls.py        # URLs principales
├── templates/         # Templates HTML
│   ├── base.html      # Template de base
│   └── accounts/      # Templates d'authentification
├── requirements.txt   # Dépendances
├── env.example        # Variables d'environnement
└── README.md         # Documentation
```

### Ajouter de nouvelles fonctionnalités
1. Créer les modèles dans `accounts/models.py`
2. Ajouter les formulaires dans `accounts/forms.py`
3. Implémenter les vues dans `accounts/views.py`
4. Créer les templates dans `templates/accounts/`
5. Ajouter les URLs dans `accounts/urls.py`
6. Écrire les tests dans `accounts/tests.py`

## Déploiement

### Production
1. Configurer les variables d'environnement de production
2. Utiliser `secure_auth.settings.prod`
3. Configurer une base de données PostgreSQL
4. Configurer un serveur web (nginx + gunicorn)
5. Activer HTTPS
6. Configurer la rotation des logs
7. **Obtenir des clés reCAPTCHA de production**

### Docker (optionnel)
```dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
```

## Support

Pour toute question ou problème :
1. Consulter les logs dans `auth.log`
2. Vérifier la configuration dans `.env`
3. Exécuter les tests : `python manage.py test`
4. Vérifier la configuration reCAPTCHA

## Licence

Ce projet est développé dans le cadre du TP-01 de sécurité informatique.
