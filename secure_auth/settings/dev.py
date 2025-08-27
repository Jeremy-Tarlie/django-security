"""
Configuration de développement Django
"""

from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

# Configuration de sécurité relâchée pour le développement
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# Configuration des logs pour le développement
LOGGING['handlers']['console']['level'] = 'DEBUG'
LOGGING['loggers']['django']['level'] = 'DEBUG'
LOGGING['loggers']['accounts']['level'] = 'DEBUG'

# Ignorer l'avertissement des clés de test reCAPTCHA en développement
SILENCED_SYSTEM_CHECKS = ['captcha.recaptcha_test_key_error']
