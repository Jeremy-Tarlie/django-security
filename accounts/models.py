"""
Modèles pour l'application accounts
"""

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import EmailValidator
import logging

logger = logging.getLogger(__name__)


class User(AbstractUser):
    """
    Modèle utilisateur personnalisé avec email unique
    Conforme aux exigences de sécurité A02 (Broken Authentication)
    """
    
    email = models.EmailField(
        unique=True,
        validators=[EmailValidator()],
        verbose_name="Adresse email",
        help_text="Adresse email unique pour l'authentification"
    )
    
    # Champs additionnels pour la sécurité
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    
    # Champs pour le verrouillage de compte
    is_locked = models.BooleanField(default=False)
    lockout_until = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']
    
    class Meta:
        verbose_name = "Utilisateur"
        verbose_name_plural = "Utilisateurs"
    
    def __str__(self):
        return self.username
    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip() or self.username
    
    def increment_failed_attempts(self):
        """Incrémente le compteur d'échecs de connexion"""
        self.failed_login_attempts += 1
        self.save(update_fields=['failed_login_attempts'])
        logger.warning(f"Échec de connexion pour l'utilisateur {self.username} (tentative {self.failed_login_attempts})")
    
    def reset_failed_attempts(self):
        """Réinitialise le compteur d'échecs de connexion"""
        self.failed_login_attempts = 0
        self.is_locked = False
        self.lockout_until = None
        self.save(update_fields=['failed_login_attempts', 'is_locked', 'lockout_until'])
        logger.info(f"Réinitialisation des échecs de connexion pour l'utilisateur {self.username}")
    
    def lock_account(self, duration_minutes=15):
        """Verrouille le compte pour une durée donnée"""
        from django.utils import timezone
        from datetime import timedelta
        
        self.is_locked = True
        self.lockout_until = timezone.now() + timedelta(minutes=duration_minutes)
        self.save(update_fields=['is_locked', 'lockout_until'])
        logger.warning(f"Compte verrouillé pour l'utilisateur {self.username} jusqu'à {self.lockout_until}")
    
    def is_account_locked(self):
        """Vérifie si le compte est actuellement verrouillé"""
        from django.utils import timezone
        
        if not self.is_locked:
            return False
        
        if self.lockout_until and timezone.now() > self.lockout_until:
            # Déverrouillage automatique
            self.reset_failed_attempts()
            return False
        
        return True
