"""
Formulaires pour l'application accounts
Conformes aux exigences de sécurité OWASP Top 10
"""

from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV3
from .models import User
import logging

logger = logging.getLogger(__name__)


class CustomUserCreationForm(UserCreationForm):
    """
    Formulaire d'inscription personnalisé avec validation sécurisée
    Anti-enumeration et validation robuste
    """
    
    email = forms.EmailField(
        label=_("Adresse email"),
        max_length=254,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'exemple@domaine.com',
            'autocomplete': 'email'
        }),
        help_text=_("Votre adresse email sera utilisée pour l'authentification.")
    )
    
    username = forms.CharField(
        label=_("Nom d'utilisateur"),
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nom d\'utilisateur',
            'autocomplete': 'username'
        }),
        help_text=_("150 caractères maximum. Lettres, chiffres et @/./+/-/_ uniquement.")
    )
    
    password1 = forms.CharField(
        label=_("Mot de passe"),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Mot de passe',
            'autocomplete': 'new-password'
        }),
        help_text=_("Votre mot de passe doit contenir au moins 12 caractères.")
    )
    
    password2 = forms.CharField(
        label=_("Confirmation du mot de passe"),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirmez votre mot de passe',
            'autocomplete': 'new-password'
        }),
        help_text=_("Entrez le même mot de passe que précédemment, pour vérification.")
    )
    
    # Honeypot pour la sécurité (bonus)
    website = forms.CharField(
        required=False,
        widget=forms.HiddenInput(),
        label=""
    )
    
    # Case à cocher CGU
    terms_accepted = forms.BooleanField(
        label=_("J'accepte les conditions générales d'utilisation"),
        required=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        error_messages={
            'required': _("Vous devez accepter les conditions générales d'utilisation.")
        }
    )
    
    # reCAPTCHA v3 pour la protection anti-bot
    captcha = ReCaptchaField(
        widget=ReCaptchaV3(
            attrs={
                'data-theme': 'light',
                'data-size': 'normal',
            }
        ),
        label=_("Vérification de sécurité"),
        help_text=_("Cette vérification nous aide à protéger contre les robots.")
    )
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2', 'terms_accepted')
    
    def clean_email(self):
        """Validation de l'email avec message générique (anti-enumeration)"""
        email = self.cleaned_data.get('email')
        if email and User.objects.filter(email=email).exists():
            # Message générique pour éviter l'enumeration
            raise ValidationError(_("Une erreur s'est produite lors de l'inscription."))
        return email
    
    def clean_username(self):
        """Validation du nom d'utilisateur avec message générique"""
        username = self.cleaned_data.get('username')
        if username and User.objects.filter(username=username).exists():
            # Message générique pour éviter l'enumeration
            raise ValidationError(_("Une erreur s'est produite lors de l'inscription."))
        return username
    
    def clean_website(self):
        """Validation du honeypot"""
        website = self.cleaned_data.get('website')
        if website:
            # Si le champ honeypot est rempli, c'est probablement un bot
            logger.warning("Tentative d'inscription détectée comme bot (honeypot rempli)")
            raise ValidationError(_("Une erreur s'est produite lors de l'inscription."))
        return website
    
    def clean(self):
        """Validation globale du formulaire"""
        cleaned_data = super().clean()
        
        # Validation des mots de passe
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        
        if password1 and password2 and password1 != password2:
            raise ValidationError(_("Les deux mots de passe ne correspondent pas."))
        
        # Validation de la complexité du mot de passe
        if password1:
            if len(password1) < 12:
                raise ValidationError(_("Le mot de passe doit contenir au moins 12 caractères."))
            
            if password1.isdigit():
                raise ValidationError(_("Le mot de passe ne peut pas être entièrement numérique."))
        
        return cleaned_data
    
    def save(self, commit=True):
        """Sauvegarde de l'utilisateur avec logging"""
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        
        if commit:
            user.save()
            logger.info(f"Nouvel utilisateur créé: {user.username} ({user.email})")
        
        return user


class CustomAuthenticationForm(AuthenticationForm):
    """
    Formulaire de connexion personnalisé avec protection anti-brute force
    Messages d'erreur non révélateurs (anti-enumeration)
    """
    
    username = forms.CharField(
        label=_("Nom d'utilisateur ou email"),
        max_length=254,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nom d\'utilisateur ou email',
            'autocomplete': 'username'
        })
    )
    
    password = forms.CharField(
        label=_("Mot de passe"),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Mot de passe',
            'autocomplete': 'current-password'
        })
    )
    
    # reCAPTCHA v3 pour la protection anti-bot (optionnel sur login)
    captcha = ReCaptchaField(
        widget=ReCaptchaV3(
            attrs={
                'data-theme': 'light',
                'data-size': 'normal',
            }
        ),
        label=_("Vérification de sécurité"),
        help_text=_("Cette vérification nous aide à protéger contre les robots."),
        required=False  # Optionnel pour ne pas bloquer les utilisateurs légitimes
    )
    
    def clean(self):
        """Validation avec messages d'erreur génériques"""
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        
        if username and password:
            # Tentative d'authentification par username ou email
            user = None
            
            # Vérifier si c'est un email
            if '@' in username:
                try:
                    user_obj = User.objects.get(email=username)
                    user = authenticate(self.request, username=user_obj.username, password=password)
                except User.DoesNotExist:
                    pass
            else:
                user = authenticate(self.request, username=username, password=password)
            
            if user is None:
                # Message d'erreur générique (anti-enumeration)
                logger.warning(f"Tentative de connexion échouée pour: {username}")
                raise ValidationError(_("Identifiants invalides."))
            
            # Vérifier si le compte est verrouillé
            if user.is_account_locked():
                logger.warning(f"Tentative de connexion sur compte verrouillé: {username}")
                raise ValidationError(_("Ce compte est temporairement verrouillé. Veuillez réessayer plus tard."))
            
            # Réinitialiser les échecs de connexion en cas de succès
            user.reset_failed_attempts()
            logger.info(f"Connexion réussie pour l'utilisateur: {user.username}")
            
            self.user_cache = user
        
        return self.cleaned_data
    
    def get_invalid_login_error(self):
        """Retourne un message d'erreur générique"""
        return ValidationError(
            _("Identifiants invalides."),
            code='invalid_login',
        )
