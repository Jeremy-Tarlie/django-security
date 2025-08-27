"""
Vues pour l'application accounts
Conformes aux exigences de sécurité OWASP Top 10
"""

from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.views.generic import CreateView
from django.urls import reverse_lazy
from django.http import HttpResponseForbidden
from django_ratelimit.decorators import ratelimit
from django.utils import timezone
from django.conf import settings
from .forms import CustomUserCreationForm, CustomAuthenticationForm
from .models import User
import logging

logger = logging.getLogger(__name__)


@csrf_protect
@require_http_methods(["GET", "POST"])
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@ratelimit(key='ip', rate='100/h', method='POST', block=True)
def register_view(request):
    """
    Vue d'inscription avec protection anti-brute force et validation sécurisée
    """
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Inscription réussie ! Bienvenue.")
            logger.info(f"Nouvelle inscription réussie: {user.username} depuis l'IP {request.META.get('REMOTE_ADDR')}")
            return redirect('accounts:dashboard')
        else:
            logger.warning(f"Tentative d'inscription échouée depuis l'IP {request.META.get('REMOTE_ADDR')}")
            messages.error(request, "Une erreur s'est produite lors de l'inscription.")
    else:
        form = CustomUserCreationForm()
    
    context = {
        'form': form,
        'recaptcha_public_key': settings.RECAPTCHA_PUBLIC_KEY,
    }
    return render(request, 'accounts/register.html', context)


@csrf_protect
@require_http_methods(["GET", "POST"])
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@ratelimit(key='ip', rate='20/h', method='POST', block=True)
def login_view(request):
    """
    Vue de connexion avec protection anti-brute force et messages d'erreur génériques
    """
    if request.user.is_authenticated:
        return redirect('accounts:dashboard')
    
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f"Bienvenue, {user.get_full_name()} !")
            logger.info(f"Connexion réussie: {user.username} depuis l'IP {request.META.get('REMOTE_ADDR')}")
            return redirect('accounts:dashboard')
        else:
            # Gestion des échecs de connexion avec verrouillage de compte
            username = request.POST.get('username', '')
            try:
                # Tentative de récupération de l'utilisateur
                if '@' in username:
                    user = User.objects.get(email=username)
                else:
                    user = User.objects.get(username=username)
                
                # Incrémenter les échecs de connexion
                user.increment_failed_attempts()
                
                # Verrouiller le compte après 5 échecs
                if user.failed_login_attempts >= 5:
                    user.lock_account(duration_minutes=15)
                    logger.warning(f"Compte verrouillé après 5 échecs: {user.username}")
                    messages.error(request, "Ce compte est temporairement verrouillé. Veuillez réessayer dans 15 minutes.")
                else:
                    messages.error(request, "Identifiants invalides.")
                
            except User.DoesNotExist:
                # Utilisateur inexistant - message générique
                messages.error(request, "Identifiants invalides.")
                logger.warning(f"Tentative de connexion avec utilisateur inexistant: {username}")
            
    else:
        form = CustomAuthenticationForm()
    
    context = {
        'form': form,
        'recaptcha_public_key': settings.RECAPTCHA_PUBLIC_KEY,
    }
    return render(request, 'accounts/login.html', context)


@login_required
def logout_view(request):
    """
    Vue de déconnexion avec invalidation de session
    """
    user = request.user
    logout(request)
    messages.info(request, "Vous avez été déconnecté avec succès.")
    logger.info(f"Déconnexion: {user.username} depuis l'IP {request.META.get('REMOTE_ADDR')}")
    return redirect('accounts:login')


@login_required
def dashboard_view(request):
    """
    Vue du tableau de bord protégée par authentification
    """
    user = request.user
    context = {
        'user': user,
        'last_login': user.last_login,
        'date_joined': user.date_joined,
    }
    
    logger.info(f"Accès au dashboard: {user.username}")
    return render(request, 'accounts/dashboard.html', context)


# Vues pour les tests de sécurité
def security_test_view(request):
    """
    Vue pour tester les protections de sécurité
    """
    if not request.user.is_staff:
        return HttpResponseForbidden("Accès refusé")
    
    context = {
        'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        'remote_addr': request.META.get('REMOTE_ADDR', ''),
        'x_forwarded_for': request.META.get('HTTP_X_FORWARDED_FOR', ''),
        'csrf_token': request.META.get('CSRF_COOKIE', ''),
    }
    
    return render(request, 'accounts/security_test.html', context)
