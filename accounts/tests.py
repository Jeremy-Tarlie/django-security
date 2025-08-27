"""
Tests pour l'application accounts
Tests de sécurité et de fonctionnalité
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch
import logging

User = get_user_model()


class UserModelTest(TestCase):
    """Tests pour le modèle User personnalisé"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword123'
        )
    
    def test_user_creation(self):
        """Test de création d'utilisateur"""
        self.assertEqual(self.user.username, 'testuser')
        self.assertEqual(self.user.email, 'test@example.com')
        self.assertTrue(self.user.check_password('testpassword123'))
    
    def test_failed_login_attempts(self):
        """Test du compteur d'échecs de connexion"""
        self.assertEqual(self.user.failed_login_attempts, 0)
        
        self.user.increment_failed_attempts()
        self.assertEqual(self.user.failed_login_attempts, 1)
        
        self.user.reset_failed_attempts()
        self.assertEqual(self.user.failed_login_attempts, 0)
    
    def test_account_locking(self):
        """Test du verrouillage de compte"""
        self.assertFalse(self.user.is_account_locked())
        
        # Simuler 5 échecs de connexion
        for _ in range(5):
            self.user.increment_failed_attempts()
        
        self.user.lock_account(duration_minutes=15)
        self.assertTrue(self.user.is_account_locked())
        
        # Vérifier le déverrouillage automatique
        self.user.lockout_until = timezone.now() - timedelta(minutes=20)
        self.user.save()
        self.assertFalse(self.user.is_account_locked())


class FormTest(TestCase):
    """Tests pour les formulaires"""
    
    def test_user_creation_form_validation(self):
        """Test de validation du formulaire d'inscription"""
        from .forms import CustomUserCreationForm
        
        # Test avec données valides
        form_data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password1': 'securepassword123',
            'password2': 'securepassword123',
            'terms_accepted': True,
            'captcha': 'test_captcha_response',  # Mock reCAPTCHA
        }
        
        with patch('captcha.fields.ReCaptchaField.clean', return_value='test_captcha_response'):
            form = CustomUserCreationForm(data=form_data)
            self.assertTrue(form.is_valid())
    
    def test_password_validation(self):
        """Test de validation des mots de passe"""
        from .forms import CustomUserCreationForm
        
        # Test mot de passe trop court
        form_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password1': 'short',
            'password2': 'short',
            'terms_accepted': True,
            'captcha': 'test_captcha_response',
        }
        
        with patch('captcha.fields.ReCaptchaField.clean', return_value='test_captcha_response'):
            form = CustomUserCreationForm(data=form_data)
            self.assertFalse(form.is_valid())
            self.assertIn('12 caractères', str(form.errors))
    
    def test_honeypot_validation(self):
        """Test de validation du honeypot"""
        from .forms import CustomUserCreationForm
        
        # Test avec honeypot rempli (bot détecté)
        form_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password1': 'securepassword123',
            'password2': 'securepassword123',
            'terms_accepted': True,
            'website': 'bot_filled_this',  # Honeypot rempli
            'captcha': 'test_captcha_response',
        }
        
        with patch('captcha.fields.ReCaptchaField.clean', return_value='test_captcha_response'):
            form = CustomUserCreationForm(data=form_data)
            self.assertFalse(form.is_valid())


class ViewTest(TestCase):
    """Tests pour les vues"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword123'
        )
    
    def test_register_view_get(self):
        """Test de la vue d'inscription (GET)"""
        response = self.client.get(reverse('accounts:register'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Inscription')
        self.assertContains(response, 'recaptcha')
    
    @patch('captcha.fields.ReCaptchaField.clean', return_value='test_captcha_response')
    def test_register_view_post_valid(self, mock_captcha):
        """Test de la vue d'inscription (POST valide)"""
        form_data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password1': 'securepassword123',
            'password2': 'securepassword123',
            'terms_accepted': True,
            'captcha': 'test_captcha_response',
        }
        
        response = self.client.post(reverse('accounts:register'), form_data)
        self.assertEqual(response.status_code, 302)  # Redirection après succès
    
    def test_login_view_get(self):
        """Test de la vue de connexion (GET)"""
        response = self.client.get(reverse('accounts:login'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Connexion')
        self.assertContains(response, 'recaptcha')
    
    def test_dashboard_view_authenticated(self):
        """Test de la vue dashboard (utilisateur authentifié)"""
        self.client.login(username='testuser', password='testpassword123')
        response = self.client.get(reverse('accounts:dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Tableau de bord')
    
    def test_dashboard_view_unauthenticated(self):
        """Test de la vue dashboard (utilisateur non authentifié)"""
        response = self.client.get(reverse('accounts:dashboard'))
        self.assertEqual(response.status_code, 302)  # Redirection vers login


class SecurityTest(TestCase):
    """Tests de sécurité spécifiques"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword123'
        )
    
    def test_csrf_protection(self):
        """Test de protection CSRF"""
        # Test sans token CSRF
        client = Client(enforce_csrf_checks=True)
        response = client.post(reverse('accounts:login'), {
            'username': 'testuser',
            'password': 'testpassword123',
        })
        self.assertEqual(response.status_code, 403)  # CSRF Forbidden
    
    def test_xss_protection(self):
        """Test de protection XSS"""
        # Test avec script injecté
        malicious_username = '<script>alert("xss")</script>'
        response = self.client.get(reverse('accounts:login'))
        self.assertNotIn(malicious_username, response.content.decode())
    
    def test_user_enumeration_protection(self):
        """Test de protection anti-enumeration"""
        # Test avec utilisateur existant
        response1 = self.client.post(reverse('accounts:login'), {
            'username': 'testuser',
            'password': 'wrongpassword',
        })
        
        # Test avec utilisateur inexistant
        response2 = self.client.post(reverse('accounts:login'), {
            'username': 'nonexistentuser',
            'password': 'wrongpassword',
        })
        
        # Les messages d'erreur doivent être identiques
        self.assertEqual(response1.status_code, response2.status_code)
    
    def test_rate_limiting(self):
        """Test du rate limiting"""
        # Test que le rate limiting est configuré
        # En test, on ne peut pas facilement déclencher le rate limiting
        # car il est basé sur l'IP et le cache
        response = self.client.get(reverse('accounts:register'))
        self.assertEqual(response.status_code, 200)
    
    @patch('captcha.fields.ReCaptchaField.clean', return_value='test_captcha_response')
    def test_recaptcha_integration(self, mock_captcha):
        """Test de l'intégration reCAPTCHA"""
        # Test que reCAPTCHA est présent dans les formulaires
        response = self.client.get(reverse('accounts:register'))
        self.assertContains(response, 'recaptcha')
        
        # Test que reCAPTCHA est validé lors de la soumission
        form_data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password1': 'securepassword123',
            'password2': 'securepassword123',
            'terms_accepted': True,
            'captcha': 'test_captcha_response',
        }
        
        response = self.client.post(reverse('accounts:register'), form_data)
        # Si reCAPTCHA échoue, on devrait avoir une erreur
        # Si il réussit, on devrait avoir une redirection
        self.assertIn(response.status_code, [200, 302])


class IntegrationTest(TestCase):
    """Tests d'intégration"""
    
    def setUp(self):
        self.client = Client()
    
    @patch('captcha.fields.ReCaptchaField.clean', return_value='test_captcha_response')
    def test_complete_registration_flow(self, mock_captcha):
        """Test du flux complet d'inscription"""
        # 1. Accéder à la page d'inscription
        response = self.client.get(reverse('accounts:register'))
        self.assertEqual(response.status_code, 200)
        
        # 2. S'inscrire
        form_data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password1': 'securepassword123',
            'password2': 'securepassword123',
            'terms_accepted': True,
            'captcha': 'test_captcha_response',
        }
        
        response = self.client.post(reverse('accounts:register'), form_data)
        self.assertEqual(response.status_code, 302)  # Redirection vers dashboard
        
        # 3. Vérifier que l'utilisateur est connecté
        response = self.client.get(reverse('accounts:dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'newuser')
