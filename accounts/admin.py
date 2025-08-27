"""
Interface d'administration pour l'application accounts
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    Interface d'administration personnalisée pour le modèle User
    """
    
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_active', 'is_locked', 'failed_login_attempts', 'date_joined')
    list_filter = ('is_active', 'is_locked', 'is_staff', 'is_superuser', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Informations personnelles', {'fields': ('first_name', 'last_name', 'email')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Sécurité', {
            'fields': ('is_locked', 'lockout_until', 'failed_login_attempts'),
            'classes': ('collapse',),
        }),
        ('Dates importantes', {
            'fields': ('last_login', 'date_joined'),
            'classes': ('collapse',),
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2'),
        }),
    )
    
    readonly_fields = ('last_login', 'date_joined', 'failed_login_attempts', 'lockout_until')
    
    def get_queryset(self, request):
        """Optimisation de la requête avec select_related"""
        return super().get_queryset(request).select_related()
    
    def unlock_account(self, request, queryset):
        """Action pour déverrouiller les comptes sélectionnés"""
        updated = queryset.update(is_locked=False, failed_login_attempts=0, lockout_until=None)
        self.message_user(request, f"{updated} compte(s) déverrouillé(s) avec succès.")
    unlock_account.short_description = "Déverrouiller les comptes sélectionnés"
    
    def reset_failed_attempts(self, request, queryset):
        """Action pour réinitialiser les tentatives d'échec"""
        updated = queryset.update(failed_login_attempts=0)
        self.message_user(request, f"Tentatives d'échec réinitialisées pour {updated} compte(s).")
    reset_failed_attempts.short_description = "Réinitialiser les tentatives d'échec"
    
    actions = [unlock_account, reset_failed_attempts]
