"""
Security configuration for SecureCloud Learn.

This module contains security-related configuration
used by the application.
"""

# Password hashing configuration
PASSWORD_HASH_METHOD = "pbkdf2:sha256"

# Minimum password length
MIN_PASSWORD_LENGTH = 8

# Maximum login attempts before temporary lockout
MAX_LOGIN_ATTEMPTS = 5

# Account lockout duration in minutes
LOCKOUT_DURATION_MINUTES = 15

# Session security settings
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

# CSRF protection will be enabled in a later step
CSRF_ENABLED = True