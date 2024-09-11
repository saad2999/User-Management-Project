from rest_framework.throttling import SimpleRateThrottle
from django.core.cache import cache
from django.utils import timezone
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


class PasswordThrottle(SimpleRateThrottle):
    scope = 'password_attempts'

    def get_cache_key(self, request, view):
        if hasattr(request, 'data'):
            username = request.data.get('username')
            if username:
                ident = username
            else:
                ident = self.get_ident(request)
        else:
            ident = self.get_ident(request)

        return f"password_attempt_{ident}"

    def allow_request(self, request, view):
        if request.method != 'POST':
            return True

        cache_key = self.get_cache_key(request, view)
        attempts = cache.get(cache_key, 0)

        if attempts >= 3:
            last_attempt = cache.get(f"{cache_key}_last_attempt")
            if last_attempt:
                cooldown = timezone.timedelta(minutes=5)
                if timezone.now() - last_attempt < cooldown:
                    return False

        return True

    def throttle_failure(self):
        cache_key = self.get_cache_key(self.request, self.view)
        attempts = cache.get(cache_key, 0)
        cache.set(cache_key, attempts + 1, 60 * 60 * 24)  # Store for 24 hours
        cache.set(f"{cache_key}_last_attempt", timezone.now(), 60 * 60 * 24)
        return True

class AuthThrottle(SimpleRateThrottle):
    scope = 'auth_attempts'

    def get_cache_key(self, request, view):
        if hasattr(request, 'data'):
            if 'username' in request.data:
                ident = request.data.get('username')
            else:
                ident = self.get_ident(request)
        else:
            ident = request.META.get('HTTP_AUTHORIZATION', '').split(' ')[-1]
            if not ident:
                ident = self.get_ident(request)
        
        return f"auth_attempt_{ident}"

    def allow_request(self, request, view):
        if request.method not in ['POST', 'GET', 'OPTIONS']:
            return True

        cache_key = self.get_cache_key(request, view)
        attempts = cache.get(cache_key, 0)

        if attempts >= 3:
            last_attempt = cache.get(f"{cache_key}_last_attempt")
            if last_attempt:
                cooldown = timezone.timedelta(minutes=5)
                if timezone.now() - last_attempt < cooldown:
                    return False

        return True

    def throttle_failure(self):
        cache_key = self.get_cache_key(self.request, self.view)
        attempts = cache.get(cache_key, 0)
        cache.set(cache_key, attempts + 1, 60 * 60 * 24)  # Store for 24 hours
        cache.set(f"{cache_key}_last_attempt", timezone.now(), 60 * 60 * 24)
        return True

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        throttle = AuthThrottle()
        
        if not throttle.allow_request(request, None):
            return throttle.throttled_response

        response = self.get_response(request)

        if response.status_code in [401, 403]:
            throttle.throttle_failure()

        return response