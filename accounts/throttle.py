from rest_framework.throttling import SimpleRateThrottle, BaseThrottle
from django.core.cache import cache
from django.utils import timezone
import logging
from rest_framework.exceptions import Throttled
from rest_framework.response import Response

logger = logging.getLogger(__name__)

class PasswordThrottle(SimpleRateThrottle):
    scope = 'password_attempts'
    THROTTLE_DURATION = 5 * 60  # 5 minutes in seconds

    def get_cache_key(self, request, view):
        ident = request.data.get('email') or self.get_ident(request)
        key = f"password_attempt_{ident}"
        logger.info(f"Generated cache key: {key}")
        return key

    def allow_request(self, request, view):
        if request.method != 'POST':
            logger.info("Not a POST request, allowing")
            return True

        cache_key = self.get_cache_key(request, view)
        attempts = cache.get(cache_key, 0)

        logger.info(f"Throttle check - Cache key: {cache_key}, Attempts: {attempts}")

        if attempts >= 3:  # Change this to your desired limit
            now = timezone.now()
            last_attempt = cache.get(f"{cache_key}_last_attempt")
            if last_attempt:
                time_elapsed = (now - last_attempt).total_seconds()
                if time_elapsed < self.THROTTLE_DURATION:
                    remaining_time = int(self.THROTTLE_DURATION - time_elapsed)
                    logger.warning(f"Throttled request for {cache_key}. Remaining time: {remaining_time} seconds")
                    raise Throttled(detail={
                        "message": "Too many password attempts. Please try again later.",
                        "remaining_time": remaining_time
                    })

        # Increment the attempts counter
        cache.set(cache_key, attempts + 1, 60 * 60 * 24)  # Store for 24 hours
        cache.set(f"{cache_key}_last_attempt", timezone.now(), 60 * 60 * 24)
        logger.info(f"Incremented attempts for {cache_key}. New attempts: {attempts + 1}")

        return True


class AuthThrottle(BaseThrottle):
    scope = 'auth_attempts'

    def get_cache_key(self, request, view):
        if hasattr(request, 'data'):
            ident = request.data.get('username', self.get_ident(request))
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
                    raise Throttled(detail="Too many authentication attempts. Please try again later.")

        return True

    def throttle_failure(self, request, view):
        logger.info("Throttle failure called")
        cache_key = self.get_cache_key(request, view)
        attempts = cache.get(cache_key, 0)
        cache.set(cache_key, attempts + 1, 60 * 60 * 24)  # Store for 24 hours
        cache.set(f"{cache_key}_last_attempt", timezone.now(), 60 * 60 * 24)
        return False  # Changed to False to indicate throttling


class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        throttle = AuthThrottle()

        try:
            if not throttle.allow_request(request, None):
                # If throttling happens, raise Throttled exception with a custom message
                raise Throttled(detail="Too many authentication attempts. Please try again later.")
        except Throttled as e:
            # Return a response object that your custom renderer can handle
            return Response({"errors": {"message": str(e.detail)}}, status=e.status_code)

        response = self.get_response(request)

        # Only throttle on failed authentication attempts
        if response.status_code in [401, 403]:
            throttle.throttle_failure(request, None)

        return response
