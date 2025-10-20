"""
Django Integration Example for DegenHF ECC Authentication

This example shows how to integrate the ECC authentication package with Django.
"""

# settings.py configuration
DJANGO_SETTINGS = """
# settings.py

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Add the ECC authentication app
    'degenhf_django',
]

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# ECC Authentication Configuration
DEGENHF_CONFIG = {
    'HASH_ITERATIONS': 100000,  # Argon2 iterations
    'TOKEN_EXPIRY': 3600,       # 1 hour in seconds
    'CACHE_SIZE': 10000,        # LRU cache size
    'CACHE_TTL': 300,           # 5 minutes cache TTL
}

# Security settings
SECRET_KEY = 'your-secret-key-here'
DEBUG = True
ALLOWED_HOSTS = []
"""

# views.py example
DJANGO_VIEWS = """
# views.py

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from degenhf_django.core import EccAuthHandler
import json

# Initialize auth handler
auth_handler = EccAuthHandler()

@csrf_exempt
@require_http_methods(["POST"])
def register_view(request):
    \"\"\"User registration endpoint\"\"\"
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return JsonResponse({'error': 'Username and password required'}, status=400)

        user_id = auth_handler.register(username, password)

        return JsonResponse({
            'status': 'success',
            'user_id': user_id,
            'message': 'User registered successfully'
        })

    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        return JsonResponse({'error': 'Internal server error'}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def login_view(request):
    \"\"\"User login endpoint\"\"\"
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return JsonResponse({'error': 'Username and password required'}, status=400)

        token = auth_handler.authenticate(username, password)

        return JsonResponse({
            'status': 'success',
            'token': token,
            'message': 'Login successful'
        })

    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=401)
    except Exception as e:
        return JsonResponse({'error': 'Internal server error'}, status=500)

@require_http_methods(["GET"])
def profile_view(request):
    \"\"\"Protected user profile endpoint\"\"\"
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authorization header required'}, status=401)

        token = auth_header.split(' ')[1]
        user_data = auth_handler.verify_token(token)

        return JsonResponse({
            'status': 'success',
            'user': {
                'id': user_data['id'],
                'username': user_data['username'],
                'created_at': user_data['created_at']
            }
        })

    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=401)
    except Exception as e:
        return JsonResponse({'error': 'Internal server error'}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def session_view(request):
    \"\"\"Create user session endpoint\"\"\"
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authorization header required'}, status=401)

        token = auth_header.split(' ')[1]
        user_data = auth_handler.verify_token(token)

        session_data = auth_handler.create_session(user_data['id'])

        return JsonResponse({
            'status': 'success',
            'session': {
                'session_id': session_data['session_id'],
                'expires_at': session_data['expires_at']
            }
        })

    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=401)
    except Exception as e:
        return JsonResponse({'error': 'Internal server error'}, status=500)
"""

# urls.py example
DJANGO_URLS = """
# urls.py

from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    # ECC Authentication endpoints
    path('api/auth/register/', views.register_view, name='register'),
    path('api/auth/login/', views.login_view, name='login'),
    path('api/auth/profile/', views.profile_view, name='profile'),
    path('api/auth/session/', views.session_view, name='session'),
]
"""

if __name__ == '__main__':
    print("Django Integration Example")
    print("=" * 50)
    print()
    print("1. Add to settings.py:")
    print(DJANGO_SETTINGS)
    print()
    print("2. Create views.py:")
    print(DJANGO_VIEWS)
    print()
    print("3. Configure urls.py:")
    print(DJANGO_URLS)
    print()
    print("4. Run migrations and start server:")
    print("   python manage.py makemigrations")
    print("   python manage.py migrate")
    print("   python manage.py runserver")