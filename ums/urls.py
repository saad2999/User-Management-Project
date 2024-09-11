from django.contrib import admin
from django.urls import path, include
from rest_framework.schemas import get_schema_view
from django.views.generic import TemplateView

urlpatterns = [
    path('api-schema/', get_schema_view(
        title="User Management System API",
        description="""This API supports CRUD operations for user management with authentication handled via JWT (JSON Web Tokens). It features three types of users: **admin** (who has full access to all functionalities), **moderator** (who can perform all actions except deletion), and **simple user** (who can access and manage their account but cannot update or delete records). Password resets are facilitated through email, which provides a token valid for 30 minutes. To protect against unauthorized access, the API will temporarily block access for 5 minutes after multiple failed login attempts or invalid JWT token usage.
""",
        version="1.0.0"
    ), name='api-schema'),
    path('admin/', admin.site.urls),
    path('api/', include('accounts.urls')),
    path(
        "swagger-ui/",
        TemplateView.as_view(
            template_name="docs.html",
            extra_context={"schema_url": "api-schema"},  # Updated this line
        ),
        name="swagger-ui",
    ),
]
