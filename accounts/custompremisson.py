from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied


class IsAdminUser(permissions.BasePermission):
   
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_admin


class IsModeratorOrReadOnly(permissions.BasePermission):
   
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            if request.user.is_admin:
                return True
            
            if request.user.is_moderator:
                if request.method != 'DELETE':
                    return True
                else:
                    raise PermissionDenied("Access denied: Moderators cannot delete.")
                    
            
            if request.method in ['PUT', 'PATCH', 'DELETE']:
                 raise PermissionDenied("Access denied: User cannot delete or update.")

        
        return True
