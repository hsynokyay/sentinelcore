# internal/sast/fixtures/python/mass_positive.py
from django.http import JsonResponse
from .models import User

def create_user(request):
    user = User.objects.create(**request.POST)
    return JsonResponse({"id": user.id})
