# internal/sast/fixtures/python/mass_negative.py
from django.http import JsonResponse
from .models import User

ALLOWED_FIELDS = {"name", "email"}

def create_user(request):
    payload = {k: request.POST[k] for k in ALLOWED_FIELDS if k in request.POST}
    user = User.objects.create(**payload)
    return JsonResponse({"id": user.id})
