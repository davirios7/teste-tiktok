import requests
from django.conf import settings
from django.shortcuts import redirect, render
from django.http import JsonResponse


def home(request):
    return render(request, "home.html")


def tiktok_login(request):
    auth_url = (
        "https://www.tiktok.com/v2/auth/authorize/"
        f"?client_key={settings.TIKTOK_CLIENT_KEY}"
        f"&response_type=code"
        f"&scope=user.info.basic"
        f"&redirect_uri={settings.TIKTOK_REDIRECT_URI}"
        f"&state=test123"
    )
    return redirect(auth_url)


def tiktok_callback(request):
    code = request.GET.get("code")

    token_url = "https://open.tiktokapis.com/v2/oauth/token/"
    data = {
        "client_key": settings.TIKTOK_CLIENT_KEY,
        "client_secret": settings.TIKTOK_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.TIKTOK_REDIRECT_URI,
    }

    response = requests.post(token_url, data=data)
    token_data = response.json()

    return JsonResponse(token_data)


def terms(request):
    return render(request, "terms.html")


def privacy(request):
    return render(request, "privacy.html")