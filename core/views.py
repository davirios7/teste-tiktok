import requests
import base64
import hashlib
import secrets

from django.conf import settings
from django.shortcuts import redirect, render
from django.http import JsonResponse, HttpResponse


def home(request):
    return render(request, "home.html")


def generate_pkce():
    code_verifier = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).rstrip(b'=').decode('utf-8')

    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode('utf-8')

    return code_verifier, code_challenge


def tiktok_login(request):
    code_verifier, code_challenge = generate_pkce()

    request.session["code_verifier"] = code_verifier

    auth_url = (
        "https://www.tiktok.com/v2/auth/authorize/"
        f"?client_key={settings.TIKTOK_CLIENT_KEY}"
        "&response_type=code"
        "&scope=user.info.basic"
        f"&redirect_uri={settings.TIKTOK_REDIRECT_URI}"
        "&state=test123"
        f"&code_challenge={code_challenge}"
        "&code_challenge_method=S256"
    )

    return redirect(auth_url)


def tiktok_callback(request):
    code = request.GET.get("code")
    code_verifier = request.session.get("code_verifier")

    if not code:
        return JsonResponse({"error": "Código não recebido"}, status=400)

    token_url = "https://open.tiktokapis.com/v2/oauth/token/"

    data = {
        "client_key": settings.TIKTOK_CLIENT_KEY,
        "client_secret": settings.TIKTOK_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.TIKTOK_REDIRECT_URI,
        "code_verifier": code_verifier,
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    response = requests.post(token_url, data=data, headers=headers)
    token_data = response.json()

    return JsonResponse(token_data)


def tiktok_verify(request):
    return HttpResponse(
        "tiktok-developers-site-verification=cic7Ymoi0oaksmI25ufPP5k1eAC2XteY",
        content_type="text/plain"
    )


def terms(request):
    return render(request, "terms.html")


def privacy(request):
    return render(request, "privacy.html")