import requests
import base64
import hashlib
import secrets

from django.conf import settings
from django.shortcuts import redirect, render
from django.http import JsonResponse, HttpResponse
from urllib.parse import quote


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

    scopes = [
        "user.info.basic",
    ]

    scope_str = quote(" ".join(scopes))

    auth_url = (
        "https://www.tiktok.com/v2/auth/authorize/"
        f"?client_key={settings.TIKTOK_CLIENT_ID}"
        "&response_type=code"
        f"&scope={scope_str}"
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
        "client_key": settings.TIKTOK_CLIENT_ID,
        "client_secret": settings.TIKTOK_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.TIKTOK_REDIRECT_URI,
        "code_verifier": code_verifier,
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    token_response = requests.post(token_url, data=data, headers=headers)
    token_data = token_response.json()

    access_token = token_data.get("access_token")

    if not access_token:
        return JsonResponse(token_data, status=400)

    request.session["tiktok_access_token"] = access_token

    user_url = "https://open.tiktokapis.com/v2/user/info/"

    user_headers = {
        "Authorization": f"Bearer {access_token}"
    }

    user_params = {
        "fields": "open_id,display_name,avatar_url"
    }

    user_response = requests.get(user_url, headers=user_headers, params=user_params)
    user_data = user_response.json()

    if "data" not in user_data:
        return JsonResponse(user_data, status=400)

    context = {
        "user": user_data["data"]["user"],
        "tokens": token_data
    }

    return render(request, "user.html", context)

def tiktok_logout(request):
    access_token = request.session.get("tiktok_access_token")

    if not access_token:
        return JsonResponse({"error": "Usuário não logado"}, status=400)

    revoke_url = "https://open.tiktokapis.com/v2/oauth/revoke/"

    data = {
        "client_key": settings.TIKTOK_CLIENT_ID,
        "client_secret": settings.TIKTOK_CLIENT_SECRET,
        "token": access_token,
    }

    response = requests.post(revoke_url, data=data)

    request.session.flush()

    if response.status_code == 200:
        return JsonResponse({"status": "Token revogado com sucesso"})
    else:
        return JsonResponse({
            "error": "Falha ao revogar",
            "detail": response.text
        }, status=400)

def tiktok_verify(request):
    return HttpResponse(
        "tiktok-developers-site-verification=cic7Ymoi0oaksmI25ufPP5k1eAC2XteY",
        content_type="text/plain"
    )


def terms(request):
    return render(request, "terms.html")


def privacy(request):
    return render(request, "privacy.html")