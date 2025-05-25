import os
import httpx # Para hacer solicitudes HTTP asíncronas
from fastapi import FastAPI, Body, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv # Para cargar variables de .env en desarrollo local

# Cargar variables de entorno desde un archivo .env si existe (para desarrollo local)
# En Render, estas variables se configuran directamente en el dashboard.
load_dotenv()

app = FastAPI(
    title="WinnerPhoto Backend Auth",
    description="Servicio de backend para manejar la autenticación de Google OAuth2.",
    version="1.0.0"
)

# --- Configuración de CORS ---
# Lista de orígenes permitidos. ¡Ajusta según tus necesidades!
origins = [
    "http://localhost",        # Si usas un puerto no estándar para el frontend local
    "http://localhost:5500",    # Puerto común para Live Server de VS Code
    "http://127.0.0.1:5500",   # Alternativa a localhost
    "https://denverdesign.github.io", # TU FRONTEND EN PRODUCCIÓN (GitHub Pages)
    # Puedes añadir más orígenes si tienes otros entornos de staging o desarrollo
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,       # Orígenes permitidos
    allow_credentials=True,      # Permitir cookies (si las usaras en el futuro)
    allow_methods=["*"],         # Permitir todos los métodos (GET, POST, etc.)
    allow_headers=["*"],         # Permitir todas las cabeceras
)

# --- Configuración de Google OAuth2 (leída de variables de entorno) ---
# Estos nombres de variables de entorno deben coincidir con los que configures en Render.
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID_BACKEND")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET_BACKEND")
# Esta redirect_uri DEBE ser la misma que está registrada en tu Google Cloud Console
# para este Client ID y la que tu frontend está usando cuando se originó la solicitud del code.
# Para producción (frontend en GitHub Pages), será la URL de tu frontend.
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI_BACKEND") # ej: "https://denverdesign.github.io/winnerphoto/"

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token" # Endpoint de Google para intercambiar el código por tokens

# --- Verificación de variables de entorno al inicio ---
if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI]):
    print("ALERTA CRÍTICA DE CONFIGURACIÓN:")
    print("Una o más variables de entorno de Google no están configuradas correctamente en el backend.")
    print(f"  GOOGLE_CLIENT_ID_BACKEND: {'Configurado' if GOOGLE_CLIENT_ID else 'NO CONFIGURADO'}")
    print(f"  GOOGLE_CLIENT_SECRET_BACKEND: {'Configurado (longitud: ' + str(len(GOOGLE_CLIENT_SECRET)) + ')' if GOOGLE_CLIENT_SECRET else 'NO CONFIGURADO'}")
    print(f"  GOOGLE_REDIRECT_URI_BACKEND: {GOOGLE_REDIRECT_URI if GOOGLE_REDIRECT_URI else 'NO CONFIGURADO'}")
    # En un entorno de producción, podrías querer que la aplicación no inicie si faltan estas.
    # Para Render, asegúrate de haberlas establecido en la sección "Environment" de tu servicio.

# --- Endpoint Raíz (para verificar que el servicio está vivo) ---
@app.get("/", summary="Endpoint de Bienvenida", tags=["General"])
async def read_root():
    """
    Endpoint simple para verificar que el backend está funcionando.
    """
    return {"mensaje": "Bienvenido al backend seguro de WinnerPhoto v1.0"}

# --- Endpoint para el Callback de Google OAuth2 ---
@app.post("/auth/google", summary="Intercambia código de Google por tokens", tags=["Autenticación"])
async def google_auth_exchange(request_data: dict = Body(..., example={"code": "auth_code_del_frontend"})):
    """
    Recibe un código de autorización de Google (`authCode`) del frontend,
    lo intercambia con Google por un `access_token`, `id_token` y (si aplica)
    un `refresh_token`.
    Devuelve `access_token` e `id_token` al frontend.
    El `refresh_token` debe ser manejado y almacenado de forma segura por este backend.
    """
    auth_code = request_data.get("code")

    if not auth_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="El código de autorización ('code') es requerido en el cuerpo JSON."
        )

    if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI]):
         raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, # O 500 Internal Server Error
            detail="Error de configuración del servidor: Las credenciales de Google no están completas en el backend."
        )

    print(f"Backend: Código de autorización recibido (primeros 20 chars): {auth_code[:20]}...")

    token_request_payload = {
        "code": auth_code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
        # "access_type": "offline" # Puedes añadir esto explícitamente si quieres asegurar
                                 # la solicitud de un refresh_token, aunque a menudo se infiere.
                                 # Google solo devuelve refresh_token en la primera autorización.
    }
    
    async with httpx.AsyncClient() as client:
        try:
            print(f"Backend: Solicitando tokens a Google en: {GOOGLE_TOKEN_URL}")
            response = await client.post(GOOGLE_TOKEN_URL, data=token_request_payload)
            response.raise_for_status()  # Lanza una excepción para errores HTTP 4xx/5xx de Google
            
            tokens = response.json()
            print(f"Backend: Respuesta de tokens recibida de Google: { {k: (v[:20] + '...' if isinstance(v, str) and len(v) > 20 else v) for k, v in tokens.items()} }") # Logueo seguro de tokens

            access_token = tokens.get("access_token")
            id_token = tokens.get("id_token")
            refresh_token = tokens.get("refresh_token") # ¡ESTE ES EL IMPORTANTE PARA TI!

            if not access_token or not id_token:
                print(f"Backend Error: Respuesta incompleta de Google al solicitar token: {tokens}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                    detail="Respuesta de token incompleta de Google."
                )

            if refresh_token:
                # ¡¡¡ACCIÓN CRUCIAL!!!
                # Aquí es donde debes almacenar el refresh_token de forma SEGURA.
                # Por ejemplo, en una base de datos, encriptado, y asociado con
                # la identidad del usuario (que puedes obtener del 'sub' claim del id_token).
                print(f"Backend: ¡REFRESH TOKEN RECIBIDO! (primeros 20 chars): {refresh_token[:20]}...")
                print("TODO: Implementar almacenamiento seguro del refresh_token aquí.")
                # Ejemplo (conceptual, necesitarías una DB real):
                # user_google_id = decode_id_token(id_token).get('sub')
                # store_refresh_token_for_user(user_google_id, refresh_token)
            
            else:
                print("Backend: No se recibió un refresh_token de Google esta vez (puede ser normal si no es la primera autorización).")


            # Devolver los tokens que el frontend necesita para operar.
            # NUNCA devuelvas el refresh_token al frontend.
            return {
                "access_token": access_token,
                "id_token": id_token,
                "message": "Tokens obtenidos exitosamente desde el backend."
            }

        except httpx.HTTPStatusError as e:
            # Error al comunicarse con el servidor de Google
            error_response_text = e.response.text
            try:
                error_details_google = e.response.json() 
                error_description_google = error_details_google.get('error_description', error_details_google.get('error', error_response_text))
            except Exception:
                error_description_google = error_response_text
            
            print(f"Backend Error: Error HTTP de Google al intercambiar código: {e.response.status_code} - {error_description_google}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, # Indica que tu servidor actuó como gateway y recibió una respuesta inválida
                detail=f"Error al comunicarse con el servicio de autenticación de Google: {error_description_google}"
            )
        except Exception as e:
            # Otros errores inesperados
            print(f"Backend Error: Error inesperado durante el intercambio de código: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail=f"Error interno del servidor durante la autenticación: {str(e)}"
            )

# --- Para ejecutar localmente (si este archivo es main.py): ---
# Comenta o elimina esto antes de desplegar en algunos entornos que usan Gunicorn o un entrypoint diferente
# if __name__ == "__main__":
#     import uvicorn
#     print("Iniciando backend localmente en http://localhost:8000")
#     print(f"  GOOGLE_CLIENT_ID_BACKEND: {'OK' if GOOGLE_CLIENT_ID else 'NO CONFIGURADO'}")
#     print(f"  GOOGLE_CLIENT_SECRET_BACKEND: {'OK' if GOOGLE_CLIENT_SECRET else 'NO CONFIGURADO'}")
#     print(f"  GOOGLE_REDIRECT_URI_BACKEND: {GOOGLE_REDIRECT_URI if GOOGLE_REDIRECT_URI else 'NO CONFIGURADO'}")
#     uvicorn.run(app, host="0.0.0.0", port=8000)