from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
from jose import JWTError, jwt
from pydantic import BaseModel
import os

# Cargar variables de entorno
load_dotenv()

# Configuración
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# Inicializar app
app = FastAPI(
    title="Backend Seguro",
    description="Ejemplo de API con protección de datos sensibles"
)

# Simulamos una base de datos de usuario
fake_users_db = {
    "admin": {
        "username": "admin",
        "password": "pass123",  # En producción, usa hashing
    }
}

# Modelo para tokens
class Token(BaseModel):
    access_token: str
    token_type: str

# Esquema de autenticación
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Función para crear token JWT
def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# Función simple de login
@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")
    token = create_access_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}

# Proteger rutas con token
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username not in fake_users_db:
            raise HTTPException(status_code=401, detail="Usuario no válido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    return username

# Datos sensibles desde variables de entorno
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN")

# Endpoint protegido que no expone claves completas
@app.get("/datos-seguros")
def obtener_datos_seguros(usuario: str = Depends(get_current_user)):
    return {
        "mensaje": "Datos sensibles solo visibles en backend",
        "client_secret": CLIENT_SECRET[:5] + "...",  # Mostrar parcialmente
        "refresh_token": REFRESH_TOKEN[:5] + "...",
        "detalle": "Estos datos no están expuestos realmente al frontend"
    }

# Ruta pública de prueba
@app.get("/")
def home():
    return {"mensaje": "Bienvenido al backend seguro"}