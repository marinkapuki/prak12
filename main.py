from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt as pyjwt
from datetime import datetime, timedelta

app = FastAPI()

# Секретный ключ для подписи JWT
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Роли и разрешения
ROLES_PERMISSIONS = {
    "admin": {"create": True, "read": True, "update": True, "delete": True},
    "user": {"create": False, "read": True, "update": True, "delete": False},
    "guest": {"create": False, "read": True, "update": False, "delete": False},
}

# Модель для запроса на вход
class LoginRequest(BaseModel):
    username: str
    password: str

# Заглушка для аутентификации пользователя
def authenticate_user(username: str, password: str):
    # В реальном приложении здесь должна быть проверка в базе данных
    if username == "admin" and password == "admin123":
        return {"username": "admin", "role": "admin"}
    elif username == "user" and password == "user123":
        return {"username": "user", "role": "user"}
    elif username == "guest" and password == "guest123":
        return {"username": "guest", "role": "guest"}
    else:
        return None

# Генерация JWT токена
def generate_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = pyjwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Проверка JWT токена
def verify_token(token: str):
    try:
        payload = pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Зависимость для проверки роли
security = HTTPBearer()

def check_role(role: str):
    async def role_checker(token: HTTPAuthorizationCredentials = Depends(security)):
        payload = verify_token(token.credentials)
        user_role = payload.get("role", "guest")
        if user_role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Недостаточно прав для доступа к ресурсу",
            )
        return payload

    return role_checker

# Эндпоинт для входа
@app.post("/login")
async def login(request: LoginRequest):
    user = authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = generate_token({"sub": user["username"], "role": user["role"]})
    return {"access_token": access_token}

# Пример защищенных конечных точек
@app.get("/admin_resource", dependencies=[Depends(check_role("admin"))])
async def admin_resource():
    return {"message": "Доступ к ресурсу администратора разрешен"}

@app.get("/user_resource", dependencies=[Depends(check_role("user"))])
async def user_resource():
    return {"message": "Доступ к ресурсу пользователя разрешен"}

@app.get("/guest_resource", dependencies=[Depends(check_role("guest"))])
async def guest_resource():
    return {"message": "Доступ к ресурсу гостя разрешен"}

# Пример конечных точек с разрешениями
@app.post("/create_resource", dependencies=[Depends(check_role("admin"))])
async def create_resource():
    return {"message": "Ресурс успешно создан"}

@app.get("/read_resource")
async def read_resource():
    return {"message": "Ресурс успешно прочитан"}

@app.put("/update_resource", dependencies=[Depends(check_role("user"))])
async def update_resource():
    return {"message": "Ресурс успешно обновлен"}

@app.delete("/delete_resource", dependencies=[Depends(check_role("admin"))])
async def delete_resource():
    return {"message": "Ресурс успешно удален"}
