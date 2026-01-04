# Copyright 2026 Erkin (https://erkin.top)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Система аутентификации панели управления
JWT токены в httpOnly cookies для безопасности

ОПТИМИЗАЦИИ:
- LRU кэширование верифицированных токенов
- Кэширование пользователей по токену
- Отложенное декодирование payload
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Tuple
from jose import JWTError, jwt
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import RedirectResponse
import threading
import time

from app.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from app.database import UserDB

COOKIE_NAME = "wg_panel_token"

# Кэш верифицированных токенов: {token_hash: (payload, expires_at)}
_token_cache: Dict[str, Tuple[dict, float]] = {}
_token_cache_lock = threading.Lock()
_token_cache_max_size = 1000  # Максимум токенов в кэше

# Кэш пользователей по token: {token_hash: (user_dict, cached_at)}
_user_by_token_cache: Dict[str, Tuple[dict, float]] = {}
_user_cache_ttl = 30  # 30 секунд TTL


def _get_token_hash(token: str) -> str:
    """Быстрый хэш токена для кэширования (последние 32 символа)"""
    return token[-32:] if len(token) > 32 else token


def _cleanup_expired_tokens():
    """Очистка просроченных токенов из кэша"""
    current_time = time.time()
    with _token_cache_lock:
        expired = [k for k, v in _token_cache.items() if v[1] < current_time]
        for k in expired:
            del _token_cache[k]
            if k in _user_by_token_cache:
                del _user_by_token_cache[k]


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Создание JWT токена"""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> Optional[dict]:
    """
    Проверка и декодирование JWT токена.
    Оптимизация: кэширование успешно верифицированных токенов.
    """
    if not token:
        return None
    
    token_hash = _get_token_hash(token)
    current_time = time.time()
    
    # Проверяем кэш
    with _token_cache_lock:
        if token_hash in _token_cache:
            payload, expires_at = _token_cache[token_hash]
            if expires_at > current_time:
                return payload.copy()
            else:
                # Токен истёк - удаляем из кэша
                del _token_cache[token_hash]
                if token_hash in _user_by_token_cache:
                    del _user_by_token_cache[token_hash]
                return None
    
    # Верифицируем токен
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp", 0)
        
        # Сохраняем в кэш
        with _token_cache_lock:
            # Очистка при переполнении
            if len(_token_cache) >= _token_cache_max_size:
                _cleanup_expired_tokens()
            _token_cache[token_hash] = (payload.copy(), exp)
        
        return payload
    except JWTError:
        return None


def get_current_user(request: Request) -> Optional[dict]:
    """
    Получение текущего пользователя из cookie.
    Оптимизация: кэширование user по token.
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    
    token_hash = _get_token_hash(token)
    current_time = time.time()
    
    # Проверяем кэш пользователей
    with _token_cache_lock:
        if token_hash in _user_by_token_cache:
            user, cached_at = _user_by_token_cache[token_hash]
            if (current_time - cached_at) < _user_cache_ttl:
                return user.copy()
    
    # Верифицируем токен
    payload = verify_token(token)
    if not payload:
        return None
    
    user_id = payload.get("sub")
    if not user_id:
        return None
    
    user = UserDB.get_user_by_id(int(user_id))
    
    # Сохраняем в кэш
    if user:
        with _token_cache_lock:
            _user_by_token_cache[token_hash] = (user.copy(), current_time)
    
    return user


def login_user(response: Response, user: dict) -> str:
    """Установка cookie с токеном при входе"""
    token = create_access_token(
        data={"sub": str(user["id"]), "username": user["username"]}
    )
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=False  # Установить True для HTTPS
    )
    return token


def logout_user(response: Response):
    """Удаление cookie при выходе"""
    response.delete_cookie(key=COOKIE_NAME)


def require_auth(request: Request) -> dict:
    """Декоратор/зависимость для защищённых маршрутов"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Требуется авторизация",
            headers={"Location": "/login"}
        )
    return user


def require_admin(request: Request) -> dict:
    """Требование прав администратора"""
    user = require_auth(request)
    if not user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Требуются права администратора"
        )
    return user
