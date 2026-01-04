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
Rug-Panel - Главный модуль приложения
Легковесная панель управления WireGuard на FastAPI + HTMX

ОПТИМИЗАЦИИ:
- GZip compression для уменьшения размера ответов
- Timing middleware для замера производительности
- Оптимизированные response headers
"""
from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from contextlib import asynccontextmanager
from pathlib import Path
import time

from app.config import DEBUG, WG_CONFIG_PATH
from app.database import init_db
from app.auth import get_current_user, require_auth
from app.routes import auth, peers, server
from app.dependencies import templates, get_wg_manager, build_peers_with_status, get_stats


class TimingMiddleware(BaseHTTPMiddleware):
    """
    Middleware для замера времени обработки запросов.
    Добавляет заголовок X-Process-Time в ответ.
    """
    async def dispatch(self, request: Request, call_next):
        start_time = time.perf_counter()
        response = await call_next(request)
        process_time = (time.perf_counter() - start_time) * 1000  # в мс
        response.headers["X-Process-Time"] = f"{process_time:.2f}ms"
        return response


class CacheControlMiddleware(BaseHTTPMiddleware):
    """
    Middleware для оптимизации кэширования статики.
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Кэширование статических файлов
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "public, max-age=86400"  # 1 день
        
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Инициализация при старте приложения"""
    print("=" * 50)
    print("🚀 Rug-Panel запускается...")
    
    # Инициализация базы данных
    init_db()
    print("✓ База данных инициализирована")
    
    # Проверка конфига WireGuard
    if Path(WG_CONFIG_PATH).exists():
        print(f"✓ Конфигурация WireGuard найдена: {WG_CONFIG_PATH}")
    else:
        print(f"⚠ Конфигурация WireGuard не найдена: {WG_CONFIG_PATH}")
        print("  Конфигурация будет создана автоматически при первом запуске")
        print("  Или перейдите в раздел 'Сервер' для создания конфигурации")
    
    print("=" * 50)
    yield
    print("👋 Rug-Panel остановлена")


# Создание приложения
app = FastAPI(
    title="Rug-Panel",
    description="Легковесная панель управления WireGuard VPN",
    version="1.0.0",
    docs_url="/api/docs" if DEBUG else None,
    redoc_url=None,
    lifespan=lifespan
)

# ==================== Middleware ====================
# Порядок важен: первый добавленный - последний выполненный

# GZip сжатие для ответов > 500 байт (уменьшает трафик на 60-80%)
app.add_middleware(GZipMiddleware, minimum_size=500)

# Замер времени обработки
app.add_middleware(TimingMiddleware)

# Кэширование статики
app.add_middleware(CacheControlMiddleware)

# Статические файлы
static_path = Path(__file__).parent.parent / "static"
static_path.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=static_path), name="static")

# Подключение роутов
app.include_router(auth.router)
app.include_router(peers.router)
app.include_router(server.router)


# ==================== Главные страницы ====================

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Главная страница - Dashboard"""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    try:
        wg = get_wg_manager()
        interface, peers_list = wg.load_config()
        statuses = wg.get_peers_status()
        server_info = wg.get_server_info()
        
        # Используем централизованные хелперы
        peers_with_status = build_peers_with_status(peers_list, statuses)
        stats = get_stats(peers_list, statuses)
        
        return templates.TemplateResponse(request, "dashboard.html", {
            "user": user,
            "peers": peers_with_status,
            "server": server_info,
            "stats": stats,
            "config_found": True
        })
    except FileNotFoundError:
        return templates.TemplateResponse(request, "dashboard.html", {
            "user": user,
            "peers": [],
            "server": {},
            "stats": {"total": 0, "online": 0, "offline": 0},
            "config_found": False,
            "config_path": str(WG_CONFIG_PATH)
        })
    except Exception as e:
        return templates.TemplateResponse(request, "dashboard.html", {
            "user": user,
            "peers": [],
            "server": {},
            "stats": {"total": 0, "online": 0, "offline": 0},
            "config_found": False,
            "error": str(e)
        })


# ==================== API для проверки состояния ====================

@app.get("/api/health")
async def health_check():
    """Проверка состояния сервиса"""
    return {"status": "ok", "service": "WireGuard Panel"}


@app.get("/api/stats", response_class=HTMLResponse)
async def get_stats_endpoint(request: Request, user: dict = Depends(require_auth)):
    """Получение статистики (для автообновления) - возвращает HTML"""
    try:
        wg = get_wg_manager()
        interface, peers_list = wg.load_config()
        statuses = wg.get_peers_status()
        stats = get_stats(peers_list, statuses)
    except:
        stats = {"total": 0, "online": 0, "offline": 0}
    
    return templates.TemplateResponse(
        request,
        "components/stats_cards.html",
        {"stats": stats}
    )


# ==================== Exception Handlers ====================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Обработчик HTTP исключений для перенаправления на логин"""
    if exc.status_code == 401:
        # Для HTMX запросов возвращаем заголовок HX-Redirect
        if request.headers.get('HX-Request'):
            from fastapi.responses import Response
            response = Response(status_code=200)
            response.headers['HX-Redirect'] = '/login'
            return response
        # Для обычных запросов редирект
        return RedirectResponse(url="/login", status_code=302)
    
    # Для других ошибок возвращаем стандартный ответ
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )
