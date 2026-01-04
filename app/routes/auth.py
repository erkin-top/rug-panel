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
Роуты авторизации панели управления
"""
from fastapi import APIRouter, Request, Response, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth import (
    get_current_user, login_user, logout_user, 
    require_auth, require_admin
)
from app.database import UserDB, verify_password
from app.dependencies import templates, alert_response, users_list_response

router = APIRouter(tags=["auth"])


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Страница входа"""
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/", status_code=302)
    
    return templates.TemplateResponse(request, "login.html", {
        "error": None
    })


@router.post("/login")
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    """Обработка входа"""
    user = UserDB.authenticate(username, password)
    
    if not user:
        return templates.TemplateResponse(request, "login.html", {
            "error": "Неверное имя пользователя или пароль"
        }, status_code=401)
    
    # Создаём редирект с установкой cookie
    redirect = RedirectResponse(url="/", status_code=302)
    login_user(redirect, user)
    return redirect


@router.get("/logout")
async def logout(response: Response):
    """Выход из системы"""
    redirect = RedirectResponse(url="/login", status_code=302)
    logout_user(redirect)
    return redirect


@router.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, user: dict = Depends(require_auth)):
    """Страница профиля пользователя"""
    return templates.TemplateResponse(request, "profile.html", {
        "user": user
    })


@router.post("/profile/password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: dict = Depends(require_auth)
):
    """Изменение пароля"""
    errors = []
    
    if new_password != confirm_password:
        errors.append("Пароли не совпадают")
    
    if len(new_password) < 6:
        errors.append("Минимальная длина пароля - 6 символов")
    
    if not verify_password(current_password, user["password_hash"]):
        errors.append("Неверный текущий пароль")
    
    if errors:
        return alert_response(request, "error", "; ".join(errors))
    
    UserDB.change_password(user["id"], new_password)
    
    return alert_response(request, "success", "Пароль успешно изменён")


# ==================== Управление пользователями панели (только админ) ====================

@router.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, user: dict = Depends(require_admin)):
    """Страница управления пользователями панели"""
    users = UserDB.get_all_users()
    return templates.TemplateResponse(request, "users.html", {
        "user": user,
        "users": users
    })


@router.get("/users/list", response_class=HTMLResponse)
async def users_list(request: Request, user: dict = Depends(require_admin)):
    """Список пользователей (HTMX partial)"""
    users = UserDB.get_all_users()
    return templates.TemplateResponse(request, "components/users_list.html", {
        "users": users,
        "current_user_id": user["id"]
    })


@router.get("/users/create-form", response_class=HTMLResponse)
async def create_user_form(request: Request, user: dict = Depends(require_admin)):
    """Форма создания пользователя (HTMX modal)"""
    return templates.TemplateResponse(request, "components/user_create_form.html", {})


@router.post("/users/create")
async def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    is_admin: bool = Form(False),
    user: dict = Depends(require_admin)
):
    """Создание нового пользователя"""
    if len(username) < 3:
        return alert_response(request, "error", 
            "Имя пользователя должно содержать минимум 3 символа")
    
    if len(password) < 6:
        return alert_response(request, "error", 
            "Пароль должен содержать минимум 6 символов")
    
    if UserDB.create_user(username, password, is_admin):
        return users_list_response(request, user["id"], f"Пользователь {username} создан")
    else:
        return alert_response(request, "error", 
            "Пользователь с таким именем уже существует")


@router.delete("/users/{user_id}")
async def delete_user(
    request: Request,
    user_id: int,
    user: dict = Depends(require_admin)
):
    """Удаление пользователя"""
    if user_id == user["id"]:
        return alert_response(request, "error", "Нельзя удалить самого себя")
    
    if UserDB.delete_user(user_id):
        return users_list_response(request, user["id"], "Пользователь удалён")
    else:
        return alert_response(request, "error", "Не удалось удалить пользователя")


@router.post("/users/{user_id}/toggle-active")
async def toggle_user_active(
    request: Request,
    user_id: int,
    user: dict = Depends(require_admin)
):
    """Включение/отключение пользователя"""
    if user_id == user["id"]:
        return alert_response(request, "error", "Нельзя отключить самого себя")
    
    new_state = UserDB.toggle_user_active(user_id)
    if new_state is not None:
        state_text = "включен" if new_state else "отключен"
        return users_list_response(request, user["id"], f"Пользователь {state_text}")
    else:
        return alert_response(request, "error", "Пользователь не найден")


@router.post("/users/{user_id}/toggle-admin")
async def toggle_user_admin(
    request: Request,
    user_id: int,
    user: dict = Depends(require_admin)
):
    """Изменение роли админа"""
    if user_id == user["id"]:
        return alert_response(request, "error", "Нельзя изменить свою роль")
    
    new_state = UserDB.toggle_user_admin(user_id)
    if new_state is not None:
        role_text = "Администратор" if new_state else "Пользователь"
        return users_list_response(request, user["id"], f"Роль изменена на: {role_text}")
    else:
        return alert_response(request, "error", "Пользователь не найден")


@router.post("/users/{user_id}/change-password")
async def admin_change_password(
    request: Request,
    user_id: int,
    new_password: str = Form(...),
    user: dict = Depends(require_admin)
):
    """Смена пароля пользователя администратором"""
    if len(new_password) < 6:
        return alert_response(request, "error", 
            "Пароль должен содержать минимум 6 символов")
    
    if UserDB.change_password(user_id, new_password):
        return alert_response(request, "success", "Пароль успешно изменён")
    else:
        return alert_response(request, "error", "Не удалось изменить пароль")


@router.get("/users/{user_id}/edit-form", response_class=HTMLResponse)
async def edit_user_form(
    request: Request,
    user_id: int,
    user: dict = Depends(require_admin)
):
    """Форма редактирования пользователя"""
    target_user = UserDB.get_user_by_id(user_id)
    if not target_user:
        return alert_response(request, "error", "Пользователь не найден")
    
    return templates.TemplateResponse(request, "components/user_edit_form.html", {
        "target_user": target_user,
        "current_user_id": user["id"]
    })
