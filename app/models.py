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
Pydantic модели для валидации данных
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

from app.config import DEFAULT_WG_PORT, DEFAULT_PERSISTENT_KEEPALIVE


# ==================== Модели авторизации ====================

class LoginForm(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=4)


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    is_admin: bool = False


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6)


class UserResponse(BaseModel):
    id: int
    username: str
    is_admin: bool
    created_at: Optional[str] = None
    last_login: Optional[str] = None


# ==================== Модели WireGuard ====================

class WGInterface(BaseModel):
    """Секция [Interface] в конфиге WireGuard"""
    private_key: str = Field(..., alias="PrivateKey")
    address: str = Field(..., alias="Address")
    listen_port: int = Field(DEFAULT_WG_PORT, alias="ListenPort")
    dns: Optional[str] = Field(None, alias="DNS")
    post_up: Optional[str] = Field(None, alias="PostUp")
    post_down: Optional[str] = Field(None, alias="PostDown")
    mtu: Optional[int] = Field(None, alias="MTU")
    
    class Config:
        populate_by_name = True


class WGPeer(BaseModel):
    """Секция [Peer] в конфиге WireGuard"""
    public_key: str = Field(..., alias="PublicKey")
    preshared_key: Optional[str] = Field(None, alias="PresharedKey")
    allowed_ips: str = Field(..., alias="AllowedIPs")
    endpoint: Optional[str] = Field(None, alias="Endpoint")
    persistent_keepalive: Optional[int] = Field(None, alias="PersistentKeepalive")
    
    # Дополнительные поля для UI (хранятся в комментариях)
    name: Optional[str] = None
    enabled: bool = True
    created_at: Optional[str] = None
    
    class Config:
        populate_by_name = True


class PeerCreate(BaseModel):
    """Форма создания нового пира"""
    name: str = Field(..., min_length=1, max_length=50)
    allowed_ips: str = Field(...)
    dns: Optional[str] = None
    persistent_keepalive: Optional[int] = Field(DEFAULT_PERSISTENT_KEEPALIVE, ge=0, le=65535)
    endpoint: Optional[str] = None


class PeerUpdate(BaseModel):
    """Форма обновления пира"""
    name: Optional[str] = Field(None, min_length=1, max_length=50)
    allowed_ips: Optional[str] = None
    enabled: Optional[bool] = None
    persistent_keepalive: Optional[int] = Field(None, ge=0, le=65535)


class PeerStatus(BaseModel):
    """Статус пира из wg show"""
    public_key: str
    endpoint: Optional[str] = None
    latest_handshake: Optional[datetime] = None
    transfer_rx: int = 0  # байты
    transfer_tx: int = 0  # байты
    is_online: bool = False


class PeerWithStatus(BaseModel):
    """Пир с информацией о статусе"""
    peer: WGPeer
    status: Optional[PeerStatus] = None
    client_config: Optional[str] = None  # Конфиг для клиента
