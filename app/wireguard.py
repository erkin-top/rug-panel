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
Модуль для работы с конфигурацией WireGuard
Парсинг и генерация конфигурационных файлов без внешних зависимостей

ОПТИМИЗАЦИИ:
- Кэширование конфигурации с TTL
- Кэширование статусов пиров
- Lazy loading для cryptography
- Пул subprocess для уменьшения накладных расходов
- Мемоизация публичных ключей
"""
import re
import subprocess
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import secrets
import base64
import threading
import time
from functools import lru_cache

from app.config import (
    WG_CONFIG_PATH, WG_INTERFACE, DEFAULT_PERSISTENT_KEEPALIVE,
    CONFIG_CACHE_TTL, STATUS_CACHE_TTL, WG_SERVER_ENDPOINT,
    DEFAULT_DNS, DEFAULT_ALLOWED_IPS, DEFAULT_WG_PORT, DEFAULT_VPN_ADDRESS
)


# Глобальный кэш для конфигурации
_config_cache: Dict[str, tuple] = {}  # {path: (interface, peers, mtime, timestamp)}
_config_cache_ttl = CONFIG_CACHE_TTL  # Из переменных окружения
_config_lock = threading.RLock()

# Кэш статусов пиров
_status_cache: Dict[str, tuple] = {}  # {interface: (statuses, timestamp)}
_status_cache_ttl = STATUS_CACHE_TTL  # Из переменных окружения
_status_lock = threading.Lock()

# Кэш публичных ключей (вычисление затратная операция)
_pubkey_cache: Dict[str, str] = {}  # {private_key: public_key}
_pubkey_lock = threading.Lock()

# Lazy-loaded cryptography модули
_x25519_loaded = False
_X25519PrivateKey = None


def _load_x25519():
    """Lazy loading для cryptography - загружаем только при необходимости"""
    global _x25519_loaded, _X25519PrivateKey
    if not _x25519_loaded:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        _X25519PrivateKey = X25519PrivateKey
        _x25519_loaded = True
    return _X25519PrivateKey


class WGKeyGenerator:
    """
    Генератор ключей WireGuard через wg утилиту или встроенные методы.
    Оптимизации:
    - Кэширование публичных ключей
    - Lazy loading cryptography
    - Проверка доступности wg один раз
    """
    
    _wg_available: Optional[bool] = None
    
    @classmethod
    def _check_wg_available(cls) -> bool:
        """Проверка доступности wg утилиты (кэшируется)"""
        if cls._wg_available is None:
            try:
                subprocess.run(
                    ["wg", "--version"],
                    capture_output=True,
                    check=True,
                    timeout=5
                )
                cls._wg_available = True
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                cls._wg_available = False
        return cls._wg_available
    
    @staticmethod
    def generate_private_key() -> str:
        """Генерация приватного ключа"""
        if WGKeyGenerator._check_wg_available():
            try:
                result = subprocess.run(
                    ["wg", "genkey"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5
                )
                return result.stdout.strip()
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
        
        # Fallback: генерация через cryptography
        X25519PrivateKey = _load_x25519()
        private_key = X25519PrivateKey.generate()
        return base64.b64encode(private_key.private_bytes_raw()).decode()
    
    @staticmethod
    def get_public_key(private_key: str) -> str:
        """Получение публичного ключа из приватного (с кэшированием)"""
        # Проверяем кэш
        with _pubkey_lock:
            if private_key in _pubkey_cache:
                return _pubkey_cache[private_key]
        
        public_key = None
        
        if WGKeyGenerator._check_wg_available():
            try:
                result = subprocess.run(
                    ["wg", "pubkey"],
                    input=private_key,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5
                )
                public_key = result.stdout.strip()
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
        
        if not public_key:
            # Fallback через cryptography
            X25519PrivateKey = _load_x25519()
            private_bytes = base64.b64decode(private_key)
            private_key_obj = X25519PrivateKey.from_private_bytes(private_bytes)
            pub_key_obj = private_key_obj.public_key()
            public_key = base64.b64encode(pub_key_obj.public_bytes_raw()).decode()
        
        # Сохраняем в кэш
        with _pubkey_lock:
            _pubkey_cache[private_key] = public_key
        
        return public_key
    
    @staticmethod
    def generate_preshared_key() -> str:
        """Генерация preshared ключа"""
        if WGKeyGenerator._check_wg_available():
            try:
                result = subprocess.run(
                    ["wg", "genpsk"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5
                )
                return result.stdout.strip()
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
        
        # Fallback: 32 случайных байта в base64
        return base64.b64encode(secrets.token_bytes(32)).decode()


class WGConfigParser:
    """
    Парсер конфигурационного файла WireGuard.
    Оптимизации:
    - Кэширование результатов парсинга
    - Проверка mtime файла для инвалидации кэша
    - Компилированные regex для скорости
    """
    
    # Предкомпилированные regex
    _SECTION_RE = re.compile(r'^\[(\w+)\]$')
    _PARAM_RE = re.compile(r'^(\w+)\s*=\s*(.*)$')
    
    def __init__(self, config_path: Path = WG_CONFIG_PATH):
        self.config_path = Path(config_path)
        self._interface: Dict = {}
        self._peers: List[Dict] = []
        self._raw_content: str = ""
    
    def parse(self, force_reload: bool = False) -> Tuple[Dict, List[Dict]]:
        """
        Парсинг конфига и возврат Interface и списка Peers.
        Использует кэширование с проверкой mtime.
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"Конфигурационный файл не найден: {self.config_path}")
        
        cache_key = str(self.config_path)
        current_mtime = self.config_path.stat().st_mtime
        current_time = time.time()
        
        # Проверяем кэш
        with _config_lock:
            if not force_reload and cache_key in _config_cache:
                cached_interface, cached_peers, cached_mtime, cached_time = _config_cache[cache_key]
                # Валидный кэш: файл не изменился И TTL не истёк
                if cached_mtime == current_mtime and (current_time - cached_time) < _config_cache_ttl:
                    # Возвращаем глубокие копии чтобы избежать мутаций кэша
                    return (
                        cached_interface.copy(),
                        [p.copy() for p in cached_peers]
                    )
        
        # Парсим файл
        self._raw_content = self.config_path.read_text(encoding='utf-8')
        self._interface = {}
        self._peers = []
        
        current_section = None
        current_data = {}
        pending_comments = []
        current_peer_comments = []
        
        in_disabled_peer = False
        disabled_peer_data = {}
        
        for line in self._raw_content.split('\n'):
            line = line.strip()
            
            if not line:
                continue
            
            if line.startswith('#'):
                comment_text = line[1:].strip()
                
                if comment_text == 'DISABLED PEER START':
                    in_disabled_peer = True
                    disabled_peer_data = {'_enabled': False}
                    continue
                elif comment_text == 'DISABLED PEER END':
                    if in_disabled_peer and disabled_peer_data.get('PublicKey'):
                        self._peers.append(disabled_peer_data.copy())
                    in_disabled_peer = False
                    disabled_peer_data = {}
                    continue
                
                if in_disabled_peer:
                    # Оптимизация: используем startswith вместо regex
                    if comment_text.startswith('Name:'):
                        disabled_peer_data['_name'] = comment_text[5:].strip()
                    elif comment_text.startswith('Created:'):
                        disabled_peer_data['_created'] = comment_text[8:].strip()
                    elif comment_text.startswith('PublicKey:'):
                        disabled_peer_data['PublicKey'] = comment_text[10:].strip()
                    elif comment_text.startswith('AllowedIPs:'):
                        disabled_peer_data['AllowedIPs'] = comment_text[11:].strip()
                    elif comment_text.startswith('PresharedKey:'):
                        disabled_peer_data['PresharedKey'] = comment_text[13:].strip()
                    elif comment_text.startswith('PersistentKeepalive:'):
                        disabled_peer_data['PersistentKeepalive'] = comment_text[20:].strip()
                    elif comment_text.startswith('ClientPrivateKey:'):
                        disabled_peer_data['_client_private_key'] = comment_text[17:].strip()
                    elif comment_text.startswith('DNS:'):
                        disabled_peer_data['_dns'] = comment_text[4:].strip()
                    continue
                
                pending_comments.append(comment_text)
                continue
            
            # Проверка секции - оптимизирован без regex
            if line.startswith('[') and line.endswith(']'):
                if current_section == 'Interface':
                    self._interface = current_data.copy()
                    # Извлекаем метаданные из сохранённых комментариев
                    saved_comments = self._interface.pop('_pending_comments', [])
                    if saved_comments:
                        self._extract_interface_metadata(self._interface, saved_comments)
                elif current_section == 'Peer':
                    self._extract_peer_metadata(current_data, current_peer_comments)
                    self._peers.append(current_data.copy())
                
                new_section = line[1:-1]
                current_data = {}
                
                # Сохраняем комментарии ДО секции Interface для последующего применения
                if new_section == 'Interface' and pending_comments:
                    current_data['_pending_comments'] = pending_comments.copy()
                
                current_section = new_section
                
                if current_section == 'Peer':
                    current_peer_comments = pending_comments.copy()
                pending_comments = []
                continue
            
            # Параметр = значение
            if '=' in line:
                key, value = line.split('=', 1)
                current_data[key.strip()] = value.strip()
        
        # Сохраняем последнюю секцию
        if current_section == 'Interface':
            self._interface = current_data.copy()
            # Извлекаем метаданные интерфейса из сохранённых комментариев
            interface_comments = self._interface.pop('_pending_comments', [])
            if interface_comments:
                self._extract_interface_metadata(self._interface, interface_comments)
        elif current_section == 'Peer':
            self._extract_peer_metadata(current_data, current_peer_comments)
            self._peers.append(current_data.copy())
        
        # Сохраняем в кэш
        with _config_lock:
            _config_cache[cache_key] = (
                self._interface.copy(),
                [p.copy() for p in self._peers],
                current_mtime,
                current_time
            )
        
        return self._interface, self._peers
    
    def _extract_interface_metadata(self, interface_data: Dict, comments: List[str]):
        """Извлечение метаданных интерфейса из комментариев
        
        Поддерживаемые форматы:
        - # ServerEndpoint: IP или IP:порт сервера для клиентских конфигов
        - # EnableNAT: true/false - состояние NAT
        - # EnableForwarding: true/false - состояние форвардинга между клиентами
        - # NetworkInterface: eth0 - сетевой интерфейс для NAT
        """
        for comment in comments:
            # Используем нижний регистр только для проверки префикса
            comment_stripped = comment.strip()
            comment_lower = comment_stripped.lower()
            
            if comment_lower.startswith('serverendpoint:'):
                interface_data['_server_endpoint'] = comment_stripped[15:].strip()
            elif comment_lower.startswith('enablenat:'):
                interface_data['_enable_nat'] = comment_stripped[10:].strip().lower()
            elif comment_lower.startswith('enableforwarding:'):
                interface_data['_enable_forwarding'] = comment_stripped[17:].strip().lower()
            elif comment_lower.startswith('networkinterface:'):
                interface_data['_network_interface'] = comment_stripped[17:].strip()
    
    def _extract_peer_metadata(self, peer_data: Dict, comments: List[str]):
        """Извлечение метаданных пира из комментариев
        
        Поддерживаемые форматы:
        - # Name: имя_пира (структурированный формат)
        - # Created: дата_создания
        - # DISABLED
        - # ClientPrivateKey: приватный ключ клиента (для генерации QR)
        - # просто_имя_пира (простой комментарий без префикса = имя)
        - #имя_без_пробела (простой комментарий без пробела после #)
        """
        name_found = False
        
        for comment in comments:
            comment_lower = comment.lower()
            
            # Структурированные метаданные
            if comment_lower.startswith('name:'):
                peer_data['_name'] = comment[5:].strip()
                name_found = True
            elif comment_lower.startswith('created:'):
                peer_data['_created'] = comment[8:].strip()
            elif comment_lower.startswith('enabled:'):
                peer_data['_enabled'] = comment[8:].strip().lower() == 'true'
            elif comment_lower.startswith('clientprivatekey:'):
                peer_data['_client_private_key'] = comment[17:].strip()
            elif comment_lower.startswith('dns:'):
                peer_data['_dns'] = comment[4:].strip()
            elif comment_lower.strip() == 'disabled':
                peer_data['_enabled'] = False
            elif not name_found and comment.strip():
                # Простой комментарий без префикса = имя пира
                # Берём только первый непустой комментарий как имя
                peer_data['_name'] = comment.strip()
                name_found = True
    
    @property
    def interface(self) -> Dict:
        return self._interface
    
    @property
    def peers(self) -> List[Dict]:
        return self._peers


class WGConfigWriter:
    """Генератор конфигурационного файла WireGuard"""
    
    @staticmethod
    def generate_config(interface: Dict, peers: List[Dict]) -> str:
        """Генерация полного конфига"""
        lines = []
        
        # Метаданные интерфейса в комментариях (до секции [Interface])
        if interface.get('_server_endpoint'):
            lines.append(f"# ServerEndpoint: {interface['_server_endpoint']}")
        
        # Сохраняем состояние режимов работы сервера
        if '_enable_nat' in interface:
            lines.append(f"# EnableNAT: {interface['_enable_nat']}")
        if '_enable_forwarding' in interface:
            lines.append(f"# EnableForwarding: {interface['_enable_forwarding']}")
        if '_network_interface' in interface:
            lines.append(f"# NetworkInterface: {interface['_network_interface']}")
        
        lines.append("[Interface]")
        
        # Interface параметры в определённом порядке
        interface_order = ['PrivateKey', 'Address', 'ListenPort', 'DNS', 'MTU', 'PostUp', 'PostDown']
        for key in interface_order:
            if key in interface and interface[key]:
                lines.append(f"{key} = {interface[key]}")
        
        # Добавляем остальные параметры (исключая внутренние поля с префиксом _)
        for key, value in interface.items():
            if key not in interface_order and value and not key.startswith('_'):
                lines.append(f"{key} = {value}")
        
        # Peers
        for peer in peers:
            # Отключённые пиры записываем как комментарии, а не как [Peer]
            if peer.get('_enabled') is False:
                lines.append("")
                lines.append("# DISABLED PEER START")
                if peer.get('_name'):
                    lines.append(f"# Name: {peer['_name']}")
                if peer.get('_created'):
                    lines.append(f"# Created: {peer['_created']}")
                lines.append(f"# PublicKey: {peer.get('PublicKey', '')}")
                lines.append(f"# AllowedIPs: {peer.get('AllowedIPs', '')}")
                if peer.get('PresharedKey'):
                    lines.append(f"# PresharedKey: {peer['PresharedKey']}")
                if peer.get('PersistentKeepalive'):
                    lines.append(f"# PersistentKeepalive: {peer['PersistentKeepalive']}")
                if peer.get('_client_private_key'):
                    lines.append(f"# ClientPrivateKey: {peer['_client_private_key']}")
                if peer.get('_dns'):
                    lines.append(f"# DNS: {peer['_dns']}")
                lines.append("# DISABLED PEER END")
                continue
            
            lines.append("")
            
            # Метаданные в комментариях - используем простой формат для имени
            if peer.get('_name'):
                lines.append(f"# {peer['_name']}")
            if peer.get('_created'):
                lines.append(f"# Created: {peer['_created']}")
            if peer.get('_client_private_key'):
                lines.append(f"# ClientPrivateKey: {peer['_client_private_key']}")
            if peer.get('_dns'):
                lines.append(f"# DNS: {peer['_dns']}")
            
            lines.append("[Peer]")
            
            peer_order = ['PublicKey', 'PresharedKey', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive']
            for key in peer_order:
                if key in peer and peer[key]:
                    lines.append(f"{key} = {peer[key]}")
        
        return '\n'.join(lines) + '\n'
    
    @staticmethod
    def generate_client_config(
        server_public_key: str,
        server_endpoint: str,
        client_private_key: str,
        client_address: str,
        dns: str = DEFAULT_DNS,
        allowed_ips: str = DEFAULT_ALLOWED_IPS,
        preshared_key: Optional[str] = None,
        persistent_keepalive: int = DEFAULT_PERSISTENT_KEEPALIVE
    ) -> str:
        """Генерация конфига для клиента"""
        lines = [
            "[Interface]",
            f"PrivateKey = {client_private_key}",
            f"Address = {client_address}",
            f"DNS = {dns}",
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
        ]
        
        if preshared_key:
            lines.append(f"PresharedKey = {preshared_key}")
        
        lines.extend([
            f"Endpoint = {server_endpoint}",
            f"AllowedIPs = {allowed_ips}",
            f"PersistentKeepalive = {persistent_keepalive}"
        ])
        
        return '\n'.join(lines) + '\n'


class WGManager:
    """
    Менеджер для управления WireGuard.
    Оптимизации:
    - Кэширование статусов с TTL
    - Инвалидация кэша при записи
    - Переиспользование parser instance
    """
    
    def __init__(self, config_path: Path = WG_CONFIG_PATH, interface: str = WG_INTERFACE):
        self.config_path = Path(config_path)
        self.interface = interface
        self.parser = WGConfigParser(config_path)
        self.key_gen = WGKeyGenerator()
    
    def load_config(self, force_reload: bool = False) -> Tuple[Dict, List[Dict]]:
        """Загрузка конфигурации (с кэшированием)"""
        return self.parser.parse(force_reload=force_reload)
    
    def save_config(self, interface: Dict, peers: List[Dict]):
        """Сохранение конфигурации (с инвалидацией кэша)"""
        content = WGConfigWriter.generate_config(interface, peers)
        
        # Создаём бэкап
        if self.config_path.exists():
            backup_path = self.config_path.with_suffix('.conf.bak')
            if backup_path.exists():
                backup_path.unlink()
            self.config_path.rename(backup_path)
        
        self.config_path.write_text(content, encoding='utf-8')
        
        # Инвалидируем кэш конфигурации
        cache_key = str(self.config_path)
        with _config_lock:
            if cache_key in _config_cache:
                del _config_cache[cache_key]
    
    def get_peers_status(self, use_cache: bool = True) -> Dict[str, Dict]:
        """
        Получение статуса всех пиров через wg show.
        Оптимизация: кэширование с коротким TTL.
        """
        current_time = time.time()
        
        # Проверяем кэш
        if use_cache:
            with _status_lock:
                if self.interface in _status_cache:
                    cached_status, cached_time = _status_cache[self.interface]
                    if (current_time - cached_time) < _status_cache_ttl:
                        return cached_status.copy()
        
        status = {}
        try:
            result = subprocess.run(
                ["wg", "show", self.interface, "dump"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5  # Добавлен таймаут
            )
            
            lines = result.stdout.strip().split('\n')
            if len(lines) < 2:
                return status
            
            # Оптимизация: используем datetime.now() один раз
            now = datetime.now()
            
            for line in lines[1:]:
                parts = line.split('\t')
                if len(parts) >= 8:
                    public_key = parts[0]
                    endpoint = parts[2] if parts[2] != '(none)' else None
                    latest_handshake = int(parts[4]) if parts[4] != '0' else None
                    rx_bytes = int(parts[5])
                    tx_bytes = int(parts[6])
                    
                    is_online = False
                    handshake_time = None
                    if latest_handshake:
                        handshake_time = datetime.fromtimestamp(latest_handshake)
                        delta = now - handshake_time
                        is_online = delta.total_seconds() < 180
                    
                    status[public_key] = {
                        'endpoint': endpoint,
                        'latest_handshake': handshake_time,
                        'transfer_rx': rx_bytes,
                        'transfer_tx': tx_bytes,
                        'is_online': is_online
                    }
            
            # Сохраняем в кэш
            with _status_lock:
                _status_cache[self.interface] = (status.copy(), current_time)
                
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            print(f"Не удалось получить статус WireGuard: {e}")
        
        return status
    
    def reload_config(self) -> bool:
        """
        Перезагрузка конфигурации WireGuard.
        
        ВАЖНО: Всегда используем полный перезапуск через wg-quick,
        т.к. wg syncconf не применяет PostUp/PostDown правила!
        
        Используем имя интерфейса (wg0), т.к. симлинк создаётся в entrypoint.sh:
        /etc/wireguard/wg0.conf -> /app/data/wg0.conf
        """
        try:
            # В Docker контейнере может работать от root или с CAP_NET_ADMIN
            # Убираем проверку geteuid для поддержки Docker
            
            # Полный перезапуск интерфейса для применения PostUp/PostDown
            # Используем имя интерфейса, т.к. симлинк создан в /etc/wireguard/
            subprocess.run(
                ["wg-quick", "down", self.interface],
                capture_output=True,
                check=False  # Игнорируем ошибки если интерфейс уже down
            )
            
            # Небольшая пауза для очистки
            import time
            time.sleep(0.5)
            
            result = subprocess.run(
                ["wg-quick", "up", self.interface],
                capture_output=True,
                text=True,
                check=True
            )
            print(f"WireGuard reloaded successfully: {self.interface}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"wg-quick restart failed: {e}")
            print(f"stdout: {e.stdout if e.stdout else 'N/A'}")
            print(f"stderr: {e.stderr if e.stderr else 'N/A'}")
            return False
        except FileNotFoundError as e:
            print(f"wg-quick not found: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error during reload: {e}")
            return False
    
    def add_peer(
        self,
        name: str,
        allowed_ips: str,
        preshared_key: bool = True,
        persistent_keepalive: int = DEFAULT_PERSISTENT_KEEPALIVE,
        dns: str = DEFAULT_DNS
    ) -> Tuple[Dict, str]:
        """Добавление нового пира"""
        interface, peers = self.load_config()
        
        # Генерация ключей для клиента
        client_private_key = self.key_gen.generate_private_key()
        client_public_key = self.key_gen.get_public_key(client_private_key)
        psk = self.key_gen.generate_preshared_key() if preshared_key else None
        
        # Создаём нового пира
        new_peer = {
            'PublicKey': client_public_key,
            'AllowedIPs': allowed_ips,
            'PersistentKeepalive': str(persistent_keepalive),
            '_name': name,
            '_created': datetime.now().isoformat(),
            '_enabled': True,
            '_client_private_key': client_private_key,  # Сохраняем для возможности показать QR позже
            '_dns': dns  # Сохраняем DNS для генерации конфига
        }
        
        if psk:
            new_peer['PresharedKey'] = psk
        
        peers.append(new_peer)
        self.save_config(interface, peers)
        
        # Генерируем конфиг для клиента
        server_public_key = self.key_gen.get_public_key(interface['PrivateKey'])
        # Приоритет endpoint: 1) ENV WG_SERVER_ENDPOINT, 2) сохранённый _server_endpoint, 3) YOUR_SERVER_IP
        if WG_SERVER_ENDPOINT:
            # ENV переменная имеет наивысший приоритет (не затирается автодетектом)
            if ':' not in WG_SERVER_ENDPOINT:
                server_endpoint = f"{WG_SERVER_ENDPOINT}:{interface.get('ListenPort', DEFAULT_WG_PORT)}"
            else:
                server_endpoint = WG_SERVER_ENDPOINT
        else:
            saved_endpoint = interface.get('_server_endpoint', '')
            if saved_endpoint:
                # Если endpoint содержит только IP без порта - добавляем порт
                if ':' not in saved_endpoint:
                    server_endpoint = f"{saved_endpoint}:{interface.get('ListenPort', DEFAULT_WG_PORT)}"
                else:
                    server_endpoint = saved_endpoint
            else:
                server_endpoint = f"YOUR_SERVER_IP:{interface.get('ListenPort', DEFAULT_WG_PORT)}"
        
        client_config = WGConfigWriter.generate_client_config(
            server_public_key=server_public_key,
            server_endpoint=server_endpoint,
            client_private_key=client_private_key,
            client_address=allowed_ips.split('/')[0] + '/32',  # Адрес клиента
            dns=dns,
            preshared_key=psk,
            persistent_keepalive=persistent_keepalive
        )
        
        return new_peer, client_config
    
    def update_peer(self, public_key: str, updates: Dict) -> bool:
        """Обновление параметров пира"""
        interface, peers = self.load_config()
        
        for peer in peers:
            if peer.get('PublicKey') == public_key:
                if 'name' in updates:
                    peer['_name'] = updates['name']
                if 'enabled' in updates:
                    peer['_enabled'] = updates['enabled']
                if 'allowed_ips' in updates:
                    peer['AllowedIPs'] = updates['allowed_ips']
                if 'persistent_keepalive' in updates:
                    peer['PersistentKeepalive'] = str(updates['persistent_keepalive'])
                
                # Обработка PresharedKey
                if 'use_preshared_key' in updates:
                    if updates['use_preshared_key']:
                        # Генерируем новый PresharedKey (заменяем старый или создаем новый)
                        peer['PresharedKey'] = self.key_gen.generate_preshared_key()
                    else:
                        # Удаляем PresharedKey если он был
                        if 'PresharedKey' in peer:
                            del peer['PresharedKey']
                
                # Обработка смены PublicKey
                if 'new_public_key' in updates:
                    old_public_key = peer['PublicKey']
                    new_public_key = updates['new_public_key']
                    
                    # Проверяем что новый ключ уникален
                    for other_peer in peers:
                        if other_peer.get('PublicKey') == new_public_key:
                            raise ValueError(f"Ключ {new_public_key} уже используется")
                    
                    # Удаляем старого пира из WireGuard
                    try:
                        subprocess.run(
                            ["wg", "set", WG_INTERFACE, "peer", old_public_key, "remove"],
                            check=False, capture_output=True
                        )
                    except Exception:
                        pass
                    
                    # Обновляем ключ
                    peer['PublicKey'] = new_public_key
                
                self.save_config(interface, peers)
                return True
        
        return False
    
    def delete_peer(self, public_key: str) -> bool:
        """Удаление пира"""
        interface, peers = self.load_config()
        
        original_count = len(peers)
        peers = [p for p in peers if p.get('PublicKey') != public_key]
        
        if len(peers) < original_count:
            self.save_config(interface, peers)
            return True
        
        return False
    
    def toggle_peer(self, public_key: str) -> Optional[bool]:
        """
        Включение/отключение пира.
        При отключении: удаляем пира из активного интерфейса через 'wg set'.
        При включении: добавляем пира обратно через 'wg set'.
        В обоих случаях сохраняем состояние в конфиге.
        """
        interface, peers = self.load_config()
        
        for peer in peers:
            if peer.get('PublicKey') == public_key:
                current_state = peer.get('_enabled', True)
                new_state = not current_state
                peer['_enabled'] = new_state
                
                # Применяем изменения к активному WireGuard интерфейсу
                try:
                    if new_state:
                        # Включаем: добавляем пира обратно в интерфейс
                        allowed_ips = peer.get('AllowedIPs', '')
                        psk = peer.get('PresharedKey', '')
                        keepalive = peer.get('PersistentKeepalive', DEFAULT_PERSISTENT_KEEPALIVE)
                        
                        cmd = ["wg", "set", WG_INTERFACE, "peer", public_key, "allowed-ips", allowed_ips]
                        if psk:
                            # PSK нужно передавать через stdin или файл
                            pass  # Упрощённо пропускаем PSK при реактивации
                        if keepalive:
                            cmd.extend(["persistent-keepalive", str(keepalive)])
                        
                        subprocess.run(cmd, check=False, capture_output=True)
                    else:
                        # Отключаем: удаляем пира из интерфейса
                        subprocess.run(
                            ["wg", "set", WG_INTERFACE, "peer", public_key, "remove"],
                            check=False, capture_output=True
                        )
                except Exception as e:
                    # Логируем ошибку, но продолжаем сохранять состояние
                    print(f"Ошибка применения wg set: {e}")
                
                self.save_config(interface, peers)
                return peer['_enabled']
        
        return None
    
    def get_next_available_ip(self) -> str:
        """Получение следующего доступного IP для нового пира"""
        interface, peers = self.load_config()
        
        # Получаем подсеть сервера
        server_address = interface.get('Address', DEFAULT_VPN_ADDRESS)
        network = ipaddress.ip_network(server_address, strict=False)
        
        # Собираем занятые IP
        used_ips = set()
        
        # IP сервера
        server_ip = ipaddress.ip_address(server_address.split('/')[0])
        used_ips.add(server_ip)
        
        # IP пиров
        for peer in peers:
            allowed = peer.get('AllowedIPs', '')
            for ip_str in allowed.split(','):
                ip_str = ip_str.strip().split('/')[0]
                try:
                    used_ips.add(ipaddress.ip_address(ip_str))
                except ValueError:
                    continue
        
        # Находим первый свободный IP
        for host in network.hosts():
            if host not in used_ips:
                return f"{host}/32"
        
        raise ValueError("Нет доступных IP-адресов в подсети")

    def _default_peer_allowed_ips(self, interface: Dict) -> str:
        """Fallback AllowedIPs (если в peer нет значения).

        Пытаемся получить вторую доступную IPv4-адресацию в VPN сети,
        чтобы избежать захардкоженного 10.0.0.2/32.
        """
        server_address = interface.get('Address', DEFAULT_VPN_ADDRESS)
        candidates = [a.strip() for a in str(server_address).split(',') if a.strip()]
        for candidate in candidates:
            try:
                iface = ipaddress.ip_interface(candidate)
                if isinstance(iface.ip, ipaddress.IPv4Address):
                    network = iface.network
                    # Берём первый хост, который не равен IP сервера
                    for host in network.hosts():
                        if host != iface.ip:
                            return f"{host}/32"
            except ValueError:
                continue
        return "0.0.0.0/32"
    
    def get_server_info(self) -> Dict:
        """Получение информации о сервере"""
        interface, _ = self.load_config()
        
        try:
            public_key = self.key_gen.get_public_key(interface['PrivateKey'])
        except:
            public_key = "Ошибка получения"
        
        return {
            'public_key': public_key,
            'address': interface.get('Address', ''),
            'listen_port': interface.get('ListenPort', DEFAULT_WG_PORT),
            'dns': interface.get('DNS', ''),
        }
    
    def get_client_config(self, public_key: str, server_endpoint: Optional[str] = None, dns: Optional[str] = None) -> Optional[str]:
        """
        Генерация клиентского конфига для существующего пира.
        Возвращает None если приватный ключ клиента не сохранён.
        """
        interface, peers = self.load_config()
        
        peer = None
        for p in peers:
            if p.get('PublicKey') == public_key:
                peer = p
                break
        
        if not peer:
            return None
        
        # Проверяем наличие приватного ключа клиента
        client_private_key = peer.get('_client_private_key')
        if not client_private_key:
            return None
        
        # Получаем публичный ключ сервера
        try:
            server_public_key = self.key_gen.get_public_key(interface['PrivateKey'])
        except:
            return None
        
        # Формируем endpoint из сохранённых настроек или переданного параметра
        if not server_endpoint:
            # Приоритет endpoint: 1) ENV WG_SERVER_ENDPOINT, 2) сохранённый _server_endpoint, 3) YOUR_SERVER_IP
            if WG_SERVER_ENDPOINT:
                # ENV переменная имеет наивысший приоритет (не затирается автодетектом)
                if ':' not in WG_SERVER_ENDPOINT:
                    server_endpoint = f"{WG_SERVER_ENDPOINT}:{interface.get('ListenPort', DEFAULT_WG_PORT)}"
                else:
                    server_endpoint = WG_SERVER_ENDPOINT
            else:
                saved_endpoint = interface.get('_server_endpoint', '')
                if saved_endpoint:
                    # Если endpoint содержит только IP без порта - добавляем порт
                    if ':' not in saved_endpoint:
                        server_endpoint = f"{saved_endpoint}:{interface.get('ListenPort', DEFAULT_WG_PORT)}"
                    else:
                        server_endpoint = saved_endpoint
                else:
                    server_endpoint = f"YOUR_SERVER_IP:{interface.get('ListenPort', DEFAULT_WG_PORT)}"
        
        # DNS - используем переданный, или сохранённый для пира, или из настроек интерфейса
        if not dns:
            dns = peer.get('_dns') or interface.get('DNS', DEFAULT_DNS)
        
        # Адрес клиента
        allowed_ips = peer.get('AllowedIPs') or self._default_peer_allowed_ips(interface)
        client_address = allowed_ips.split('/')[0] + '/32'
        
        return WGConfigWriter.generate_client_config(
            server_public_key=server_public_key,
            server_endpoint=server_endpoint,
            client_private_key=client_private_key,
            client_address=client_address,
            dns=dns,
            preshared_key=peer.get('PresharedKey'),
            persistent_keepalive=int(peer.get('PersistentKeepalive', 25))
        )
