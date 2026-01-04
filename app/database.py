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
База данных для пользователей панели управления (НЕ WireGuard пиров)
Используется SQLite для простоты и отсутствия внешних зависимостей

ОПТИМИЗАЦИИ:
- Connection pooling через queue
- LRU кэширование пользователей
- WAL режим для лучшего concurrency
- Подготовленные индексы
- Batch операции где возможно
"""
import sqlite3
import threading
from queue import Queue, Empty
from contextlib import contextmanager
from typing import Optional, Dict, Any
from functools import lru_cache
import hashlib
import secrets
import hmac
import time

from app.config import DATABASE_PATH

# Параметры хеширования паролей (PBKDF2-HMAC-SHA256 - встроенный и надёжный)
# При доступе к серверу злоумышленник получит SECRET_KEY, поэтому
# используем умеренные параметры для баланса безопасности и скорости
PBKDF2_ITERATIONS = 100000  # Количество итераций
PBKDF2_HASH_FUNC = 'sha256'
SALT_LENGTH = 16
HASH_LENGTH = 32


def get_password_hash(password: str) -> str:
    """Хеширование пароля с использованием PBKDF2-HMAC-SHA256"""
    salt = secrets.token_bytes(SALT_LENGTH)
    hash_bytes = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_FUNC,
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=HASH_LENGTH
    )
    # Формат: iterations$salt_hex$hash_hex
    return f"{PBKDF2_ITERATIONS}${salt.hex()}${hash_bytes.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверка пароля"""
    try:
        # Поддержка старого формата Argon2 для миграции
        if hashed_password.startswith('$argon2'):
            # Argon2 хеши начинаются с $argon2 - требуют ручной миграции
            # Возвращаем False, пользователь должен сбросить пароль
            return False
        
        parts = hashed_password.split('$')
        if len(parts) != 3:
            return False
        
        iterations = int(parts[0])
        salt = bytes.fromhex(parts[1])
        stored_hash = bytes.fromhex(parts[2])
        
        # Вычисляем хеш введённого пароля
        computed_hash = hashlib.pbkdf2_hmac(
            PBKDF2_HASH_FUNC,
            plain_password.encode('utf-8'),
            salt,
            iterations,
            dklen=len(stored_hash)
        )
        
        # Сравнение с защитой от timing attack
        return hmac.compare_digest(computed_hash, stored_hash)
    except (ValueError, AttributeError):
        return False


class ConnectionPool:
    """
    Пул соединений SQLite для улучшения производительности.
    Избегает накладных расходов на создание/закрытие соединений.
    """
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, pool_size: int = 5):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, pool_size: int = 5):
        if self._initialized:
            return
        
        self.pool_size = pool_size
        self._pool: Queue = Queue(maxsize=pool_size)
        self._local = threading.local()
        self._initialized = True
        
        # Предварительное создание соединений
        for _ in range(pool_size):
            conn = self._create_connection()
            self._pool.put(conn)
    
    def _create_connection(self) -> sqlite3.Connection:
        """Создание оптимизированного соединения"""
        conn = sqlite3.connect(
            DATABASE_PATH,
            check_same_thread=False,  # Для пула
            isolation_level=None,     # Autocommit для read операций
            timeout=30.0              # Таймаут ожидания блокировки
        )
        conn.row_factory = sqlite3.Row
        
        # Оптимизации SQLite
        conn.execute("PRAGMA journal_mode=WAL")        # Write-Ahead Logging
        conn.execute("PRAGMA synchronous=NORMAL")       # Баланс скорости/надёжности
        conn.execute("PRAGMA cache_size=-64000")        # 64MB cache
        conn.execute("PRAGMA temp_store=MEMORY")        # Temp tables в памяти
        conn.execute("PRAGMA mmap_size=268435456")      # Memory-mapped I/O (256MB)
        
        return conn
    
    def get_connection(self) -> sqlite3.Connection:
        """Получить соединение из пула"""
        try:
            conn = self._pool.get(timeout=5.0)
            return conn
        except Empty:
            # Пул исчерпан - создаём новое соединение
            return self._create_connection()
    
    def return_connection(self, conn: sqlite3.Connection):
        """Вернуть соединение в пул"""
        try:
            self._pool.put_nowait(conn)
        except:
            # Пул полон - закрываем соединение
            conn.close()
    
    def close_all(self):
        """Закрыть все соединения в пуле"""
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except Empty:
                break


# Глобальный пул соединений
_pool: Optional[ConnectionPool] = None


def get_pool() -> ConnectionPool:
    """Получить или создать пул соединений"""
    global _pool
    if _pool is None:
        _pool = ConnectionPool()
    return _pool


@contextmanager
def get_db():
    """
    Контекстный менеджер для подключения к БД.
    Использует connection pooling для оптимизации.
    """
    pool = get_pool()
    conn = pool.get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.return_connection(conn)


def init_db():
    """Инициализация базы данных с оптимизациями"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Таблица пользователей панели
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        
        # Проверяем, есть ли колонка is_active (для миграции старых БД)
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'is_active' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1")
        
        # Таблица сессий (для отслеживания активных сессий)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        # ОПТИМИЗАЦИЯ: Создаём индексы для часто используемых запросов
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
        
        # Создаём администратора по умолчанию если нет пользователей
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            admin_hash = get_password_hash("admin")
            cursor.execute(
                "INSERT INTO users (username, password_hash, is_admin, is_active) VALUES (?, ?, ?, ?)",
                ("admin", admin_hash, True, True)
            )
            print("✓ Создан пользователь admin с паролем 'admin' - ОБЯЗАТЕЛЬНО смените!")


# Кэш пользователей для уменьшения запросов к БД
_user_cache: Dict[str, tuple] = {}  # {username: (user_dict, timestamp)}
_user_cache_by_id: Dict[int, tuple] = {}  # {id: (user_dict, timestamp)}
_cache_ttl = 60  # Время жизни кэша в секундах
_cache_lock = threading.Lock()


def _cache_get(cache: Dict, key: Any) -> Optional[dict]:
    """Получить значение из кэша с проверкой TTL"""
    if key in cache:
        user, ts = cache[key]
        if time.time() - ts < _cache_ttl:
            return user.copy()  # Возвращаем копию чтобы избежать мутаций
    return None


def _cache_set(cache: Dict, key: Any, value: dict):
    """Установить значение в кэш"""
    with _cache_lock:
        cache[key] = (value.copy(), time.time())


def _cache_invalidate(username: str = None, user_id: int = None):
    """Инвалидация кэша"""
    with _cache_lock:
        if username and username in _user_cache:
            del _user_cache[username]
        if user_id and user_id in _user_cache_by_id:
            del _user_cache_by_id[user_id]


class UserDB:
    """Класс для работы с пользователями панели (с кэшированием)"""
    
    @staticmethod
    def get_user(username: str) -> Optional[dict]:
        """Получить пользователя по имени (с кэшированием)"""
        # Проверяем кэш
        cached = _cache_get(_user_cache, username)
        if cached:
            return cached
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                user = dict(row)
                _cache_set(_user_cache, username, user)
                _cache_set(_user_cache_by_id, user['id'], user)
                return user
            return None
    
    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[dict]:
        """Получить пользователя по ID (с кэшированием)"""
        # Проверяем кэш
        cached = _cache_get(_user_cache_by_id, user_id)
        if cached:
            return cached
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if row:
                user = dict(row)
                _cache_set(_user_cache_by_id, user_id, user)
                _cache_set(_user_cache, user['username'], user)
                return user
            return None
    
    @staticmethod
    def authenticate(username: str, password: str) -> Optional[dict]:
        """Аутентификация пользователя"""
        user = UserDB.get_user(username)
        if user and user.get('is_active', True) and verify_password(password, user["password_hash"]):
            # Обновляем время последнего входа (не блокирующе)
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user["id"],)
                )
            # Инвалидируем кэш для обновления last_login
            _cache_invalidate(username=username, user_id=user["id"])
            return user
        return None
    
    @staticmethod
    def create_user(username: str, password: str, is_admin: bool = False) -> bool:
        """Создать нового пользователя"""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                    (username, get_password_hash(password), is_admin)
                )
            return True
        except sqlite3.IntegrityError:
            return False
    
    @staticmethod
    def change_password(user_id: int, new_password: str) -> bool:
        """Изменить пароль пользователя"""
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Получаем имя пользователя для инвалидации кэша
            cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            username = row[0] if row else None
            
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (get_password_hash(new_password), user_id)
            )
            success = cursor.rowcount > 0
            if success:
                _cache_invalidate(user_id=user_id, username=username)
            return success
    
    @staticmethod
    def delete_user(user_id: int) -> bool:
        """Удалить пользователя"""
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Получаем имя пользователя для инвалидации кэша
            cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            username = row[0] if row else None
            
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            success = cursor.rowcount > 0
            if success:
                _cache_invalidate(user_id=user_id, username=username)
            return success
    
    @staticmethod
    def update_user(user_id: int, updates: dict) -> bool:
        """Обновить данные пользователя (оптимизировано - один запрос)"""
        if not updates:
            return True
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Собираем обновления в один запрос
            set_clauses = []
            params = []
            
            if 'password' in updates:
                set_clauses.append("password_hash = ?")
                params.append(get_password_hash(updates['password']))
            
            if 'is_admin' in updates:
                set_clauses.append("is_admin = ?")
                params.append(updates['is_admin'])
            
            if 'is_active' in updates:
                set_clauses.append("is_active = ?")
                params.append(updates['is_active'])
            
            if set_clauses:
                params.append(user_id)
                query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?"
                cursor.execute(query, params)
                _cache_invalidate(user_id=user_id)
            
            return True
    
    @staticmethod
    def toggle_user_active(user_id: int) -> Optional[bool]:
        """Переключить активность пользователя"""
        user = UserDB.get_user_by_id(user_id)
        if not user:
            return None
        
        new_state = not user.get('is_active', True)
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET is_active = ? WHERE id = ?",
                (new_state, user_id)
            )
        _cache_invalidate(user_id=user_id)
        return new_state
    
    @staticmethod
    def toggle_user_admin(user_id: int) -> Optional[bool]:
        """Переключить роль админа"""
        user = UserDB.get_user_by_id(user_id)
        if not user:
            return None
        
        new_state = not user.get('is_admin', False)
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET is_admin = ? WHERE id = ?",
                (new_state, user_id)
            )
        _cache_invalidate(user_id=user_id)
        return new_state
    
    @staticmethod
    def get_all_users() -> list:
        """Получить всех пользователей"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, is_admin, is_active, created_at, last_login FROM users")
            return [dict(row) for row in cursor.fetchall()]
