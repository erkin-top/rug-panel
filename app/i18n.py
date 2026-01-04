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
Модуль интернационализации (i18n) для Rug-Panel
Обеспечивает поддержку многоязычности интерфейса

ОПТИМИЗАЦИИ:
- LRU кэш для загруженных языков
- Lazy loading языковых файлов
- Thread-safe singleton pattern
"""
import json
import threading
from pathlib import Path
from functools import lru_cache
from typing import Dict, Any, Optional

from app.config import LANGUAGE


class I18n:
    """
    Класс для управления переводами интерфейса.
    Singleton с thread-safe инициализацией.
    """
    _instance = None
    _lock = threading.Lock()
    _translations: Dict[str, Dict[str, Any]] = {}
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            self._languages_dir = Path(__file__).parent / "languages"
            self._current_language = LANGUAGE
            self._load_language(self._current_language)
    
    @lru_cache(maxsize=10)
    def _load_language_file(self, language: str) -> Dict[str, Any]:
        """
        Загрузка языкового файла с кэшированием.
        
        Args:
            language: Код языка (ru, en)
            
        Returns:
            Словарь с переводами
        """
        lang_file = self._languages_dir / f"{language}.json"
        
        if not lang_file.exists():
            # Fallback на русский, если язык не найден
            lang_file = self._languages_dir / "ru.json"
            if not lang_file.exists():
                return {}
        
        try:
            with open(lang_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠ Ошибка загрузки языка {language}: {e}")
            return {}
    
    def _load_language(self, language: str):
        """Загрузка языка в память"""
        if language not in self._translations:
            self._translations[language] = self._load_language_file(language)
    
    def set_language(self, language: str):
        """
        Установка текущего языка.
        
        Args:
            language: Код языка (ru, en)
        """
        self._current_language = language
        self._load_language(language)
    
    def get(self, key: str, language: Optional[str] = None, **kwargs) -> str:
        """
        Получение перевода по ключу.
        
        Args:
            key: Ключ перевода (например, "nav.clients" или "dashboard.title")
            language: Код языка (если None - используется текущий)
            **kwargs: Параметры для форматирования строки
            
        Returns:
            Переведённая строка
        """
        lang = language or self._current_language
        
        # Загрузка языка, если ещё не загружен
        if lang not in self._translations:
            self._load_language(lang)
        
        translations = self._translations.get(lang, {})
        
        # Навигация по вложенным ключам (например, "nav.clients")
        keys = key.split('.')
        value = translations
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                value = None
                break
        
        # Если перевод не найден, возвращаем ключ
        if value is None:
            return key
        
        # Форматирование строки, если переданы параметры
        if kwargs and isinstance(value, str):
            try:
                return value.format(**kwargs)
            except (KeyError, ValueError):
                return value
        
        return value
    
    def get_all(self, language: Optional[str] = None) -> Dict[str, Any]:
        """
        Получение всех переводов для языка.
        
        Args:
            language: Код языка (если None - используется текущий)
            
        Returns:
            Словарь со всеми переводами
        """
        lang = language or self._current_language
        
        if lang not in self._translations:
            self._load_language(lang)
        
        return self._translations.get(lang, {})
    
    @property
    def current_language(self) -> str:
        """Получение текущего языка"""
        return self._current_language
    
    @property
    def available_languages(self) -> list:
        """Список доступных языков"""
        if not self._languages_dir.exists():
            return []
        
        return [
            f.stem for f in self._languages_dir.glob("*.json")
        ]


# Создание singleton экземпляра
_i18n_instance = I18n()


def get_i18n() -> I18n:
    """
    Получение экземпляра I18n (для использования в DI).
    
    Returns:
        Singleton экземпляр I18n
    """
    return _i18n_instance


def t(key: str, **kwargs) -> str:
    """
    Быстрый доступ к переводам.
    
    Args:
        key: Ключ перевода
        **kwargs: Параметры для форматирования
        
    Returns:
        Переведённая строка
    """
    return _i18n_instance.get(key, **kwargs)


def get_translations(language: Optional[str] = None) -> Dict[str, Any]:
    """
    Получение всех переводов для использования в шаблонах.
    
    Args:
        language: Код языка (если None - используется текущий)
        
    Returns:
        Словарь со всеми переводами
    """
    return _i18n_instance.get_all(language)
