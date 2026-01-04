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
Роуты настройки сервера WireGuard
"""
from fastapi import APIRouter, Request, Form, Depends, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pathlib import Path
from datetime import datetime
import subprocess
import shutil
import os
import re
import ipaddress

from app.auth import require_auth, require_admin
from app.wireguard import WGManager, WGKeyGenerator, WGConfigParser, WGConfigWriter
from app.config import (
    WG_CONFIG_PATH,
    WG_INTERFACE,
    DATA_DIR,
    PANEL_VERSION,
    WG_SERVER_ENDPOINT,
    DEFAULT_WAN_INTERFACE,
    DEFAULT_VPN_ADDRESS,
)
from app.dependencies import templates, get_wg_manager, alert_response

router = APIRouter(prefix="/server", tags=["server"])


def detect_default_interface() -> str:
    """Определение основного сетевого интерфейса"""
    try:
        # Для Linux
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=True
        )
        # Формат: "default via X.X.X.X dev eth0 ..."
        match = re.search(r'dev\s+(\S+)', result.stdout)
        if match:
            return match.group(1)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Fallback
    return DEFAULT_WAN_INTERFACE


def _vpn_network_from_address(address: str) -> str:
    """Определить VPN сеть (CIDR) из поля Address.

    Address может быть:
    - "10.0.0.1/24"
    - "10.0.0.1/24, fd00::1/64" (через запятую)
    """
    candidates = [a.strip() for a in (address or "").split(",") if a.strip()]
    if not candidates:
        candidates = [DEFAULT_VPN_ADDRESS]

    for candidate in candidates:
        try:
            iface = ipaddress.ip_interface(candidate)
            # Для NAT используем только IPv4 сеть
            if isinstance(iface.ip, ipaddress.IPv4Address):
                return str(iface.network)
        except ValueError:
            continue

    # Последний fallback
    try:
        return str(ipaddress.ip_interface(DEFAULT_VPN_ADDRESS).network)
    except Exception:
        return "10.0.0.0/24"


def detect_server_ip() -> str:
    """Определение внешнего IP сервера
    
    Приоритет: WG_SERVER_ENDPOINT из env > автодетект IP
    Если WG_SERVER_ENDPOINT задан - он НЕ будет затираться автодетектом
    """
    # ENV переменная имеет наивысший приоритет
    if WG_SERVER_ENDPOINT:
        return WG_SERVER_ENDPOINT
    
    try:
        result = subprocess.run(
            ["curl", "-s", "ifconfig.me"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except:
        pass
    
    try:
        result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            ips = result.stdout.strip().split()
            if ips:
                return ips[0]
    except:
        pass
    
    return "YOUR_SERVER_IP"


def generate_postup_postdown(
    interface: str,
    vpn_network: str,
    enable_nat: bool = True,
    enable_forwarding: bool = True,
    client_isolation: bool = False
) -> tuple:
    """Генерация PostUp/PostDown правил iptables
    
    ВАЖНО: Логика построена на ЯВНОЙ блокировке по умолчанию.
    
    Режимы работы сервера:
    - Без NAT и Forwarding: клиенты имеют доступ только к серверу (весь форвард заблокирован)
    - NAT включен: клиенты выходят в интернет через сервер
    - Forwarding включен: клиенты видят друг друга в VPN сети
    - NAT + Forwarding: полный доступ в интернет и друг к другу
    
    Принцип работы:
    1. Сначала удаляем все старые правила WG (для чистого состояния)
    2. Добавляем базовое правило DROP для всего форварда от/к WG
    3. Добавляем ACCEPT правила ПЕРЕД DROP для разрешённых режимов
    """
    postup_rules = []
    postdown_rules = []
    
    # ========== PostUp ==========
    # Шаг 1: Очистка старых правил (игнорируем ошибки если правил нет)
    # Удаляем возможные старые ACCEPT правила
    postup_rules.append(f"iptables -D FORWARD -i %i -o {interface} -j ACCEPT 2>/dev/null || true")
    postup_rules.append(f"iptables -D FORWARD -i {interface} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true")
    postup_rules.append(f"iptables -D FORWARD -i %i -o %i -j ACCEPT 2>/dev/null || true")
    # Удаляем возможные старые DROP правила
    postup_rules.append(f"iptables -D FORWARD -i %i -j DROP 2>/dev/null || true")
    postup_rules.append(f"iptables -D FORWARD -o %i -j DROP 2>/dev/null || true")
    # Удаляем старый NAT
    postup_rules.append(f"iptables -t nat -D POSTROUTING -s {vpn_network} -o {interface} -j MASQUERADE 2>/dev/null || true")
    
    # Шаг 2: Добавляем ACCEPT правила для разрешённых режимов (ПЕРЕД DROP!)
    if enable_nat:
        # NAT для выхода в интернет (только для VPN подсети)
        postup_rules.append(f"iptables -t nat -A POSTROUTING -s {vpn_network} -o {interface} -j MASQUERADE")
        # Разрешаем форвардинг от WG к внешнему интерфейсу
        postup_rules.append(f"iptables -I FORWARD 1 -i %i -o {interface} -j ACCEPT")
        # Разрешаем обратный трафик (ответы)
        postup_rules.append(f"iptables -I FORWARD 1 -i {interface} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT")
    
    if enable_forwarding:
        # Разрешаем форвардинг между клиентами WG (wg0 -> wg0)
        postup_rules.append(f"iptables -I FORWARD 1 -i %i -o %i -j ACCEPT")
    
    # Шаг 3: Добавляем базовые DROP правила В КОНЕЦ цепочки (блокируют всё остальное)
    postup_rules.append(f"iptables -A FORWARD -i %i -j DROP")
    postup_rules.append(f"iptables -A FORWARD -o %i -j DROP")
    
    # ========== PostDown ==========
    # Удаляем все правила при остановке WG
    if enable_nat:
        postdown_rules.append(f"iptables -t nat -D POSTROUTING -s {vpn_network} -o {interface} -j MASQUERADE 2>/dev/null || true")
        postdown_rules.append(f"iptables -D FORWARD -i %i -o {interface} -j ACCEPT 2>/dev/null || true")
        postdown_rules.append(f"iptables -D FORWARD -i {interface} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true")
    
    if enable_forwarding:
        postdown_rules.append(f"iptables -D FORWARD -i %i -o %i -j ACCEPT 2>/dev/null || true")
    
    # Удаляем DROP правила
    postdown_rules.append(f"iptables -D FORWARD -i %i -j DROP 2>/dev/null || true")
    postdown_rules.append(f"iptables -D FORWARD -o %i -j DROP 2>/dev/null || true")
    
    postup = "; ".join(postup_rules) if postup_rules else ""
    postdown = "; ".join(postdown_rules) if postdown_rules else ""
    
    return postup, postdown


def parse_server_mode(interface_config: dict) -> dict:
    """Анализ текущего режима работы сервера
    
    Сначала проверяем явно сохранённые метаданные, затем анализируем PostUp.
    
    Определяет:
    - enable_nat: есть ли MASQUERADE правило
    - enable_forwarding: есть ли правило для клиент-клиент форварда
    - network_interface: интерфейс для NAT
    """
    mode = {
        'enable_nat': True,  # По умолчанию включено
        'enable_forwarding': True,  # По умолчанию включено
        'network_interface': DEFAULT_WAN_INTERFACE
    }
    
    # 1. Проверяем явно сохранённые метаданные (приоритет)
    if '_enable_nat' in interface_config:
        mode['enable_nat'] = interface_config['_enable_nat'] == 'true'
    if '_enable_forwarding' in interface_config:
        mode['enable_forwarding'] = interface_config['_enable_forwarding'] == 'true'
    if '_network_interface' in interface_config:
        mode['network_interface'] = interface_config['_network_interface']
        return mode  # Если есть метаданные, доверяем им
    
    # 2. Fallback: анализируем PostUp правила
    postup = interface_config.get('PostUp', '')
    if not postup:
        return mode
    
    # Определяем сетевой интерфейс из NAT правил
    nat_match = re.search(r'-o\s+([\w+]+)\s+-j\s+MASQUERADE', postup)
    if nat_match:
        iface = nat_match.group(1)
        if iface != 'eth+':
            mode['network_interface'] = iface
        mode['enable_nat'] = True
    else:
        # Проверяем наличие DROP без NAT ACCEPT
        if 'FORWARD -i %i -j DROP' in postup and 'MASQUERADE' not in postup:
            mode['enable_nat'] = False
        # Попробуем найти интерфейс из FORWARD правил
        forward_match = re.search(r'FORWARD.*-i\s+%i\s+-o\s+([\w+]+)\s+-j\s+ACCEPT', postup)
        if forward_match:
            mode['network_interface'] = forward_match.group(1)
    
    # Проверяем forwarding между клиентами (wg -> wg)
    if '-i %i -o %i -j ACCEPT' in postup:
        mode['enable_forwarding'] = True
    elif 'FORWARD -i %i -j DROP' in postup and '-i %i -o %i -j ACCEPT' not in postup:
        mode['enable_forwarding'] = False
    
    return mode


@router.get("/settings", response_class=HTMLResponse)
async def server_settings_page(
    request: Request,
    user: dict = Depends(require_admin),
    wg: WGManager = Depends(get_wg_manager)
):
    """Страница настроек сервера WireGuard"""
    config_exists = Path(WG_CONFIG_PATH).exists()
    interface = {}
    server_mode = {}
    
    if config_exists:
        try:
            interface, _ = wg.load_config()
            # Анализируем режим работы (передаём весь interface для чтения метаданных)
            server_mode = parse_server_mode(interface)
        except Exception as e:
            interface = {'error': str(e)}
    
    # Определяем параметры системы
    detected_interface = detect_default_interface()
    detected_ip = detect_server_ip()
    
    # Проверяем, задана ли ENV переменная WG_SERVER_ENDPOINT
    env_endpoint_set = bool(WG_SERVER_ENDPOINT)
    
    return templates.TemplateResponse(request, "server_settings.html", {
        "user": user,
        "config_exists": config_exists,
        "config_path": str(WG_CONFIG_PATH),
        "wg_interface": WG_INTERFACE,
        "panel_version": PANEL_VERSION,
        "interface": interface,
        "server_mode": server_mode,
        "detected_interface": detected_interface,
        "detected_ip": detected_ip,
        "env_endpoint_set": env_endpoint_set,
        "env_endpoint_value": WG_SERVER_ENDPOINT
    })


@router.post("/settings/update")
async def update_server_settings(
    request: Request,
    address: str = Form(...),
    listen_port: int = Form(...),
    dns: str = Form(""),
    network_interface: str = Form(DEFAULT_WAN_INTERFACE),
    enable_nat: bool = Form(False),
    enable_forwarding: bool = Form(False),
    server_endpoint: str = Form(""),
    postup: str = Form(""),
    postdown: str = Form(""),
    user: dict = Depends(require_admin),
    wg: WGManager = Depends(get_wg_manager)
):
    """Обновление настроек сервера"""
    try:
        interface, peers = wg.load_config()
        
        # Обновляем параметры интерфейса
        interface['Address'] = address
        interface['ListenPort'] = str(listen_port)
        
        if dns:
            interface['DNS'] = dns
        elif 'DNS' in interface:
            del interface['DNS']
        
        # Сохраняем состояние режимов в метаданных (для восстановления при загрузке)
        interface['_enable_nat'] = 'true' if enable_nat else 'false'
        interface['_enable_forwarding'] = 'true' if enable_forwarding else 'false'
        interface['_network_interface'] = network_interface
        
        # Определяем VPN сеть для NAT (убираем хардкод 10.0.0.0/24)
        vpn_network = _vpn_network_from_address(address)

        # Всегда генерируем PostUp/PostDown из чекбоксов
        # (игнорируем ручной ввод если он содержит автогенерированные правила)
        generated_postup, generated_postdown = generate_postup_postdown(
            interface=network_interface,
            vpn_network=vpn_network,
            enable_nat=enable_nat,
            enable_forwarding=enable_forwarding
        )
        
        # Проверяем, не ввёл ли пользователь полностью свои правила
        # (если postup не содержит наших маркеров "|| true" - это кастомные правила)
        # ВАЖНО: Игнорируем значения из формы если они совпадают с текущими в конфиге
        # (пользователь их не редактировал, это просто отражение старого состояния)
        current_postup = interface.get('PostUp', '')
        current_postdown = interface.get('PostDown', '')
        
        # Определяем, действительно ли пользователь вводил кастомные правила
        # (т.е. изменил значения в textarea И они не наши автогенерированные)
        user_edited_postup = postup.strip() and postup.strip() != current_postup
        user_edited_postdown = postdown.strip() and postdown.strip() != current_postdown
        
        is_custom_postup = user_edited_postup and '|| true' not in postup and 'iptables -D FORWARD' not in postup
        is_custom_postdown = user_edited_postdown and '|| true' not in postdown
        
        if is_custom_postup:
            interface['PostUp'] = postup.strip()
        elif generated_postup:
            interface['PostUp'] = generated_postup
        elif 'PostUp' in interface:
            del interface['PostUp']
            
        if is_custom_postdown:
            interface['PostDown'] = postdown.strip()
        elif generated_postdown:
            interface['PostDown'] = generated_postdown
        elif 'PostDown' in interface:
            del interface['PostDown']
        
        # Сохраняем endpoint в метаданных (для генерации клиентских конфигов)
        # НЕ сохраняем если задано через ENV (WG_SERVER_ENDPOINT имеет приоритет)
        if server_endpoint and not WG_SERVER_ENDPOINT:
            interface['_server_endpoint'] = server_endpoint
        
        wg.save_config(interface, peers)
        
        # Всегда пробуем применить конфиг при сохранении PostUp/PostDown
        # Это критично для применения правил iptables
        reload_success = False
        reload_error = None
        try:
            reload_success = wg.reload_config()
        except Exception as e:
            reload_error = str(e)
            print(f"Ошибка перезагрузки конфигурации: {e}")
        
        if reload_success:
            message = "Настройки сервера сохранены и применены! PostUp/PostDown правила активированы."
        else:
            error_hint = f" ({reload_error})" if reload_error else ""
            message = f"Настройки сохранены. Нажмите 'Применить конфиг' для активации PostUp/PostDown правил.{error_hint}"
        
        return alert_response(request, "success" if reload_success else "warning", message)
        
    except Exception as e:
        return alert_response(request, "error", f"Ошибка сохранения: {str(e)}")


@router.post("/start")
async def start_wireguard(
    request: Request,
    user: dict = Depends(require_admin)
):
    """Запуск интерфейса WireGuard"""
    try:
        result = subprocess.run(
            ["wg-quick", "up", WG_INTERFACE],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise Exception(result.stderr)
        
        return alert_response(request, "success", f"Интерфейс {WG_INTERFACE} запущен")
        
    except Exception as e:
        return alert_response(request, "error", f"Ошибка запуска: {str(e)}")


@router.post("/stop")
async def stop_wireguard(
    request: Request,
    user: dict = Depends(require_admin)
):
    """Остановка интерфейса WireGuard"""
    try:
        result = subprocess.run(
            ["wg-quick", "down", WG_INTERFACE],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise Exception(result.stderr)
        
        return templates.TemplateResponse(request, "components/alert.html", {
            "type": "success",
            "message": f"Интерфейс {WG_INTERFACE} остановлен"
        })
        
    except Exception as e:
        return alert_response(request, "error", f"Ошибка остановки: {str(e)}")


@router.post("/restart")
async def restart_wireguard(
    request: Request,
    user: dict = Depends(require_admin),
    wg: WGManager = Depends(get_wg_manager)
):
    """Перезапуск WireGuard с применением конфига"""
    try:
        success = wg.reload_config()
        
        if success:
            return alert_response(request, "success", "Конфигурация применена")
        else:
            raise Exception("Не удалось перезагрузить конфигурацию")
            
    except Exception as e:
        return alert_response(request, "error", f"Ошибка: {str(e)}")


@router.get("/backup", response_class=FileResponse)
async def download_backup(
    request: Request,
    user: dict = Depends(require_admin)
):
    """Скачивание бэкапа текущего конфига"""
    if not Path(WG_CONFIG_PATH).exists():
        raise HTTPException(status_code=404, detail="Конфиг не найден")
    
    # Создаём бэкап с timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"wg0_backup_{timestamp}.conf"
    backup_path = DATA_DIR / backup_name
    
    shutil.copy(WG_CONFIG_PATH, backup_path)
    
    return FileResponse(
        path=backup_path,
        filename=backup_name,
        media_type="application/octet-stream"
    )


@router.post("/import")
async def import_config(
    request: Request,
    config_file: UploadFile = File(...),
    create_backup: bool = Form(True),
    user: dict = Depends(require_admin)
):
    """Импорт конфигурации со старого сервера"""
    try:
        # Читаем загруженный файл
        content = await config_file.read()
        config_content = content.decode('utf-8')
        
        # Валидируем что это WireGuard конфиг
        if '[Interface]' not in config_content:
            raise ValueError("Неверный формат конфига WireGuard")
        
        # Создаём бэкап текущего конфига если он существует
        if create_backup and Path(WG_CONFIG_PATH).exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Path(WG_CONFIG_PATH).with_suffix(f'.conf.backup_{timestamp}')
            shutil.copy(WG_CONFIG_PATH, backup_path)
        
        # Записываем новый конфиг
        config_path = Path(WG_CONFIG_PATH)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(config_content, encoding='utf-8')
        
        # Устанавливаем права
        try:
            os.chmod(config_path, 0o600)
        except:
            pass
        
        # Парсим для подсчёта пиров
        parser = WGConfigParser(config_path)
        _, peers = parser.parse()
        
        return alert_response(request, "success", 
            f"Конфиг импортирован успешно! Найдено пиров: {len(peers)}")
        
    except Exception as e:
        return alert_response(request, "error", f"Ошибка импорта: {str(e)}")


@router.get("/status")
async def get_server_status(
    request: Request,
    user: dict = Depends(require_auth)
):
    """Получение статуса сервера WireGuard"""
    status = {
        'is_running': False,
        'interface': WG_INTERFACE,
        'config_exists': Path(WG_CONFIG_PATH).exists()
    }
    
    try:
        result = subprocess.run(
            ["wg", "show", WG_INTERFACE],
            capture_output=True,
            text=True
        )
        status['is_running'] = result.returncode == 0
        
        if status['is_running']:
            # Парсим вывод wg show
            for line in result.stdout.split('\n'):
                if 'listening port:' in line.lower():
                    status['listening_port'] = line.split(':')[-1].strip()
                elif 'public key:' in line.lower():
                    status['public_key'] = line.split(':')[-1].strip()
                    
    except FileNotFoundError:
        status['wg_installed'] = False
    
    return JSONResponse(status)


@router.get("/install", response_class=HTMLResponse)
async def install_config_page(
    request: Request,
    user: dict = Depends(require_admin)
):
    """Страница создания новой конфигурации WireGuard"""
    # Если конфиг уже существует, редирект на настройки
    if Path(WG_CONFIG_PATH).exists():
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/server/settings", status_code=303)
    
    # Определяем параметры системы
    detected_interface = detect_default_interface()
    detected_ip = detect_server_ip()
    
    return templates.TemplateResponse(request, "server_install.html", {
        "user": user,
        "detected_interface": detected_interface,
        "detected_ip": detected_ip,
        "default_vpn_address": DEFAULT_VPN_ADDRESS,
        "panel_version": PANEL_VERSION
    })


@router.post("/install")
async def create_initial_config(
    request: Request,
    address: str = Form(DEFAULT_VPN_ADDRESS),
    listen_port: int = Form(51820),
    network_interface: str = Form(DEFAULT_WAN_INTERFACE),
    enable_nat: bool = Form(True),
    enable_forwarding: bool = Form(True),
    user: dict = Depends(require_admin),
    wg: WGManager = Depends(get_wg_manager)
):
    """Создание начальной конфигурации WireGuard"""
    try:
        # Генерируем серверные ключи
        private_key = WGKeyGenerator.generate_private_key()
        public_key = WGKeyGenerator.get_public_key(private_key)
        
        # Определяем VPN сеть
        vpn_network = _vpn_network_from_address(address)
        
        # Генерируем PostUp/PostDown
        postup, postdown = generate_postup_postdown(
            interface=network_interface,
            vpn_network=vpn_network,
            enable_nat=enable_nat,
            enable_forwarding=enable_forwarding
        )
        
        # Формируем конфигурацию интерфейса
        interface = {
            'Address': address,
            'ListenPort': str(listen_port),
            'PrivateKey': private_key,
            '_enable_nat': 'true' if enable_nat else 'false',
            '_enable_forwarding': 'true' if enable_forwarding else 'false',
            '_network_interface': network_interface
        }
        
        if postup:
            interface['PostUp'] = postup
        if postdown:
            interface['PostDown'] = postdown
        
        # Сохраняем конфигурацию
        wg.save_config(interface, [])
        
        # Устанавливаем права
        try:
            os.chmod(WG_CONFIG_PATH, 0o600)
        except:
            pass
        
        return alert_response(request, "success", 
            f"Конфигурация создана! Публичный ключ сервера: {public_key[:16]}...")
        
    except Exception as e:
        return alert_response(request, "error", f"Ошибка создания конфига: {str(e)}")

