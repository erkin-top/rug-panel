#!/usr/bin/env python3
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
Точка входа для запуска Rug-Panel
"""
import uvicorn
from app.config import HOST, PORT, DEBUG

if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║           🔐 Rug-Panel v1.4.3                         ║
    ║      Легковесная панель управления WireGuard VPN      ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(
        "app.main:app",
        host=HOST,
        port=PORT,
        reload=DEBUG,
        access_log=True,
        proxy_headers=True, # Включаем обработку заголовков прокси
        forwarded_allow_ips="*" # Разрешаем заголовки от любых IP (в контейнере это безопасно, т.к. внешний доступ контролируется)
    )
