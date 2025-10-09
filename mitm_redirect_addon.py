from mitmproxy import http, ctx
import os

COOKIE = "mitm_redirect_done"
FORCE_FLAG = r"C:\temp\mitm_force_redirect"
ONE_SHOT_FLAG = r"C:\temp\mitm_reset_once"
REDIRECT_FILE = r"C:\mitm\redirect_target.txt"
LOG_PREFIX = "[MITM-REDIR]"

def log(msg):
    ctx.log.info(f"{LOG_PREFIX} {msg}")

def get_redirect_target():
    """Ð§Ð¸Ñ‚Ð°ÐµÑ‚ Ñ†ÐµÐ»ÐµÐ²Ð¾Ð¹ URL Ð¸Ð· Ñ„Ð°Ð¹Ð»Ð°"""
    try:
        if os.path.exists(REDIRECT_FILE):
            with open(REDIRECT_FILE, 'r') as f:
                target = f.read().strip()
                if target:
                    return target
        log("No redirect target found in file, using default")
        return "https://bbc.com"  # fallback
    except Exception as e:
        log(f"Error reading redirect target: {e}")
        return "https://bbc.com"  # fallback

def should_force():
    return os.path.exists(FORCE_FLAG)

def should_one_shot():
    return os.path.exists(ONE_SHOT_FLAG)

def remove_one_shot_flag():
    try:
        if os.path.exists(ONE_SHOT_FLAG):
            os.remove(ONE_SHOT_FLAG)
            log("Global one-shot flag removed")
    except Exception as e:
        ctx.log.warn(f"{LOG_PREFIX} remove_one_shot_flag error: {e}")

def is_redirect_target(flow: http.HTTPFlow, redirect_target: str) -> bool:
    """ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÑ‚, Ð¸Ð´Ñ‘Ñ‚ Ð»Ð¸ Ð·Ð°Ð¿Ñ€Ð¾Ñ Ðº ÑÐ°Ð¼Ð¾Ð¼Ñƒ redirect_target"""
    try:
        if not redirect_target:
            return False
        req_url = flow.request.pretty_url.lower()
        target_url = redirect_target.lower().rstrip("/")
        return req_url.startswith(target_url)
    except Exception:
        return False

def request(flow: http.HTTPFlow) -> None:
    host = (flow.request.pretty_host or "").lower()
    path = flow.request.path or "/"
    client = getattr(getattr(flow, "client_conn", None), "peername", None)

    # ÐŸÐ¾Ð»ÑƒÑ‡Ð°ÐµÐ¼ Ñ†ÐµÐ»ÐµÐ²Ð¾Ð¹ URL Ð¸Ð· Ñ„Ð°Ð¹Ð»Ð°
    redirect_target = get_redirect_target()

    # ÐŸÑ€Ð¾Ð²ÐµÑ€ÑÐµÐ¼, Ð½Ðµ ÑÐ°Ð¼ Ð»Ð¸ ÑÑ‚Ð¾ redirect_target
    if is_redirect_target(flow, redirect_target):
        log(f"skip redirect for target itself: {flow.request.pretty_url}")
        return

    log(f"incoming {host}{path} client={client}")

    # Ð¡Ð¿Ð¸ÑÐ¾Ðº Ð´Ð¾Ð¼ÐµÐ½Ð¾Ð² Ð´Ð»Ñ Ð¿ÐµÑ€ÐµÑ…Ð²Ð°Ñ‚Ð°
    target_domains = ["admin.booking.com", "bbc.com"]

    for domain in target_domains:
        if host.endswith(domain.lower()):
            if should_force():
                log(f"FORCE redirect {host}{path} -> {redirect_target}")
                flow.response = http.Response.make(302, b"", {"Location": redirect_target})
                return

            if should_one_shot():
                log(f"GLOBAL ONE-SHOT redirect {host}{path} -> {redirect_target}")
                flow.response = http.Response.make(
                    302, b"", {
                        "Location": redirect_target,
                        "Set-Cookie": f"{COOKIE}=1; Path=/; Secure; HttpOnly"
                    }
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
            flow.response = http.Response.make(
                302, b"", {
                    "Location": redirect_target,
                    "Set-Cookie": f"{COOKIE}=1; Path=/; Secure; HttpOnly"
                }
            )
            return