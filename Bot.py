import os
import re
import sys
import asyncio
import logging
import ipaddress
import socket
import html

from urllib.parse import urlparse, urljoin, urldefrag
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import Message
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties

import httpx


# ==========================================
# CONFIGURATION
# ==========================================

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()

BOT_NAME = "Link Bypasser Bot"
DEVELOPER = "Gobinda"

REQUEST_TIMEOUT = 15
MAX_REDIRECTS = 15
MAX_HTML_HOPS = 5

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
)


# ==========================================
# SHORTENER HOSTS
# ==========================================

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy",
    "shorte.st", "adf.ly", "bc.vc",
    "ouo.io", "ouo.press", "shrinkme.io",
    "shrinkearn.com", "linkshrink.net",
    "adfoc.us", "za.gl", "za.uy",
    "gplinks.co", "gplinks.in", "droplink.co",
    "yoshort.in", "clk.sh", "clicksfly.com",
    "try2link.com", "arolinks.com",
    "indianshortner.in", "urlshortx.com",
    "tnlink.in", "omg10.com", "gtlink.co",
    "filesdl.in", "filesdl.top",
    "filesdl.xyz", "filesdl.net",
}


# ==========================================
# REGEX
# ==========================================

URL_REGEX = re.compile(
    r'https?://[^\s<>"\']+',
    re.IGNORECASE
)

HTML_PATTERNS = [

    re.compile(
        r'<meta[^>]+http-equiv=["\']refresh["\']'
        r'[^>]+content=["\'][^;]*;\s*url=([^"\']+)["\']',
        re.I
    ),

    re.compile(
        r'url\s*[:=]\s*["\'](https?://[^"\']+)["\']',
        re.I
    ),

    re.compile(
        r'href\s*=\s*["\'](https?://[^"\']+)["\']',
        re.I
    ),

    re.compile(
        r'data-(?:url|href|link|target)\s*=\s*["\']([^"\']+)["\']',
        re.I
    ),

    re.compile(
        r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        re.I
    ),

    re.compile(
        r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
        re.I
    ),
]


# ==========================================
# LOGGING
# ==========================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)

dp = Dispatcher()


# ==========================================
# URL VALIDATION
# ==========================================

def normalize_url(url):

    url = url.strip().rstrip(".,!?;:)")

    if not url.startswith(("http://", "https://")):
        raise ValueError("Only HTTP and HTTPS links are supported.")

    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError("Invalid URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not supported.")

    return url


def is_public_host(host):

    try:
        ip = ipaddress.ip_address(host)

        return ip.is_global

    except ValueError:
        pass

    try:
        addresses = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM
        )

        return bool(addresses) and all(
            ipaddress.ip_address(item[4][0]).is_global
            for item in addresses
        )

    except Exception:
        return False


def check_safe_url(url):

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Unsupported URL scheme.")

    if not parsed.hostname or not is_public_host(parsed.hostname):
        raise ValueError("Private or non-public destination blocked.")


# ==========================================
# URL HELPERS
# ==========================================

def extract_urls(text):

    return URL_REGEX.findall(text or "")


def is_shortener_host(host):

    host = (host or "").lower().rstrip(".")

    if host.startswith("www."):
        host = host[4:]

    return any(
        host == domain or host.endswith("." + domain)
        for domain in SHORTENER_HOSTS
    )


# ==========================================
# HTTP REDIRECT RESOLVER
# ==========================================

async def http_resolve(client, url):

    chain = [url]
    current = url

    for _ in range(MAX_REDIRECTS):

        check_safe_url(current)

        try:

            response = await client.get(
                current,
                follow_redirects=False
            )

            if response.status_code not in (
                301, 302, 303, 307, 308
            ):
                return current, chain, None

            location = response.headers.get("Location")

            if not location:
                return current, chain, None

            next_url = urljoin(current, location)

            next_url = normalize_url(next_url)

            if next_url in chain:
                return current, chain, "Redirect loop detected."

            current = next_url
            chain.append(current)

        except httpx.TimeoutException:
            return current, chain, "Request timed out."

        except Exception as e:
            return current, chain, str(e)

    return current, chain, "Maximum redirect limit reached."


# ==========================================
# HTML LINK EXTRACTION
# ==========================================

async def find_embedded_link(client, url):

    try:

        check_safe_url(url)

        response = await client.get(url)

        if response.status_code != 200:
            return None

        content_type = response.headers.get(
            "content-type", ""
        ).lower()

        if not (
            "text/html" in content_type
            or "application/xhtml+xml" in content_type
        ):
            return None

        if len(response.content) > 2_000_000:
            return None

        html_content = response.text

        candidates = []

        for pattern in HTML_PATTERNS:

            for match in pattern.findall(html_content):

                candidate = match.strip().replace("\\/", "/")

                candidate = urljoin(
                    str(response.url),
                    candidate
                )

                try:
                    candidate = normalize_url(candidate)
                    check_safe_url(candidate)

                    if candidate != url:
                        candidates.append(candidate)

                except ValueError:
                    continue

        # Remove duplicates

        candidates = list(dict.fromkeys(candidates))

        # Prefer non-shortener URLs

        for candidate in candidates:

            host = urlparse(candidate).hostname

            if not is_shortener_host(host):
                return candidate

        return candidates[0] if candidates else None

    except Exception as e:

        logger.error(
            "HTML extraction error: %s",
            e
        )

        return None


# ==========================================
# SMART BYPASS
# ==========================================

async def smart_bypass(url):

    chain = [url]
    current = url

    try:

        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            headers={
                "User-Agent": USER_AGENT
            },
            follow_redirects=False,
            trust_env=False
        ) as client:

            # Stage 1: HTTP redirects

            current, http_chain, error = await http_resolve(
                client,
                current
            )

            chain.extend(http_chain[1:])

            if error:
                return current, chain, error

            # Stage 2: HTML extraction

            for _ in range(MAX_HTML_HOPS):

                host = urlparse(current).hostname

                if not is_shortener_host(host):
                    break

                embedded = await find_embedded_link(
                    client,
                    current
                )

                if not embedded or embedded == current:
                    break

                current, inner_chain, error = await http_resolve(
                    client,
                    embedded
                )

                chain.extend(inner_chain[1:])

                if error:
                    return current, chain, error

            # Remove tracking query and fragment

            parsed = urlparse(current)

            cleaned = parsed._replace(
                query="",
                fragment=""
            ).geturl()

            return cleaned, chain, None

    except Exception as e:

        return current, chain, str(e)


# ==========================================
# TELEGRAM START
# ==========================================

@dp.message(Command("start"))
async def cmd_start(message: Message):

    await message.answer(

        f"🔗 <b>{BOT_NAME}</b>\n"
        f"👨‍💻 Developer: <b>{html.escape(DEVELOPER)}</b>\n\n"

        "Send a supported short link to resolve it.\n\n"

        "<b>Commands:</b>\n"
        "/resolve &lt;url&gt; - Resolve link\n"
        "/hosts - Supported hosts\n"
        "/help - Bot information",

        parse_mode=ParseMode.HTML
    )


# ==========================================
# HELP
# ==========================================

@dp.message(Command("help"))
async def cmd_help(message: Message):

    await message.answer(

        "<b>LINK BYPASSER HELP</b>\n\n"

        "Supported operations:\n"
        "1. HTTP redirects\n"
        "2. Meta Refresh redirects\n"
        "3. HTML link extraction\n"
        "4. Basic JavaScript redirect patterns\n\n"

        "Usage:\n"
        "<code>/resolve https://example.com</code>\n\n"

        "Note: CAPTCHA, login-protected pages and "
        "JavaScript execution are not supported.",

        parse_mode=ParseMode.HTML
    )


# ==========================================
# HOSTS
# ==========================================

@dp.message(Command("hosts"))
async def cmd_hosts(message: Message):

    hosts = "\n".join(
        f"• <code>{html.escape(host)}</code>"
        for host in sorted(SHORTENER_HOSTS)
    )

    await message.answer(

        f"<b>SUPPORTED HOSTS ({len(SHORTENER_HOSTS)})</b>\n\n"
        f"{hosts}",

        parse_mode=ParseMode.HTML
    )


# ==========================================
# RESOLVE COMMAND
# ==========================================

@dp.message(Command("resolve"))
async def cmd_resolve(message: Message):

    parts = (message.text or "").split(maxsplit=1)

    if len(parts) < 2:

        await message.answer(
            "Usage: <code>/resolve https://example.com</code>",
            parse_mode=ParseMode.HTML
        )

        return

    urls = extract_urls(parts[1])

    if not urls:

        await message.answer("Invalid URL.")
        return

    await process_url(message, urls[0])


# ==========================================
# NORMAL MESSAGE
# ==========================================

@dp.message(F.text)
async def handle_message(message: Message):

    urls = extract_urls(message.text)

    if not urls:

        await message.answer(
            "🔗 Send a link to resolve."
        )

        return

    await process_url(message, urls[0])


# ==========================================
# PROCESS URL
# ==========================================

async def process_url(message: Message, url: str):

    try:

        url = normalize_url(url)

        check_safe_url(url)

    except ValueError as e:

        await message.answer(
            f"❌ {html.escape(str(e))}"
        )

        return

    status = await message.answer(
        "⏳ <b>Resolving link...</b>",
        parse_mode=ParseMode.HTML
    )

    final, chain, error = await smart_bypass(url)

    safe_original = html.escape(url)
    safe_final = html.escape(final)

    if error:

        await status.edit_text(

            "❌ <b>Resolution failed</b>\n\n"
            f"Original: <code>{safe_original}</code>\n"
            f"Reason: {html.escape(error)}",

            parse_mode=ParseMode.HTML
        )

        return

    chain_text = ""

    if len(chain) > 1:

        chain_text = "\n\n<b>Redirect Chain:</b>\n"

        for index, item in enumerate(chain[:12], 1):

            chain_text += (
                f"{index}. <code>"
                f"{html.escape(item)}"
                f"</code>\n"
            )

    if final == url:

        note = (
            "\n⚠️ No redirect detected. "
            "The server may have blocked the request."
        )

    elif is_shortener_host(urlparse(final).hostname):

        note = (
            "\n⚠️ Still on a shortener. "
            "Further resolution may require browser interaction."
        )

    else:

        note = ""

    await status.edit_text(

        "✅ <b>LINK RESOLVED</b>\n\n"

        f"🔗 <b>Original:</b>\n<code>{safe_original}</code>\n\n"

        f"🎯 <b>Final URL:</b>\n<code>{safe_final}</code>"

        f"{chain_text}"

        f"\n{note}\n\n"

        f"<i>Developed by {html.escape(DEVELOPER)}</i>",

        parse_mode=ParseMode.HTML
    )

    logger.info(
        "Resolved: %s -> %s",
        url,
        final
    )


# ==========================================
# MAIN
# ==========================================

async def main():

    if not BOT_TOKEN:

        logger.error("BOT_TOKEN is missing!")

        sys.exit(1)

    bot = Bot(

        token=BOT_TOKEN,

        default=DefaultBotProperties(
            parse_mode=ParseMode.HTML
        )

    )

    try:

        me = await bot.get_me()

        logger.info(
            "Bot started: @%s",
            me.username
        )

        print("=" * 40)
        print(BOT_NAME)
        print("Developer:", DEVELOPER)
        print("Username:", me.username)
        print("Status: RUNNING")
        print("=" * 40)

        await dp.start_polling(bot)

    finally:

        await bot.session.close()


if __name__ == "__main__":

    try:

        asyncio.run(main())

    except KeyboardInterrupt:

        print("Bot stopped.")