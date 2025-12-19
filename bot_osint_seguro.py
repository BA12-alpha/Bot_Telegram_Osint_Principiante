#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBERMENTOR BOT - VERSIÓN EDUCATIVA 11.0
- Bot educativo interactivo de ciberseguridad
- Sistema de progreso y seguimiento de usuarios
- Curriculum estructurado desde principiante a experto
- OSINT defensivo (IP, dominio, email, URL, DNS, SSL, subdominios, imagen, redes sociales…)
- Cifrado educativo (Fernet AES) y análisis de cadenas (/analyze)
- Menú dinámico con botones (/menu) y aspecto más profesional
"""

import os
import re
import json
import logging
import ipaddress
import urllib.parse
import hashlib
from datetime import datetime
from collections import defaultdict
from typing import Any, Dict, Optional

import base64
import io
import socket

import requests
import telebot
from telebot.types import (
    InlineKeyboardMarkup,
    InlineKeyboardButton,
)
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import dns.resolver
import whois
from PIL import Image, ExifTags
from cryptography.fernet import Fernet

# CyberMentor modules
from database import Database
from curriculum import Curriculum

# ===========================================================
# CARGA DE CONFIGURACIÓN
# ===========================================================

CONFIG_PATH = os.getenv("OSINT_BOT_CONFIG", "config.json")


def load_config(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"No se encontró {path}. Crea uno basado en config.example.json."
        )
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    if "telegram" not in cfg or not cfg["telegram"].get("bot_token"):
        raise ValueError("Falta 'telegram.bot_token' en config.json")

    cfg.setdefault("services", {})
    cfg.setdefault("settings", {})
    settings = cfg["settings"]

    settings.setdefault("results_dir", "./results")
    settings.setdefault("log_level", "INFO")
    settings.setdefault("max_history_per_user", 50)
    settings.setdefault("max_image_size_mb", 8)
    settings.setdefault("requests_timeout_seconds", 10)

    return cfg


CONFIG = load_config(CONFIG_PATH)

TELEGRAM_TOKEN = CONFIG["telegram"]["bot_token"]
URLSCAN_API_KEY = CONFIG["services"].get("urlscan_api_key", "").strip() or None

RESULTS_DIR = CONFIG["settings"]["results_dir"]
MAX_HISTORY_PER_USER = int(CONFIG["settings"]["max_history_per_user"])
MAX_IMAGE_SIZE_MB = float(CONFIG["settings"]["max_image_size_mb"])
REQUESTS_TIMEOUT = float(CONFIG["settings"]["requests_timeout_seconds"])

# ===========================================================
# LOGGING
# ===========================================================

LOG_LEVEL = CONFIG["settings"]["log_level"].upper()
if LOG_LEVEL not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
    LOG_LEVEL = "INFO"

logging.basicConfig(level=getattr(logging, LOG_LEVEL))
logger = logging.getLogger("ciberhackercito")

# ===========================================================
# ESTADO Y DIRECTORIOS
# ===========================================================

USER_HISTORY: Dict[int, list] = defaultdict(list)

os.makedirs(RESULTS_DIR, exist_ok=True)
try:
    os.chmod(RESULTS_DIR, 0o700)
except Exception:
    pass

REQUESTS_HEADERS = {"User-Agent": "CiberhackercitoOSINT/3.0 (+seguridad)"}

bot = telebot.TeleBot(TELEGRAM_TOKEN, parse_mode="Markdown")

# ===========================================================
# CYBERMENTOR INITIALIZATION
# ===========================================================

# Initialize database and curriculum
db = Database("cybermentor.db")
curriculum = Curriculum()

# User session states for interactive flows
user_states: Dict[int, Dict[str, Any]] = defaultdict(dict)

# ===========================================================
# UTILIDADES / SEGURIDAD
# ===========================================================


def clean_text(text: str) -> str:
    """Limpia y limita longitud; aquí lo usamos cuando no queremos Markdown."""
    return text.replace("`", "").replace("_", "").replace("*", "")[:3500]


def sanitize_domain(domain: str) -> str:
    domain = domain.strip()
    domain = domain.replace("https://", "").replace("http://", "").replace("www.", "")
    domain = domain.split("/")[0]

    if len(domain) > 253:
        raise ValueError("Dominio demasiado largo")
    if not re.match(r"^[A-Za-z0-9.-]{1,253}$", domain):
        raise ValueError("Dominio inválido")
    if ".." in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("Dominio inválido")
    return domain.lower()


def sanitize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("URL inválida")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Esquema no permitido")
    return url


def sanitize_username(username: str) -> str:
    username = username.strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,64}$", username):
        raise ValueError("Usuario inválido (solo letras, números, punto, guion, guion bajo, máx 64)")
    return username


def limited_requests_get(url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("timeout", REQUESTS_TIMEOUT)
    kwargs.setdefault("headers", REQUESTS_HEADERS)
    kwargs.setdefault("verify", True)
    return requests.get(url, **kwargs)


def limited_requests_head(url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("timeout", REQUESTS_TIMEOUT)
    kwargs.setdefault("headers", REQUESTS_HEADERS)
    kwargs.setdefault("verify", True)
    return requests.head(url, **kwargs)


def limited_requests_post(url: str, **kwargs) -> requests.Response:
    kwargs.setdefault("timeout", REQUESTS_TIMEOUT)
    kwargs.setdefault("headers", REQUESTS_HEADERS)
    kwargs.setdefault("verify", True)
    return requests.post(url, **kwargs)


def scrub_sensitive(data: Any) -> Any:
    sensitive_keys = {"password", "token", "secret", "hashes", "api_key", "authorization"}

    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            if k.lower() in sensitive_keys:
                out[k] = "***"
            else:
                out[k] = scrub_sensitive(v)
        return out
    if isinstance(data, list):
        return [scrub_sensitive(x) for x in data]
    return data


def save_result(data: Dict[str, Any], command: str, user_id: int) -> Optional[str]:
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_command = re.sub(r"[^A-Za-z0-9_-]", "_", command)[:30]
        filename = f"{safe_command}_{timestamp}.json"
        filepath = os.path.join(RESULTS_DIR, filename)

        safe_data = scrub_sensitive(data)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(safe_data, f, indent=2, ensure_ascii=False)

        target = (
            data.get("target")
            or data.get("email")
            or data.get("phone")
            or data.get("ip")
            or data.get("dominio")
            or "N/A"
        )

        USER_HISTORY[user_id].append(
            {
                "time": datetime.now().isoformat(),
                "command": command,
                "target": str(target)[:100],
                "file": filename,
            }
        )

        if len(USER_HISTORY[user_id]) > MAX_HISTORY_PER_USER:
            USER_HISTORY[user_id] = USER_HISTORY[user_id][-MAX_HISTORY_PER_USER:]

        return filepath
    except Exception as e:
        logger.error(f"Error guardando resultado: {e}")
        return None


# ===========================================================
# CIFRADO EDUCATIVO (FERNET)
# ===========================================================


def _derive_fernet_key_from_passphrase(passphrase: str) -> bytes:
    p = passphrase.encode("utf-8")
    h = hashlib.sha256(p).digest()
    return base64.urlsafe_b64encode(h)


def encrypt_text_fernet(passphrase: str, plaintext: str) -> Dict[str, Any]:
    try:
        key = _derive_fernet_key_from_passphrase(passphrase)
        f = Fernet(key)
        token = f.encrypt(plaintext.encode("utf-8"))
        return {
            "algoritmo": "fernet",
            "cifrado_base64": token.decode("utf-8"),
            "longitud_texto": len(plaintext),
        }
    except Exception as e:
        logger.error(f"Error encrypt_text_fernet: {e}")
        return {"error": f"Error cifrando: {str(e)}"}


def decrypt_text_fernet(passphrase: str, ciphertext_b64: str) -> Dict[str, Any]:
    try:
        key = _derive_fernet_key_from_passphrase(passphrase)
        f = Fernet(key)
        plaintext_bytes = f.decrypt(ciphertext_b64.encode("utf-8"))
        plaintext = plaintext_bytes.decode("utf-8", errors="replace")
        return {
            "algoritmo": "fernet",
            "texto_plano": plaintext,
            "longitud_texto": len(plaintext),
        }
    except Exception as e:
        logger.error(f"Error decrypt_text_fernet: {e}")
        return {"error": f"Error descifrando (clave incorrecta o texto dañado): {str(e)}"}


# ===========================================================
# FUNCIONES OSINT / SEGURIDAD
# ===========================================================

def phone_geolocation(phone_number: str) -> Dict[str, Any]:
    try:
        clean = re.sub(r"[^\d+]", "", phone_number)

        if not clean.startswith("+"):
            if len(clean) == 10:
                clean = "+52" + clean
            elif len(clean) == 11 and clean.startswith("1"):
                clean = "+" + clean

        parsed = phonenumbers.parse(clean, None)

        if not phonenumbers.is_valid_number(parsed):
            return {"error": "Número inválido"}

        result = {
            "numero_original": phone_number,
            "numero_formateado": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            ),
            "pais": geocoder.country_name_for_number(parsed, "es") or "Desconocido",
            "ubicacion": geocoder.description_for_number(parsed, "es") or "Desconocido",
            "operador": carrier.name_for_number(parsed, "es") or "Desconocido",
            "zona_horaria": timezone.time_zones_for_number(parsed) or [],
            "tipo": "Móvil" if phonenumbers.number_type(parsed) == 1 else "Fijo",
        }
        return result

    except Exception as e:
        logger.warning(f"Error en phone_geolocation: {e}")
        return {"error": f"Error: {str(e)}"}


def ip_scan(ip: str) -> Dict[str, Any]:
    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            return {
                "ip": ip,
                "tipo": "Privada",
                "mensaje": "IP privada - No escaneable externamente",
            }

        result: Dict[str, Any] = {"ip": ip, "tipo": "Pública"}

        try:
            url = f"http://ip-api.com/json/{ip}"
            response = limited_requests_get(url)
            if response.status_code == 200:
                geo = response.json()
                result["geolocalizacion"] = {
                    "pais": geo.get("country"),
                    "region": geo.get("regionName"),
                    "ciudad": geo.get("city"),
                    "isp": geo.get("isp"),
                    "lat": geo.get("lat"),
                    "lon": geo.get("lon"),
                }
        except Exception as e:
            logger.info(f"Geo IP falló: {e}")

        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result["hostname"] = hostname
        except Exception:
            result["hostname"] = "No encontrado"

        try:
            open_ports = []
            common_ports = [21, 22, 80, 443]
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                code = sock.connect_ex((ip, port))
                sock.close()
                if code == 0:
                    open_ports.append(port)
            if open_ports:
                result["puertos_abiertos"] = open_ports
        except Exception as e:
            logger.info(f"Escaneo de puertos falló: {e}")

        return result

    except ValueError:
        return {"error": "IP inválida"}
    except Exception as e:
        logger.error(f"Error ip_scan: {e}")
        return {"error": f"Error escaneo: {str(e)}"}


def email_analysis(email: str) -> Dict[str, Any]:
    try:
        email = email.strip()
        if len(email) > 254:
            return {"error": "Email demasiado largo"}

        if not re.match(r"^[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
            return {"error": "Formato de email inválido"}

        result: Dict[str, Any] = {"email": email}
        domain = email.split("@")[1]
        domain = sanitize_domain(domain)
        result["dominio"] = domain
        result["formato_valido"] = True

        try:
            w = whois.whois(domain)
            result["whois"] = {
                "registrado": bool(w.domain_name),
                "registrador": w.registrar or "Desconocido",
                "creacion": str(w.creation_date) if w.creation_date else "N/A",
            }
        except Exception as e:
            logger.info(f"WHOIS fallo email: {e}")

        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            result["mx_records"] = [str(mx.exchange) for mx in mx_records][:3]
        except Exception:
            result["mx_records"] = []

        return result
    except Exception as e:
        logger.error(f"Error email_analysis: {e}")
        return {"error": f"Error análisis: {str(e)}"}


def domain_info(domain: str) -> Dict[str, Any]:
    try:
        domain = sanitize_domain(domain)
        result: Dict[str, Any] = {"dominio": domain}

        try:
            w = whois.whois(domain)
            result["whois"] = {
                "registrado": bool(w.domain_name),
                "registrador": w.registrar or "Desconocido",
                "creacion": str(w.creation_date) if w.creation_date else "N/A",
                "expiracion": str(w.expiration_date) if w.expiration_date else "N/A",
                "nameservers": list(w.name_servers)[:3] if w.name_servers else [],
            }
        except Exception as e:
            result["whois_error"] = str(e)

        try:
            a_records = dns.resolver.resolve(domain, "A")
            result["ip_addresses"] = [str(ip) for ip in a_records][:5]
        except Exception:
            result["ip_addresses"] = []

        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            result["mail_servers"] = [str(mx.exchange) for mx in mx_records][:3]
        except Exception:
            result["mail_servers"] = []

        return result
    except Exception as e:
        logger.error(f"Error domain_info: {e}")
        return {"error": f"Error dominio: {str(e)}"}


def hash_analysis(hash_str: str) -> Dict[str, Any]:
    hash_str = hash_str.strip()
    hash_length = len(hash_str)

    hash_types = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}

    probable_type = hash_types.get(hash_length, "Desconocido")

    if re.match(r"^[a-fA-F0-9]{32}$", hash_str):
        probable_type = "MD5"
    elif re.match(r"^[a-fA-F0-9]{40}$", hash_str):
        probable_type = "SHA-1"
    elif re.match(r"^[a-fA-F0-9]{64}$", hash_str):
        probable_type = "SHA-256"

    display_hash = hash_str[:50] + "..." if len(hash_str) > 50 else hash_str

    return {
        "hash": display_hash,
        "longitud": hash_length,
        "tipo_probable": probable_type,
        "ejemplos": {
            "md5": hashlib.md5(b"test").hexdigest(),
            "sha1": hashlib.sha1(b"test").hexdigest(),
            "sha256": hashlib.sha256(b"test").hexdigest(),
        },
    }


def url_security(url: str) -> Dict[str, Any]:
    try:
        url = sanitize_url(url)
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()

        indicators = []
        risk_score = 0

        suspicious_keywords = ["login", "secure", "verify", "account", "bank", "paypal"]
        for keyword in suspicious_keywords:
            if keyword in domain:
                indicators.append(f"Contiene '{keyword}' en el dominio")
                risk_score += 1

        suspicious_tlds = [".xyz", ".top", ".club", ".online", ".site", ".tk", ".ml"]
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            indicators.append("TLD potencialmente sospechoso")
            risk_score += 2

        if len(url) > 120:
            indicators.append("URL muy larga (posible ofuscación)")
            risk_score += 1

        if "-" in domain and any(bank in domain for bank in ["paypal", "bank", "login"]):
            indicators.append("Dominio con palabras sensibles y guiones")
            risk_score += 1

        if risk_score >= 4:
            risk_level = "ALTO RIESGO"
            recommendation = "NO VISITAR (posible phishing)"
        elif risk_score >= 2:
            risk_level = "RIESGO MEDIO"
            recommendation = "Revisar con más herramientas antes de confiar"
        else:
            risk_level = "BAJO RIESGO"
            recommendation = "No se detectan indicadores fuertes, pero navega con cautela"

        return {
            "url": url,
            "dominio": domain,
            "puntuacion_riesgo": risk_score,
            "nivel_riesgo": risk_level,
            "indicadores": indicators,
            "recomendacion": recommendation,
        }
    except Exception as e:
        logger.error(f"Error url_security: {e}")
        return {"error": f"Error URL: {str(e)}"}


def ssl_check(domain: str) -> Dict[str, Any]:
    try:
        domain = sanitize_domain(domain)
        import ssl

        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(10)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        from datetime import datetime as dt

        not_before = dt.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = dt.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_valid = (not_after - dt.utcnow()).days

        issuer = dict(x[0] for x in cert.get("issuer", []))
        result: Dict[str, Any] = {
            "dominio": domain,
            "valido": True,
            "valido_desde": not_before.strftime("%Y-%m-%d"),
            "valido_hasta": not_after.strftime("%Y-%m-%d"),
            "dias_restantes": days_valid,
            "emitido_por": issuer.get("organizationName", "Desconocido"),
        }

        if days_valid < 30:
            result["advertencia"] = f"El certificado expira en {days_valid} días"

        return result
    except socket.timeout:
        return {"error": "Timeout conectando al puerto 443"}
    except ConnectionRefusedError:
        return {"error": "Puerto 443 cerrado o no accesible"}
    except Exception as e:
        logger.error(f"Error ssl_check: {e}")
        return {"error": f"Error SSL: {str(e)}"}


def find_subdomains(domain: str) -> Dict[str, Any]:
    try:
        domain = sanitize_domain(domain)

        subdomains = [
            "www",
            "mail",
            "ftp",
            "admin",
            "test",
            "dev",
            "api",
            "secure",
            "portal",
            "webmail",
            "blog",
            "shop",
            "store",
            "app",
            "cdn",
            "static",
            "panel",
            "ns1",
            "ns2",
            "mx",
        ]

        found = []
        for sub in subdomains:
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                found.append(full_domain)
            except socket.gaierror:
                continue

        return {
            "dominio": domain,
            "subdominios_encontrados": len(found),
            "subdominios": found[:20],
        }
    except Exception as e:
        logger.error(f"Error find_subdomains: {e}")
        return {"error": f"Error subdominios: {str(e)}"}


def dns_recon(domain: str) -> Dict[str, Any]:
    try:
        domain = sanitize_domain(domain)
        result: Dict[str, Any] = {"dominio": domain}

        record_types = ["A", "AAAA", "MX", "NS", "TXT"]

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                result[record_type] = [str(rdata) for rdata in answers]
            except Exception:
                result[record_type] = []

        return result
    except Exception as e:
        logger.error(f"Error dns_recon: {e}")
        return {"error": f"Error DNS: {str(e)}"}


def image_analysis(image_url: str) -> Dict[str, Any]:
    try:
        image_url = sanitize_url(image_url)
        response = limited_requests_get(image_url, stream=True)

        if response.status_code != 200:
            return {"error": "No se pudo descargar la imagen"}

        max_bytes = int(MAX_IMAGE_SIZE_MB * 1024 * 1024)
        content = response.raw.read(max_bytes + 1)
        if len(content) > max_bytes:
            return {"error": f"Imagen demasiado grande (>{MAX_IMAGE_SIZE_MB}MB)"}

        img = Image.open(io.BytesIO(content))

        result: Dict[str, Any] = {
            "url": image_url,
            "tamano_bytes": len(content),
            "dimensiones": f"{img.width}x{img.height}",
            "formato": img.format,
            "modo": img.mode,
        }

        try:
            exif_raw = img._getexif()
            if exif_raw:
                exif_data: Dict[str, str] = {}
                for tag_id, value in exif_raw.items():
                    tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                    exif_data[str(tag_name)] = str(value)[:100]
                result["exif"] = exif_data
        except Exception as e:
            logger.info(f"EXIF no disponible: {e}")

        return result
    except Exception as e:
        logger.error(f"Error image_analysis: {e}")
        return {"error": f"Error imagen: {str(e)}"}


def social_search(username: str) -> Dict[str, Any]:
    try:
        username = sanitize_username(username)
    except ValueError as e:
        return {"error": str(e)}

    platforms = {
        "Facebook": f"https://www.facebook.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "YouTube": f"https://youtube.com/@{username}",
        "TikTok": f"https://tiktok.com/@{username}",
        "Telegram": f"https://t.me/{username}",
    }

    results: Dict[str, Any] = {"usuario": username, "plataformas": {}}
    found = 0

    for platform, url in platforms.items():
        try:
            response = limited_requests_head(url, allow_redirects=True)
            exists = response.status_code < 400
            if exists:
                found += 1
            results["plataformas"][platform] = {
                "url": url,
                "existe": exists,
                "codigo": response.status_code,
            }
        except Exception as e:
            logger.info(f"Error consultando {platform}: {e}")
            results["plataformas"][platform] = {
                "url": url,
                "existe": "Error",
                "codigo": None,
            }

    total = len(platforms)
    results["resumen"] = {
        "encontradas": found,
        "total": total,
        "porcentaje": round((found / total) * 100, 1) if total else 0,
    }

    return results


def password_strength(password: str) -> Dict[str, Any]:
    score = 0
    feedback = []

    if len(password) >= 16:
        score += 3
        feedback.append("Longitud excelente (16+ caracteres)")
    elif len(password) >= 12:
        score += 2
        feedback.append("Longitud buena (12+ caracteres)")
    elif len(password) >= 8:
        score += 1
        feedback.append("Longitud mínima (8 caracteres)")
    else:
        feedback.append("Longitud insuficiente (< 8 caracteres)")

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    complexity = sum([has_lower, has_upper, has_digit, has_special])

    if complexity == 4:
        score += 3
        feedback.append("Excelente complejidad (4 tipos de caracteres)")
    elif complexity >= 3:
        score += 2
        feedback.append("Buena complejidad (3 tipos de caracteres)")
    elif complexity >= 2:
        score += 1
        feedback.append("Complejidad aceptable (2 tipos de caracteres)")
    else:
        feedback.append("Complejidad insuficiente")

    common_passwords = ["123456", "password", "qwerty", "admin", "welcome"]
    if password.lower() in common_passwords:
        score = 0
        feedback.append("CONTRASEÑA MUY COMÚN - CAMBIAR INMEDIATAMENTE")

    if score >= 6:
        strength = "MUY FUERTE"
        time_to_crack = "Años"
    elif score >= 4:
        strength = "FUERTE"
        time_to_crack = "Meses"
    elif score >= 2:
        strength = "MODERADA"
        time_to_crack = "Días"
    else:
        strength = "DÉBIL"
        time_to_crack = "Minutos/Horas"

    return {
        "longitud": len(password),
        "puntuacion": score,
        "fortaleza": strength,
        "tiempo_descifrado": time_to_crack,
        "retroalimentacion": feedback,
        "hashes": {
            "md5": hashlib.md5(password.encode()).hexdigest(),
            "sha1": hashlib.sha1(password.encode()).hexdigest(),
            "sha256": hashlib.sha256(password.encode()).hexdigest(),
        },
    }


def generate_report(report_type: str, target: str) -> Dict[str, Any]:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_type = report_type.lower()

    if report_type == "ip":
        data = ip_scan(target)
    elif report_type == "email":
        data = email_analysis(target)
    elif report_type == "domain":
        data = domain_info(target)
    elif report_type == "url":
        data = url_security(target)
    else:
        return {"error": "Tipo de reporte no soportado. Usa: ip, email, domain, url."}

    report: Dict[str, Any] = {
        "metadata": {
            "reporte_id": hashlib.md5(f"{report_type}{target}{timestamp}".encode()).hexdigest()[:8],
            "generado": timestamp,
            "tipo": report_type,
            "objetivo": target,
        },
        "datos": data,
        "recomendaciones": [],
    }

    if report_type == "email" and isinstance(data, dict) and "whois" in data:
        report["recomendaciones"].append("Verificar autenticidad del dominio del remitente.")
    if report_type == "ip" and isinstance(data, dict) and data.get("tipo") == "Pública":
        report["recomendaciones"].append("No exponer servicios innecesarios en IP pública.")
    if report_type == "url" and isinstance(data, dict):
        if data.get("nivel_riesgo") in ["ALTO RIESGO", "RIESGO MEDIO"]:
            report["recomendaciones"].append("No ingresar credenciales ni datos sensibles en esa URL.")

    return report


def urlscan_analysis(url: str) -> Dict[str, Any]:
    try:
        url = sanitize_url(url)

        if not URLSCAN_API_KEY:
            return {"error": "URLSCAN_API_KEY no configurado en config.json"}

        headers = {
            "API-Key": URLSCAN_API_KEY,
            "Content-Type": "application/json",
        }
        data = {"url": url, "public": "on"}

        response = limited_requests_post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)

        if response.status_code == 200:
            scan_data = response.json()
            return {
                "url": url,
                "id_escaneo": scan_data.get("uuid"),
                "url_resultados": scan_data.get("result"),
                "mensaje": "Escaneo iniciado",
                "ver_resultados": f"https://urlscan.io/result/{scan_data.get('uuid')}",
            }
        else:
            return {"error": f"Error URLScan: {response.status_code}"}
    except Exception as e:
        logger.error(f"Error urlscan_analysis: {e}")
        return {"error": f"Error: {str(e)}"}


def get_history(user_id: int) -> Dict[str, Any]:
    history = USER_HISTORY.get(user_id, [])
    if not history:
        return {"mensaje": "No hay historial de búsquedas"}

    from collections import Counter

    command_counts = Counter([item["command"] for item in history])

    return {
        "total_busquedas": len(history),
        "primera_busqueda": history[0]["time"] if history else None,
        "ultima_busqueda": history[-1]["time"] if history else None,
        "comandos_mas_usados": dict(command_counts.most_common(5)),
        "ultimas_5": [
            {
                "comando": h["command"],
                "objetivo": h["target"],
                "hora": h["time"],
            }
            for h in history[-5:]
        ],
    }


def smart_analyze(text: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "original": text,
        "detecciones": [],
        "decodificaciones": {},
    }

    t = text.strip()

    if re.fullmatch(r"[a-fA-F0-9]{32}", t):
        result["detecciones"].append("Probable MD5 (32 caracteres hex)")
    elif re.fullmatch(r"[a-fA-F0-9]{40}", t):
        result["detecciones"].append("Probable SHA-1 (40 caracteres hex)")
    elif re.fullmatch(r"[a-fA-F0-9]{64}", t):
        result["detecciones"].append("Probable SHA-256 (64 caracteres hex)")
    elif re.fullmatch(r"[a-fA-F0-9]{96}", t):
        result["detecciones"].append("Probable SHA-384 (96 caracteres hex)")
    elif re.fullmatch(r"[a-fA-F0-9]{128}", t):
        result["detecciones"].append("Probable SHA-512 (128 caracteres hex)")

    b64_chars = re.fullmatch(r"[A-Za-z0-9+/=_-]+", t)
    if b64_chars and len(t) % 4 == 0:
        try:
            decoded = base64.b64decode(t, validate=True)
            decoded_text = decoded.decode("utf-8", errors="replace")
            result["detecciones"].append("Cadena válida Base64")
            result["decodificaciones"]["base64"] = decoded_text[:500]
        except Exception:
            pass

    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        try:
            decoded = bytes.fromhex(t)
            decoded_text = decoded.decode("utf-8", errors="replace")
            result["detecciones"].append("Cadena válida Hex")
            result["decodificaciones"]["hex"] = decoded_text[:500]
        except Exception:
            pass

    if "%" in t or "+" in t:
        try:
            decoded_text = urllib.parse.unquote_plus(t)
            if decoded_text != t:
                result["detecciones"].append("Posible URL-encoded")
                result["decodificaciones"]["url"] = decoded_text[:500]
        except Exception:
            pass

    if not result["detecciones"]:
        result["detecciones"].append("No se detectó un formato claro (hash/base64/hex/url)")

    return result


def gen_password(length: int) -> Dict[str, Any]:
    import secrets
    import string

    if length < 6 or length > 64:
        return {"error": "Longitud fuera de rango (6-64)"}

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?"
    pwd = "".join(secrets.choice(alphabet) for _ in range(length))

    return {
        "password": pwd,
        "longitud": length,
    }


def explain_topic(topic: str) -> str:
    t = topic.strip().lower()
    if t in ("hash", "hashes"):
        return (
            "*¿Qué es un hash?*\n\n"
            "Un *hash* es el resultado de aplicar una función matemática a unos datos. "
            "Se usa para comprobar integridad o almacenar contraseñas sin guardarlas en claro.\n\n"
            "Ejemplos: MD5, SHA-1, SHA-256.\n"
            "- No es cifrado: no está pensado para revertirse.\n"
            "- Dos entradas distintas deberían dar hashes diferentes.\n"
        )
    if t in ("ssl", "tls", "https"):
        return (
            "*¿Qué es SSL/TLS?*\n\n"
            "Es el protocolo que cifra la comunicación entre tu navegador y un servidor (HTTPS). "
            "Evita que terceros vean lo que envías o recibes.\n\n"
            "Un certificado SSL/TLS:\n"
            "- Identifica al servidor (dominio).\n"
            "- Tiene fechas de validez.\n"
            "- Lo emite una autoridad certificadora.\n"
        )
    if t in ("2fa", "mfa", "doble factor"):
        return (
            "*¿Qué es 2FA?*\n\n"
            "2FA (doble factor de autenticación) añade una segunda prueba además de la contraseña:\n"
            "- Algo que sabes: tu contraseña.\n"
            "- Algo que tienes: tu móvil (código, app, llave física).\n\n"
            "Así, aunque roben tu contraseña, no pueden entrar sin el segundo factor.\n"
        )
    if t in ("phishing", "phish"):
        return (
            "*¿Qué es phishing?*\n\n"
            "Es un tipo de ataque donde un atacante se hace pasar por una entidad legítima "
            "(banco, red social, etc.) para robar credenciales o datos.\n\n"
            "Señales típicas:\n"
            "- Correos con urgencia o amenazas.\n"
            "- Enlaces raros o dominios parecidos.\n"
            "- Errores de ortografía, saludos genéricos.\n"
        )
    return (
        "Temas disponibles:\n"
        "- hash\n"
        "- ssl\n"
        "- 2fa\n"
        "- phishing\n\n"
        "Ejemplo: `/explain hash`"
    )


# ===========================================================
# MENÚ DINÁMICO
# ===========================================================

def main_menu_keyboard() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("🎓 Aprendizaje", callback_data="menu_learning"),
        InlineKeyboardButton("📊 Mi Progreso", callback_data="cmd_progreso"),
    )
    kb.row(
        InlineKeyboardButton("🛰 OSINT básico", callback_data="menu_osint"),
        InlineKeyboardButton("🌐 Web / URL", callback_data="menu_web"),
    )
    kb.row(
        InlineKeyboardButton("🔐 Contraseñas / Cifrado", callback_data="menu_crypto"),
    )
    kb.row(
        InlineKeyboardButton("ℹ️ Herramientas info", callback_data="menu_info"),
        InlineKeyboardButton("📚 Ayuda", callback_data="menu_help"),
    )
    return kb


def learning_menu_text() -> str:
    return (
        "*🎓 APRENDIZAJE*\n\n"
        "`/leccion` – Ver lección actual\n"
        "`/ejercicio` – Solicitar ejercicio práctico\n"
        "`/entregar <respuesta>` – Entregar ejercicio\n"
        "`/progreso` – Ver tu progreso\n"
        "`/especialidad` – Ver especializaciones\n"
        "`/recursos` – Recursos adicionales\n\n"
        "*Módulos disponibles:*\n"
        "A. Fundamentos (0-20%)\n"
        "B. Redes y Protocolos (21-40%)\n"
        "C. Programación (41-60%)\n"
        "D. Pentesting (61-80%)\n"
        "E. Especializaciones (81-100%)\n"
    )


def osint_menu_text() -> str:
    return (
        "*🛰 OSINT BÁSICO*\n\n"
        "`/ip <ip>` – Info básica IP\n"
        "`/phone <num>` – Teléfono\n"
        "`/email <correo>` – Análisis email\n"
        "`/domain <dominio>` – WHOIS/DNS\n"
        "`/hash <hash>` – Tipo probable de hash\n"
        "`/report <tipo> <valor>` – Reporte OSINT\n"
    )


def web_menu_text() -> str:
    return (
        "*🌐 WEB / URL*\n\n"
        "`/url <url>` – Riesgo URL\n"
        "`/ssl <dominio>` – Certificado SSL\n"
        "`/subdomains <dom>` – Subdominios\n"
        "`/dns <dom>` – Registros DNS\n"
        "`/image <url>` – Metadatos imagen\n"
        "`/scanurl <url>` – URLScan.io (si configuras API)\n"
    )


def crypto_menu_text() -> str:
    return (
        "*🔐 CONTRASEÑAS / CIFRADO*\n\n"
        "`/password <pass>` – Fuerza de contraseña\n"
        "`/genpass <n>` – Generar contraseña segura\n"
        "`/analyze <cadena>` – Detectar hash/base64/hex/url\n"
        "`/encrypt <clave> <txt>` – Cifrar con Fernet\n"
        "`/decrypt <clave> <txt>` – Descifrar con Fernet\n"
    )


def info_menu_text() -> str:
    return (
        "*ℹ️ HERRAMIENTAS INFO*\n\n"
        "`/history` – Historial de tus consultas\n"
        "`/social <user>` – Búsqueda en redes\n"
        "`/explain <tema>` – Explicación de conceptos\n"
        "Temas: `hash`, `ssl`, `2fa`, `phishing`\n"
    )


def help_menu_text() -> str:
    return (
        "*📚 AYUDA RÁPIDA*\n\n"
        "Usa `/menu` para navegar por las categorías.\n"
        "Ejemplos:\n"
        "- `/ip 8.8.8.8`\n"
        "- `/domain google.com`\n"
        "- `/url https://ejemplo.com`\n"
        "- `/password MiClave123!`\n"
        "- `/genpass 16`\n"
    )


# ===========================================================
# MANEJADORES DE COMANDOS
# ===========================================================

@bot.message_handler(commands=["start"])
def send_welcome(message):
    user_id = message.from_user.id
    username = message.from_user.username
    
    # Check if user exists
    user = db.get_user(user_id)
    
    if user:
        # Returning user
        text = (
            f"*🎓 ¡Bienvenido de nuevo, {username or 'estudiante'}!*\n\n"
            f"Estás en el nivel *{user['level']}*\n"
            f"XP: {user['xp']} puntos\n"
            f"Módulo actual: *{curriculum.get_module(user['current_module'])['name']}*\n"
            f"Lección: {user['current_lesson']}\n\n"
            "¿Continuamos donde te quedaste?"
        )
        
        kb = InlineKeyboardMarkup()
        kb.row(
            InlineKeyboardButton("📖 Continuar lección", callback_data="continue_lesson"),
            InlineKeyboardButton("📊 Ver progreso", callback_data="cmd_progreso")
        )
        kb.row(
            InlineKeyboardButton("📚 Menú principal", callback_data="main_menu")
        )
        
        bot.send_message(message.chat.id, text, reply_markup=kb)
    else:
        # New user - Start onboarding
        text = (
            "*🎓 ¡Hola futuro experto en ciberseguridad!*\n\n"
            "Soy *CyberMentor*, tu profesor virtual. "
            "Voy a guiarte desde cero hasta nivel experto en seguridad informática.\n\n"
            "¿Desde qué dispositivo estudiarás principalmente?"
        )
        
        kb = InlineKeyboardMarkup()
        kb.row(
            InlineKeyboardButton("📱 Smartphone", callback_data="device_mobile"),
            InlineKeyboardButton("💻 Computadora", callback_data="device_computer")
        )
        
        bot.send_message(message.chat.id, text, reply_markup=kb)


@bot.message_handler(commands=["help", "ayuda"])
def send_help(message):
    text = (
        "*🤖 CYBERMENTOR BOT – V11.0*\n\n"
        "Bot educativo de ciberseguridad y herramientas OSINT.\n\n"
        "*Comandos de Aprendizaje:*\n"
        "`/leccion` - Ver lección actual\n"
        "`/ejercicio` - Solicitar ejercicio\n"
        "`/entregar` - Entregar ejercicio\n"
        "`/progreso` - Ver tu progreso\n"
        "`/especialidad` - Ver especializaciones\n\n"
        "*Herramientas OSINT:*\n"
        "Usa `/menu` para ver todas las herramientas disponibles.\n"
    )
    bot.send_message(
        message.chat.id,
        text,
        reply_markup=main_menu_keyboard(),
    )


@bot.message_handler(commands=["menu"])
def handle_menu(message):
    bot.send_message(
        message.chat.id,
        "Selecciona una categoría:",
        reply_markup=main_menu_keyboard(),
    )


@bot.callback_query_handler(func=lambda call: call.data.startswith("menu_"))
def on_menu_callback(call):
    if call.data == "menu_learning":
        text = learning_menu_text()
    elif call.data == "menu_osint":
        text = osint_menu_text()
    elif call.data == "menu_web":
        text = web_menu_text()
    elif call.data == "menu_crypto":
        text = crypto_menu_text()
    elif call.data == "menu_info":
        text = info_menu_text()
    elif call.data == "menu_help":
        text = help_menu_text()
    else:
        text = "Menú no reconocido."

    try:
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=text,
            reply_markup=main_menu_keyboard(),
        )
    except Exception:
        bot.answer_callback_query(call.id, "Actualizando menú…")


# ===========================================================
# CYBERMENTOR CALLBACK HANDLERS
# ===========================================================

@bot.callback_query_handler(func=lambda call: call.data.startswith("device_"))
def handle_device_selection(call):
    user_id = call.from_user.id
    username = call.from_user.username
    
    device_type = "mobile" if call.data == "device_mobile" else "computer"
    device_icon = "📱" if device_type == "mobile" else "💻"
    
    # Create user profile
    db.create_user(user_id, username, device_type)
    
    text = (
        f"*¡Perfecto! {device_icon}*\n\n"
        "He creado tu perfil de estudiante.\n\n"
        f"*Nivel:* Principiante\n"
        f"*XP:* 0 puntos\n"
        f"*Dispositivo:* {device_icon} {'Smartphone' if device_type == 'mobile' else 'Computadora'}\n\n"
        "Tu experiencia de aprendizaje se ha adaptado a tu dispositivo.\n\n"
        "🎯 *Comenzaremos con el Módulo A: Fundamentos*\n\n"
        "¿Listo para tu primera lección?"
    )
    
    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("📖 Comenzar primera lección", callback_data="continue_lesson")
    )
    kb.row(
        InlineKeyboardButton("📚 Ver módulos", callback_data="show_modules")
    )
    
    try:
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=text,
            reply_markup=kb
        )
    except Exception:
        bot.send_message(call.message.chat.id, text, reply_markup=kb)
    
    bot.answer_callback_query(call.id, "¡Perfil creado!")


@bot.callback_query_handler(func=lambda call: call.data == "continue_lesson")
def handle_continue_lesson(call):
    user_id = call.from_user.id
    user = db.get_user(user_id)
    
    if not user:
        bot.answer_callback_query(call.id, "Error: Usuario no encontrado")
        return
    
    lesson_id = user['current_lesson']
    lesson = curriculum.get_lesson(lesson_id)
    
    if not lesson:
        bot.answer_callback_query(call.id, "Lección no encontrada")
        return
    
    # Display lesson
    text = lesson['content']
    
    # Add navigation buttons
    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("❓ Responder pregunta", callback_data=f"quiz_{lesson_id}"),
        InlineKeyboardButton("📝 Ejercicio", callback_data=f"exercise_{lesson_id}")
    )
    kb.row(
        InlineKeyboardButton("✅ Completar lección", callback_data=f"complete_{lesson_id}"),
        InlineKeyboardButton("🔙 Menú", callback_data="main_menu")
    )
    
    try:
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=text,
            reply_markup=kb
        )
    except Exception:
        bot.send_message(call.message.chat.id, text, reply_markup=kb)
    
    bot.answer_callback_query(call.id)


@bot.callback_query_handler(func=lambda call: call.data.startswith("quiz_"))
def handle_quiz(call):
    lesson_id = call.data.replace("quiz_", "")
    lesson = curriculum.get_lesson(lesson_id)
    
    if not lesson or not lesson.get('questions'):
        bot.answer_callback_query(call.id, "No hay preguntas para esta lección")
        return
    
    # Get first question
    question = lesson['questions'][0]
    
    text = f"*❓ Pregunta de comprensión:*\n\n{question['q']}"
    
    kb = InlineKeyboardMarkup()
    for i, option in enumerate(question['options']):
        kb.row(InlineKeyboardButton(option, callback_data=f"answer_{lesson_id}_{i}"))
    
    try:
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=text,
            reply_markup=kb
        )
    except Exception:
        bot.send_message(call.message.chat.id, text, reply_markup=kb)
    
    bot.answer_callback_query(call.id)


@bot.callback_query_handler(func=lambda call: call.data.startswith("exercise_"))
def handle_exercise_callback(call):
    lesson_id = call.data.replace("exercise_", "")
    user_id = call.from_user.id
    
    # Find exercise for this lesson
    exercise = None
    for ex_id, ex in curriculum.exercises.items():
        if ex['lesson'] == lesson_id:
            exercise = ex
            break
    
    if not exercise:
        bot.answer_callback_query(call.id, "No hay ejercicios disponibles")
        return
    
    text = (
        f"*📝 EJERCICIO: {exercise['title']}*\n\n"
        f"{exercise['description']}\n\n"
        f"*XP:* {exercise.get('xp', 30)} puntos\n\n"
        f"Usa `/entregar <tu_respuesta>` para enviar tu solución."
    )
    
    try:
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=text
        )
    except Exception:
        bot.send_message(call.message.chat.id, text)
    
    bot.answer_callback_query(call.id)


@bot.callback_query_handler(func=lambda call: call.data.startswith("answer_"))
def handle_answer(call):
    parts = call.data.split("_")
    lesson_id = parts[1]
    answer_idx = int(parts[2])
    
    lesson = curriculum.get_lesson(lesson_id)
    if not lesson or not lesson.get('questions'):
        bot.answer_callback_query(call.id, "Error")
        return
    
    question = lesson['questions'][0]
    correct_idx = question['answer']
    
    user_id = call.from_user.id
    
    if answer_idx == correct_idx:
        # Correct answer - award XP
        xp_earned = 10
        db.add_xp(user_id, xp_earned)
        
        text = f"*✅ ¡Correcto!*\n\n+{xp_earned} XP\n\n¿Quieres continuar con la lección?"
        bot.answer_callback_query(call.id, "¡Correcto! +10 XP", show_alert=True)
    else:
        text = f"*❌ Incorrecto*\n\nLa respuesta correcta era: *{question['options'][correct_idx]}*\n\n¿Quieres repasar la lección?"
        bot.answer_callback_query(call.id, "Incorrecto. Revisa la lección", show_alert=True)
    
    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("📖 Ver lección", callback_data="continue_lesson"),
        InlineKeyboardButton("🔙 Menú", callback_data="main_menu")
    )
    
    try:
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=text,
            reply_markup=kb
        )
    except Exception:
        bot.send_message(call.message.chat.id, text, reply_markup=kb)


@bot.callback_query_handler(func=lambda call: call.data.startswith("complete_"))
def handle_complete_lesson(call):
    lesson_id = call.data.replace("complete_", "")
    user_id = call.from_user.id
    
    lesson = curriculum.get_lesson(lesson_id)
    if not lesson:
        bot.answer_callback_query(call.id, "Error")
        return
    
    # Mark lesson as complete
    db.mark_lesson_complete(user_id, lesson_id, score=100)
    
    # Award XP
    xp_earned = lesson.get('xp', 50)
    new_xp = db.add_xp(user_id, xp_earned)
    
    # Get next lesson
    next_lesson_id = curriculum.get_next_lesson(lesson_id)
    
    # Update user's current lesson
    if next_lesson_id:
        db.update_user(user_id, current_lesson=next_lesson_id)
    
    # Check for achievements
    completed_lessons = db.get_completed_lessons(user_id)
    if len(completed_lessons) == 1:
        db.add_achievement(user_id, "first_lesson", "Primera Lección Completada")
        achievement_text = "\n\n🏆 *¡Logro desbloqueado: Primera Lección!*"
    elif len(completed_lessons) == 5:
        db.add_achievement(user_id, "module_a", "Módulo A Completado")
        achievement_text = "\n\n🏆 *¡Logro desbloqueado: Módulo A Completado!*"
    else:
        achievement_text = ""
    
    text = (
        f"*✅ ¡Lección completada!*\n\n"
        f"*{lesson['title']}*\n\n"
        f"+{xp_earned} XP (Total: {new_xp})\n"
        f"Lecciones completadas: {len(completed_lessons)}"
        f"{achievement_text}\n\n"
    )
    
    kb = InlineKeyboardMarkup()
    if next_lesson_id:
        text += f"*Siguiente:* Lección {next_lesson_id}"
        kb.row(InlineKeyboardButton("➡️ Siguiente lección", callback_data="continue_lesson"))
    else:
        text += "¡Has completado todas las lecciones disponibles!"
    
    kb.row(
        InlineKeyboardButton("📊 Ver progreso", callback_data="cmd_progreso"),
        InlineKeyboardButton("🔙 Menú", callback_data="main_menu")
    )
    
    try:
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=text,
            reply_markup=kb
        )
    except Exception:
        bot.send_message(call.message.chat.id, text, reply_markup=kb)
    
    bot.answer_callback_query(call.id, f"¡Felicitaciones! +{xp_earned} XP", show_alert=True)


@bot.callback_query_handler(func=lambda call: call.data == "show_modules")
def handle_show_modules(call):
    text = "*📚 MÓDULOS DE APRENDIZAJE*\n\n"
    
    for module_id, module in curriculum.modules.items():
        text += f"*{module_id}. {module['name']}* ({module['progress_range'][0]}-{module['progress_range'][1]}%)\n"
        text += f"   _{module['description']}_\n\n"
    
    kb = InlineKeyboardMarkup()
    kb.row(InlineKeyboardButton("📖 Comenzar lección", callback_data="continue_lesson"))
    kb.row(InlineKeyboardButton("🔙 Inicio", callback_data="main_menu"))
    
    try:
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=text,
            reply_markup=kb
        )
    except Exception:
        bot.send_message(call.message.chat.id, text, reply_markup=kb)
    
    bot.answer_callback_query(call.id)


@bot.callback_query_handler(func=lambda call: call.data == "main_menu")
def handle_main_menu(call):
    text = "Selecciona una categoría:"
    
    try:
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=text,
            reply_markup=main_menu_keyboard()
        )
    except Exception:
        bot.send_message(call.message.chat.id, text, reply_markup=main_menu_keyboard())
    
    bot.answer_callback_query(call.id)


@bot.callback_query_handler(func=lambda call: call.data == "cmd_progreso")
def handle_progreso_callback(call):
    user_id = call.from_user.id
    stats = db.get_user_stats(user_id)
    
    if not stats:
        bot.answer_callback_query(call.id, "Error al obtener progreso")
        return
    
    completed_lessons = db.get_completed_lessons(user_id)
    progress_pct = curriculum.calculate_progress(completed_lessons)
    
    text = (
        "*📊 TU PROGRESO*\n\n"
        f"*Nivel:* {stats['level'].title()}\n"
        f"*XP:* {stats['xp']} puntos\n"
        f"*Progreso general:* {progress_pct}%\n\n"
        f"*Estadísticas:*\n"
        f"• Lecciones completadas: {stats['completed_lessons']}\n"
        f"• Ejercicios entregados: {stats['exercises_submitted']}\n"
        f"• Logros: {stats['achievements']}\n"
        f"• Puntuación media: {stats['average_score']}%\n\n"
        f"*Módulo actual:* {curriculum.get_module(stats['current_module'])['name']}\n"
        f"*Lección actual:* {stats['current_lesson']}\n"
    )
    
    # Check level progression
    if stats['xp'] >= 1000:
        level = "Expert"
    elif stats['xp'] >= 500:
        level = "Advanced"
    elif stats['xp'] >= 200:
        level = "Intermediate"
    else:
        level = "Beginner"
    
    if level != stats['level']:
        db.update_user(user_id, level=level)
        text += f"\n🎉 *¡Has subido de nivel a {level}!*"
    
    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("📖 Continuar aprendiendo", callback_data="continue_lesson"),
        InlineKeyboardButton("🏆 Ver logros", callback_data="show_achievements")
    )
    kb.row(InlineKeyboardButton("🔙 Menú", callback_data="main_menu"))
    
    try:
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=text,
            reply_markup=kb
        )
    except Exception:
        bot.send_message(call.message.chat.id, text, reply_markup=kb)
    
    bot.answer_callback_query(call.id)


@bot.callback_query_handler(func=lambda call: call.data == "show_achievements")
def handle_show_achievements(call):
    user_id = call.from_user.id
    achievements = db.get_achievements(user_id)
    
    if not achievements:
        text = "*🏆 LOGROS*\n\nAún no has desbloqueado logros. ¡Sigue estudiando!"
    else:
        text = "*🏆 TUS LOGROS*\n\n"
        for ach in achievements:
            text += f"🏅 *{ach['achievement_name']}*\n"
            text += f"   Obtenido: {ach['earned_at'][:10]}\n\n"
    
    kb = InlineKeyboardMarkup()
    kb.row(InlineKeyboardButton("📊 Ver progreso", callback_data="cmd_progreso"))
    kb.row(InlineKeyboardButton("🔙 Menú", callback_data="main_menu"))
    
    try:
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=text,
            reply_markup=kb
        )
    except Exception:
        bot.send_message(call.message.chat.id, text, reply_markup=kb)
    
    bot.answer_callback_query(call.id)


@bot.message_handler(commands=["phone"])
def handle_phone(message):
    try:
        text = message.text.strip()
        if len(text.split()) < 2:
            bot.reply_to(message, "Uso: `/phone <número>`\nEj: `/phone +525551234567`", parse_mode="Markdown")
            return

        phone = " ".join(text.split()[1:])[:50]
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "📡 Analizando número...")

        result = phone_geolocation(phone)
        save_result(result, "phone", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = (
                "*📱 INFORMACIÓN DEL TELÉFONO*\n\n"
                f"• Número: `{result.get('numero_formateado', 'N/A')}`\n"
                f"• País: {result.get('pais', 'N/A')}\n"
                f"• Ubicación: {result.get('ubicacion', 'N/A')}\n"
                f"• Operador: {result.get('operador', 'N/A')}\n"
                f"• Tipo: {result.get('tipo', 'N/A')}\n"
            )

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_phone error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["ip"])
def handle_ip(message):
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(message, "Uso: `/ip <dirección_ip>`", parse_mode="Markdown")
            return

        ip = parts[1][:64]
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🌐 Escaneando IP...")

        result = ip_scan(ip)
        save_result(result, "ip", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*🌐 INFORMACIÓN DE IP*\n\n"
            response += f"• IP: `{result.get('ip', 'N/A')}`\n"
            response += f"• Tipo: {result.get('tipo', 'N/A')}\n"

            if "geolocalizacion" in result:
                geo = result["geolocalizacion"]
                response += "\n*Geolocalización:*\n"
                response += f"• País: {geo.get('pais', 'N/A')}\n"
                response += f"• Ciudad: {geo.get('ciudad', 'N/A')}\n"
                response += f"• ISP: {geo.get('isp', 'N/A')}\n"

            if "hostname" in result:
                response += f"\nHostname: `{result['hostname']}`\n"

            if "puertos_abiertos" in result:
                response += f"\nPuertos abiertos: `{', '.join(map(str, result['puertos_abiertos']))}`\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_ip error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["email"])
def handle_email(message):
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(message, "Uso: `/email <correo>`", parse_mode="Markdown")
            return

        email = parts[1][:254]
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "📧 Analizando email...")

        result = email_analysis(email)
        save_result(result, "email", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*📧 ANÁLISIS DE EMAIL*\n\n"
            response += f"• Email: `{result.get('email', 'N/A')}`\n"
            response += f"• Dominio: `{result.get('dominio', 'N/A')}`\n"
            response += f"• Formato válido: {'Sí' if result.get('formato_valido') else 'No'}\n"

            if "whois" in result:
                who = result["whois"]
                response += "\n*WHOIS:*\n"
                response += f"• Registrado: {'Sí' if who.get('registrado') else 'No'}\n"
                response += f"• Registrador: {who.get('registrador', 'N/A')}\n"

            if result.get("mx_records"):
                response += "\n*Servidores MX:*\n"
                for mx in result["mx_records"][:3]:
                    response += f"• {mx}\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_email error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["domain"])
def handle_domain(message):
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(message, "Uso: `/domain <dominio>`", parse_mode="Markdown")
            return

        domain = parts[1]
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🔎 Analizando dominio...")

        result = domain_info(domain)
        save_result(result, "domain", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*🌐 INFORMACIÓN DE DOMINIO*\n\n"
            response += f"• Dominio: `{result.get('dominio', 'N/A')}`\n"

            if "whois" in result:
                who = result["whois"]
                response += "\n*WHOIS:*\n"
                response += f"• Registrado: {'Sí' if who.get('registrado') else 'No'}\n"
                response += f"• Registrador: {who.get('registrador', 'N/A')}\n"
                response += f"• Creación: {who.get('creacion', 'N/A')}\n"
                response += f"• Expiración: {who.get('expiracion', 'N/A')}\n"

            if result.get("ip_addresses"):
                response += "\n*Direcciones IP:*\n"
                for ip in result["ip_addresses"][:3]:
                    response += f"• `{ip}`\n"

            if result.get("mail_servers"):
                response += "\n*Servidores de correo:*\n"
                for mx in result["mail_servers"][:3]:
                    response += f"• {mx}\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_domain error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["url"])
def handle_url(message):
    try:
        parts = message.text.split(maxsplit=1)
        if len(parts) < 2:
            bot.reply_to(message, "Uso: `/url <url>`\nEj: `/url https://ejemplo.com`", parse_mode="Markdown")
            return

        url = parts[1].strip()
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🛡 Analizando URL...")

        result = url_security(url)
        save_result(result, "url", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*🛡 ANÁLISIS DE URL*\n\n"
            response += f"• URL: `{result.get('url', 'N/A')}`\n"
            response += f"• Dominio: `{result.get('dominio', 'N/A')}`\n"
            response += f"• Puntuación riesgo: `{result.get('puntuacion_riesgo', 0)}/5`\n"
            response += f"• Nivel riesgo: *{result.get('nivel_riesgo', 'N/A')}*\n"
            response += f"• Recomendación: {result.get('recomendacion', 'N/A')}\n"

            if result.get("indicadores"):
                response += "\n*Indicadores detectados:*\n"
                for ind in result["indicadores"]:
                    response += f"• {ind}\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_url error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["ssl"])
def handle_ssl(message):
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(message, "Uso: `/ssl <dominio>`", parse_mode="Markdown")
            return

        domain = parts[1]
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🔒 Verificando SSL...")

        result = ssl_check(domain)
        save_result(result, "ssl", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*🔒 CERTIFICADO SSL*\n\n"
            response += f"• Dominio: `{result.get('dominio', 'N/A')}`\n"
            response += f"• Válido: {'Sí' if result.get('valido') else 'No'}\n"
            response += f"• Válido desde: {result.get('valido_desde', 'N/A')}\n"
            response += f"• Válido hasta: {result.get('valido_hasta', 'N/A')}\n"
            response += f"• Días restantes: {result.get('dias_restantes', 'N/A')}\n"
            response += f"• Emitido por: {result.get('emitido_por', 'N/A')}\n"

            if "advertencia" in result:
                response += f"\n*Advertencia:* {result['advertencia']}\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_ssl error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["subdomains"])
def handle_subdomains(message):
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(message, "Uso: `/subdomains <dominio>`", parse_mode="Markdown")
            return

        domain = parts[1]
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🧩 Buscando subdominios...")

        result = find_subdomains(domain)
        save_result(result, "subdomains", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*🧩 SUBDOMINIOS ENCONTRADOS*\n\n"
            response += f"• Dominio: `{result.get('dominio', 'N/A')}`\n"
            response += f"• Total: `{result.get('subdominios_encontrados', 0)}`\n"

            if result.get("subdominios"):
                response += "\n*Lista:*\n"
                for sub in result["subdominios"][:15]:
                    response += f"• `{sub}`\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_subdomains error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["dns"])
def handle_dns(message):
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(message, "Uso: `/dns <dominio>`", parse_mode="Markdown")
            return

        domain = parts[1]
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "📡 Consultando DNS...")

        result = dns_recon(domain)
        save_result(result, "dns", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*📡 REGISTROS DNS*\n\n"
            response += f"• Dominio: `{result.get('dominio', 'N/A')}`\n"

            for rt in ["A", "AAAA", "MX", "NS", "TXT"]:
                if result.get(rt):
                    response += f"\n*{rt}:*\n"
                    for record in result[rt][:5]:
                        response += f"• {record}\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_dns error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["image"])
def handle_image(message):
    try:
        parts = message.text.split(maxsplit=1)
        if len(parts) < 2:
            bot.reply_to(message, "Uso: `/image <url_imagen>`", parse_mode="Markdown")
            return

        image_url = parts[1].strip()
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🖼 Analizando imagen...")

        result = image_analysis(image_url)
        save_result(result, "image", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*🖼 METADATOS DE IMAGEN*\n\n"
            response += f"• URL: `{result.get('url', 'N/A')}`\n"
            response += f"• Tamaño: `{result.get('tamano_bytes', 0)} bytes`\n"
            response += f"• Dimensiones: `{result.get('dimensiones', 'N/A')}`\n"
            response += f"• Formato: `{result.get('formato', 'N/A')}`\n"
            response += f"• Modo: `{result.get('modo', 'N/A')}`\n"

            if result.get("exif"):
                response += "\n*Algunos metadatos EXIF:*\n"
                for k, v in list(result["exif"].items())[:5]:
                    response += f"• {k}: {v[:50]}\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_image error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["social"])
def handle_social(message):
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(message, "Uso: `/social <usuario>`\nEj: `/social juanperez`", parse_mode="Markdown")
            return

        username = parts[1]
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "👥 Buscando en redes sociales...")

        result = social_search(username)
        save_result(result, "social", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*👥 BÚSQUEDA EN REDES SOCIALES*\n\n"
            response += f"• Usuario: `{result.get('usuario', 'N/A')}`\n"

            resumen = result.get("resumen", {})
            response += (
                f"• Plataformas encontradas: "
                f"{resumen.get('encontradas', 0)}/{resumen.get('total', 0)}\n"
            )
            response += f"• Porcentaje: {resumen.get('porcentaje', 0)}%\n"

            response += "\n*Resultados:*\n"
            for platform, info in result.get("plataformas", {}).items():
                status = "OK" if info.get("existe") is True else "NO"
                response += f"• {platform}: {status}\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_social error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["password"])
def handle_password(message):
    try:
        parts = message.text.split(maxsplit=1)
        if len(parts) < 2:
            bot.reply_to(
                message,
                "Uso: `/password <contraseña>`\nEj: `/password MiContraseña123!`",
                parse_mode="Markdown",
            )
            return

        password = parts[1]
        if len(password) > 128:
            bot.reply_to(message, "La contraseña es demasiado larga (máx 128 caracteres).")
            return

        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🔐 Analizando contraseña...")

        result = password_strength(password)

        safe_result = result.copy()
        if "hashes" in safe_result:
            del safe_result["hashes"]
        save_result(safe_result, "password", message.from_user.id)

        response = "*🔐 ANÁLISIS DE CONTRASEÑA*\n\n"
        response += f"• Longitud: `{result.get('longitud', 0)}`\n"
        response += f"• Puntuación: `{result.get('puntuacion', 0)}/10`\n"
        response += f"• Fortaleza: *{result.get('fortaleza', 'N/A')}*\n"
        response += (
            f"• Tiempo estimado de descifrado: `{result.get('tiempo_descifrado', 'N/A')}`\n"
        )

        if result.get("retroalimentacion"):
            response += "\n*Recomendaciones:*\n"
            for fb in result["retroalimentacion"][:5]:
                response += f"• {fb}\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_password error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["hash"])
def handle_hash(message):
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(message, "Uso: `/hash <cadena_hash>`", parse_mode="Markdown")
            return

        hash_str = parts[1][:256]
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🔎 Analizando hash...")

        result = hash_analysis(hash_str)
        save_result(result, "hash", message.from_user.id)

        response = "*🔎 ANÁLISIS DE HASH*\n\n"
        response += f"• Hash: `{result.get('hash', 'N/A')}`\n"
        response += f"• Longitud: `{result.get('longitud', 0)}`\n"
        response += f"• Tipo probable: `{result.get('tipo_probable', 'N/A')}`\n"

        if result.get("ejemplos"):
            response += "\n*Ejemplos (texto 'test'):*\n"
            for algo, h in result["ejemplos"].items():
                response += f"• {algo.upper()}: `{h}`\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_hash error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["report"])
def handle_report(message):
    try:
        parts = message.text.split(maxsplit=2)
        if len(parts) < 3:
            bot.reply_to(
                message,
                "Uso: `/report <tipo> <valor>`\nTipos: ip, email, domain, url\nEj: `/report ip 8.8.8.8`",
                parse_mode="Markdown",
            )
            return

        report_type = parts[1].strip()
        target = parts[2].strip()

        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "📄 Generando reporte...")

        result = generate_report(report_type, target)
        save_result(result, f"report_{report_type}", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            meta = result.get("metadata", {})
            response = "*📄 REPORTE OSINT*\n\n"
            response += f"• ID Reporte: `{meta.get('reporte_id', 'N/A')}`\n"
            response += f"• Tipo: `{meta.get('tipo', 'N/A')}`\n"
            response += f"• Objetivo: `{meta.get('objetivo', 'N/A')}`\n"
            response += f"• Generado: `{meta.get('generado', 'N/A')}`\n"

            if result.get("recomendaciones"):
                response += "\n*Recomendaciones:*\n"
                for rec in result["recomendaciones"]:
                    response += f"• {rec}\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_report error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["history"])
def handle_history(message):
    try:
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "📜 Consultando historial...")

        result = get_history(message.from_user.id)

        if "mensaje" in result:
            response = result["mensaje"]
        else:
            response = "*📜 TU HISTORIAL DE BÚSQUEDAS*\n\n"
            response += f"• Total búsquedas: `{result.get('total_busquedas', 0)}`\n"
            if result.get("ultima_busqueda"):
                response += f"• Última: `{result.get('ultima_busqueda', 'N/A')}`\n"

            if result.get("comandos_mas_usados"):
                response += "\n*Comandos más usados:*\n"
                for cmd, count in result["comandos_mas_usados"].items():
                    response += f"• `{cmd}`: {count}\n"

            if result.get("ultimas_5"):
                response += "\n*Últimas 5 búsquedas:*\n"
                for h in result["ultimas_5"]:
                    response += f"• `{h['comando']}` - {h['objetivo']} ({h['hora']})\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_history error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["scanurl"])
def handle_scanurl(message):
    try:
        parts = message.text.split(maxsplit=1)
        if len(parts) < 2:
            bot.reply_to(
                message,
                "Uso: `/scanurl <url>`\nEj: `/scanurl https://ejemplo.com`",
                parse_mode="Markdown",
            )
            return

        url = parts[1].strip()
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🔬 Escaneando URL con urlscan.io...")

        result = urlscan_analysis(url)
        save_result(result, "urlscan", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*🔬 ESCANEO URLSCAN.IO*\n\n"
            response += f"• URL: `{result.get('url', 'N/A')}`\n"
            response += f"• ID Escaneo: `{result.get('id_escaneo', 'N/A')}`\n"
            response += f"• Estado: {result.get('mensaje', 'N/A')}\n"
            if result.get("ver_resultados"):
                response += f"• Ver resultados: {result.get('ver_resultados', 'N/A')}\n"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_scanurl error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["analyze"])
def handle_analyze(message):
    try:
        parts = message.text.split(maxsplit=1)
        if len(parts) < 2:
            bot.reply_to(
                message,
                "Uso: `/analyze <cadena>`\nEj: `/analyze SGVsbG8gd29ybGQ=`",
                parse_mode="Markdown",
            )
            return

        data = parts[1].strip()
        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🧬 Analizando cadena...")

        result = smart_analyze(data)
        save_result(result, "analyze", message.from_user.id)

        response_lines = []
        response_lines.append("*🧬 ANÁLISIS DE CADENA*\n")
        response_lines.append(f"Original: `{result.get('original', '')[:200]}`")

        if result.get("detecciones"):
            response_lines.append("\n*Detecciones:*")
            for det in result["detecciones"]:
                response_lines.append(f"• {det}")

        dec = result.get("decodificaciones", {})
        if dec:
            response_lines.append("\n*Decodificaciones:*")
            for k, v in dec.items():
                response_lines.append(f"`[{k}]` {v[:200]}")

        response = "\n".join(response_lines)

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_analyze error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["encrypt"])
def handle_encrypt(message):
    try:
        parts = message.text.split(maxsplit=2)
        if len(parts) < 3:
            bot.reply_to(
                message,
                "Uso: `/encrypt <clave> <texto>`\nEj: `/encrypt MiClaveSecreta Hola mundo`",
                parse_mode="Markdown",
            )
            return

        passphrase = parts[1]
        plaintext = parts[2]

        if len(passphrase) < 4:
            bot.reply_to(message, "La clave es muy corta, usa al menos 4 caracteres.")
            return

        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🔐 Cifrando texto...")

        result = encrypt_text_fernet(passphrase, plaintext)
        save_result({"algoritmo": "fernet", "longitud_texto": len(plaintext)}, "encrypt", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*🔐 CIFRADO FERNET (AES)*\n\n"
            response += f"Texto original (longitud `{result.get('longitud_texto', 0)}`):\n"
            response += f"`{plaintext[:200]}`\n\n"
            response += "Texto cifrado (base64):\n"
            response += f"`{result.get('cifrado_base64', '')[:3500]}`"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_encrypt error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["decrypt"])
def handle_decrypt(message):
    try:
        parts = message.text.split(maxsplit=2)
        if len(parts) < 3:
            bot.reply_to(
                message,
                "Uso: `/decrypt <clave> <texto_cifrado_base64>`\n"
                "Ej: `/decrypt MiClaveSecreta <cifrado>`",
                parse_mode="Markdown",
            )
            return

        passphrase = parts[1]
        ciphertext_b64 = parts[2]

        bot.send_chat_action(message.chat.id, "typing")
        msg = bot.reply_to(message, "🔓 Descifrando texto...")

        result = decrypt_text_fernet(passphrase, ciphertext_b64)
        save_result({"algoritmo": "fernet"}, "decrypt", message.from_user.id)

        if "error" in result:
            response = result["error"]
        else:
            response = "*🔓 DESCIFRADO FERNET (AES)*\n\n"
            response += f"Texto plano (longitud `{result.get('longitud_texto', 0)}`):\n"
            response += f"`{result.get('texto_plano', '')[:3500]}`"

        bot.delete_message(message.chat.id, msg.message_id)
        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_decrypt error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["genpass"])
def handle_genpass(message):
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.reply_to(
                message,
                "Uso: `/genpass <longitud>`\nEj: `/genpass 16`",
                parse_mode="Markdown",
            )
            return

        try:
            length = int(parts[1])
        except ValueError:
            bot.reply_to(message, "La longitud debe ser un número entero.")
            return

        bot.send_chat_action(message.chat.id, "typing")
        result = gen_password(length)

        if "error" in result:
            response = result["error"]
        else:
            response = "*🔐 GENERADOR DE CONTRASEÑAS*\n\n"
            response += f"• Longitud: `{result.get('longitud', 0)}`\n"
            response += f"• Contraseña sugerida:\n`{result.get('password', '')}`"

        bot.send_message(message.chat.id, response, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_genpass error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


# ===========================================================
# CYBERMENTOR COMMAND HANDLERS
# ===========================================================

@bot.message_handler(commands=["leccion"])
def handle_leccion(message):
    """Show current lesson"""
    try:
        user_id = message.from_user.id
        user = db.get_user(user_id)
        
        if not user:
            bot.reply_to(message, "Usa `/start` para comenzar tu aprendizaje.", parse_mode="Markdown")
            return
        
        lesson_id = user['current_lesson']
        lesson = curriculum.get_lesson(lesson_id)
        
        if not lesson:
            bot.reply_to(message, "No se encontró la lección actual.")
            return
        
        text = lesson['content']
        
        kb = InlineKeyboardMarkup()
        kb.row(
            InlineKeyboardButton("❓ Pregunta", callback_data=f"quiz_{lesson_id}"),
            InlineKeyboardButton("✅ Completar", callback_data=f"complete_{lesson_id}")
        )
        kb.row(InlineKeyboardButton("🔙 Menú", callback_data="main_menu"))
        
        bot.send_message(message.chat.id, text, reply_markup=kb)
    except Exception as e:
        logger.error(f"handle_leccion error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["ejercicio"])
def handle_ejercicio(message):
    """Request exercise for current lesson"""
    try:
        user_id = message.from_user.id
        user = db.get_user(user_id)
        
        if not user:
            bot.reply_to(message, "Usa `/start` para comenzar tu aprendizaje.", parse_mode="Markdown")
            return
        
        lesson_id = user['current_lesson']
        
        # Find exercise for this lesson
        exercise = None
        for ex_id, ex in curriculum.exercises.items():
            if ex['lesson'] == lesson_id:
                exercise = ex
                break
        
        if not exercise:
            bot.reply_to(message, "No hay ejercicios disponibles para esta lección aún.")
            return
        
        text = (
            f"*📝 EJERCICIO: {exercise['title']}*\n\n"
            f"{exercise['description']}\n\n"
            f"*XP:* {exercise.get('xp', 30)} puntos\n\n"
            f"Usa `/entregar <tu_respuesta>` para enviar tu solución."
        )
        
        bot.send_message(message.chat.id, text, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_ejercicio error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["entregar"])
def handle_entregar(message):
    """Submit exercise solution"""
    try:
        user_id = message.from_user.id
        user = db.get_user(user_id)
        
        if not user:
            bot.reply_to(message, "Usa `/start` para comenzar tu aprendizaje.", parse_mode="Markdown")
            return
        
        parts = message.text.split(maxsplit=1)
        if len(parts) < 2:
            bot.reply_to(
                message,
                "Uso: `/entregar <tu_respuesta>`\nEj: `/entregar Mi solución al ejercicio...`",
                parse_mode="Markdown"
            )
            return
        
        submission = parts[1]
        lesson_id = user['current_lesson']
        
        # Find exercise for this lesson
        exercise_id = f"E{lesson_id}"
        exercise = curriculum.get_exercise(exercise_id)
        
        # Simple feedback system
        if len(submission) < 10:
            feedback = "Tu respuesta es muy corta. Desarrolla más tu solución."
            score = 30
        elif len(submission) > 1000:
            feedback = "Tu respuesta es muy extensa. Intenta ser más conciso."
            score = 70
        else:
            feedback = "¡Buena estructura! Revisa los puntos clave de la lección para mejorar."
            score = 80
        
        # Save submission
        db.save_exercise_submission(user_id, exercise_id, submission, feedback, score)
        
        # Award XP
        xp_earned = score // 2  # Half the score as XP
        new_xp = db.add_xp(user_id, xp_earned)
        
        text = (
            f"*✅ Ejercicio recibido*\n\n"
            f"*Puntuación:* {score}/100\n"
            f"*XP ganado:* +{xp_earned} (Total: {new_xp})\n\n"
            f"*Retroalimentación:*\n{feedback}\n\n"
            "¿Quieres intentarlo de nuevo o continuar?"
        )
        
        kb = InlineKeyboardMarkup()
        kb.row(
            InlineKeyboardButton("🔄 Reintentar", callback_data=f"exercise_{lesson_id}"),
            InlineKeyboardButton("➡️ Continuar", callback_data="continue_lesson")
        )
        
        bot.send_message(message.chat.id, text, reply_markup=kb)
    except Exception as e:
        logger.error(f"handle_entregar error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["progreso"])
def handle_progreso_command(message):
    """Show user progress"""
    try:
        user_id = message.from_user.id
        stats = db.get_user_stats(user_id)
        
        if not stats:
            bot.reply_to(message, "Usa `/start` para comenzar tu aprendizaje.", parse_mode="Markdown")
            return
        
        completed_lessons = db.get_completed_lessons(user_id)
        progress_pct = curriculum.calculate_progress(completed_lessons)
        
        text = (
            "*📊 TU PROGRESO*\n\n"
            f"*Nivel:* {stats['level'].title()}\n"
            f"*XP:* {stats['xp']} puntos\n"
            f"*Progreso general:* {progress_pct}%\n\n"
            f"*Estadísticas:*\n"
            f"• Lecciones completadas: {stats['completed_lessons']}\n"
            f"• Ejercicios entregados: {stats['exercises_submitted']}\n"
            f"• Logros: {stats['achievements']}\n"
            f"• Puntuación media: {stats['average_score']}%\n\n"
            f"*Módulo actual:* {curriculum.get_module(stats['current_module'])['name']}\n"
            f"*Lección actual:* {stats['current_lesson']}\n"
        )
        
        kb = InlineKeyboardMarkup()
        kb.row(
            InlineKeyboardButton("📖 Continuar lección", callback_data="continue_lesson"),
            InlineKeyboardButton("🏆 Ver logros", callback_data="show_achievements")
        )
        
        bot.send_message(message.chat.id, text, reply_markup=kb)
    except Exception as e:
        logger.error(f"handle_progreso error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["especialidad"])
def handle_especialidad(message):
    """Show specializations"""
    try:
        user_id = message.from_user.id
        user = db.get_user(user_id)
        
        if not user:
            bot.reply_to(message, "Usa `/start` para comenzar tu aprendizaje.", parse_mode="Markdown")
            return
        
        # Check if user has enough progress
        completed_lessons = db.get_completed_lessons(user_id)
        if len(completed_lessons) < 10:
            bot.reply_to(
                message,
                f"Necesitas completar al menos 10 lecciones para elegir una especialización.\n"
                f"Lecciones completadas: {len(completed_lessons)}/10"
            )
            return
        
        user_specs = db.get_specializations(user_id)
        
        text = "*🎯 ESPECIALIZACIONES (HATS)*\n\n"
        
        for spec_id, spec in curriculum.get_all_specializations().items():
            icon = spec['icon']
            name = spec['name']
            desc = spec['description']
            skills = spec['skills']
            
            selected = "✅ SELECCIONADA" if spec_id in user_specs else ""
            
            text += f"{icon} *{name}* {selected}\n"
            text += f"   _{desc}_\n"
            text += f"   Habilidades: {skills}\n\n"
        
        text += "\nPara elegir una especialización, contacta al administrador."
        
        bot.send_message(message.chat.id, text, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_especialidad error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(commands=["recursos"])
def handle_recursos(message):
    """Show additional resources"""
    text = (
        "*📚 RECURSOS ADICIONALES*\n\n"
        "*Plataformas de práctica:*\n"
        "• TryHackMe - tryhackme.com\n"
        "• HackTheBox - hackthebox.com\n"
        "• OverTheWire - overthewire.org\n"
        "• PentesterLab - pentesterlab.com\n\n"
        "*Bug Bounty:*\n"
        "• HackerOne - hackerone.com\n"
        "• Bugcrowd - bugcrowd.com\n"
        "• Intigriti - intigriti.com\n\n"
        "*Aprendizaje:*\n"
        "• OWASP - owasp.org\n"
        "• CyberSecLabs - cyberseclabs.co.uk\n"
        "• Portswigger Academy - portswigger.net/web-security\n\n"
        "*Certificaciones:*\n"
        "• CEH - Certified Ethical Hacker\n"
        "• OSCP - Offensive Security Certified Professional\n"
        "• CompTIA Security+\n"
    )
    
    bot.send_message(message.chat.id, text, parse_mode="Markdown")


@bot.message_handler(commands=["explain"])
def handle_explain(message):
    try:
        parts = message.text.split(maxsplit=1)
        topic = parts[1] if len(parts) > 1 else ""
        text = explain_topic(topic)
        bot.send_chat_action(message.chat.id, "typing")
        bot.send_message(message.chat.id, text, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"handle_explain error: {e}")
        bot.reply_to(message, clean_text(f"Error: {str(e)}"))


@bot.message_handler(func=lambda message: True)
def handle_unknown(message):
    text = (
        "Comando no reconocido.\n\n"
        "Usa `/menu` para ver todas las opciones disponibles.\n"
        "Ejemplos:\n"
        "- `/ip 8.8.8.8`\n"
        "- `/domain google.com`\n"
        "- `/url https://ejemplo.com`\n"
        "- `/password MiClave123!`\n"
        "- `/genpass 16`\n"
    )
    bot.send_message(message.chat.id, text, parse_mode="Markdown")


# ===========================================================
# INICIO DEL BOT
# ===========================================================

if __name__ == "__main__":
    print("=" * 60)
    print("BOT OSINT CIBERHACKERCITO - VERSIÓN SEGURA 10.0")
    print(f"Config: {CONFIG_PATH}")
    print("Iniciando bot de Telegram...")
    print("=" * 60)
    try:
        bot_info = bot.get_me()
        print(f"Bot: @{bot_info.username} (ID: {bot_info.id})")
        print("\nComandos activos principales:")
        print("/menu, /start, /help")
        print("/phone, /ip, /email, /domain, /hash")
        print("/url, /ssl, /subdomains, /dns, /image, /social")
        print("/password, /genpass, /analyze, /encrypt, /decrypt")
        print("/report, /history, /scanurl, /explain")
        print("=" * 60)

        bot.polling(none_stop=True, interval=1, timeout=30)
    except Exception as e:
        logger.error(f"Error iniciando el bot: {e}")
        print("Revisa tu config.json (bot_token) y tu conexión a internet.")
