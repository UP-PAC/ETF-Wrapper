
# --- Objective-point success check (Solution B) ---
def _check_objectives_success(wealth_path, objectives):
    """Return True iff all objectives are satisfied at their target months."""
    for obj in objectives:
        m = int(obj.get("month", obj.get("m", 0)))
        amt = float(obj.get("amount", obj.get("amt", 0.0)))
        if m < 0 or m >= len(wealth_path):
            return False
        if wealth_path[m] < amt:
            return False
    return True

import streamlit as st




if "ga_running" not in st.session_state:
    st.session_state.ga_running = False
if "ga_completed" not in st.session_state:
    st.session_state.ga_completed = False
    st.session_state.ga_running = True
# --- GA persistent results containers (added) ---
if "ga_state" not in st.session_state:
    st.session_state.ga_state = {
        "running": False,
        "completed": False,
        "best_fitness": None,
        "best_solution": None,
        "best_dyn": None,
        "best_results": None,
    }
# ----------------------------------------------

import streamlit.components.v1 as components
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
from datetime import datetime
import io
import time
import math
import re
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

st.set_page_config(page_title="ETF Wrapper – Demo UI", page_icon="📈", layout="wide")

# ============================================================
# Colori coerenti per Asset Class (Plotly Express default)
# ============================================================
# In più punti dell'app usiamo grafici a torta/legende per Asset Class.
# Per garantire coerenza visiva (stessa Asset Class -> stesso colore),
# fissiamo una mappa colori deterministica basata sulla sequenza default
# di Plotly Express.

_PX_DEFAULT_DISCRETE_SEQ = list(getattr(px.colors.qualitative, "Plotly", []))

def _build_asset_color_map(asset_list: list[str]) -> dict:
    """Restituisce una color map deterministica per le Asset Class."""
    if not _PX_DEFAULT_DISCRETE_SEQ:
        return {a: "#636EFA" for a in asset_list}  # fallback blu
    return {a: _PX_DEFAULT_DISCRETE_SEQ[i % len(_PX_DEFAULT_DISCRETE_SEQ)] for i, a in enumerate(asset_list)}

import os
import base64
import hmac
from storage import UserStorage

# =======================
# Toggle DEV/PROD (login)
# - DEV: nessun login, user_id="dev"
# - PROD: richiede OIDC via st.login() e usa st.user per user_id
#   Config consigliata:
#     - environment: APP_MODE=prod   (oppure in secrets: [app] mode="prod")
#     - secrets.toml: [auth] ... oppure [auth.<provider>] ...
# =======================

def _get_app_mode() -> str:
    """Ritorna 'prod' o 'dev'. Su Streamlit Cloud legge dai Secrets (APP_MODE) oppure da env."""
    try:
        mode = None
        if hasattr(st, "secrets"):
            # supporta sia: APP_MODE="prod" (top-level) sia: [app] mode="prod"
            mode = st.secrets.get("APP_MODE", None)
            if not mode:
                mode = st.secrets.get("app", {}).get("mode", None)
        if not mode:
            mode = os.getenv("APP_MODE", "dev")
        s = str(mode).strip().lower()
        return s if s else "dev"
    except Exception:
        return "dev"

APP_MODE = _get_app_mode()

# --- Auth mode (Streamlit Cloud Secrets / env) ---
# --- AUTH MODE: secrets.toml (se presente) -> env var -> fallback 'local'
try:
    AUTH_MODE = str(st.secrets["UW_AUTH_MODE"]).strip().lower()
except Exception:
    AUTH_MODE = os.getenv("UW_AUTH_MODE", "local").strip().lower()

if not AUTH_MODE:
    AUTH_MODE = "local"



# =======================
# Local auth persistence (signed token in query params)
# Obiettivo: evitare nuove richieste di login quando la navigazione usa link (?main=...)
# =======================
import hashlib as _hashlib
import time as _time
import base64 as _base64
import urllib.parse as _urlparse

def _get_local_auth_secret() -> bytes:
    """Segreto per firmare i token di persistenza (env/secrets)."""
    try:
        s = None
        if hasattr(st, "secrets"):
            s = st.secrets.get("UW_AUTH_SECRET", None)
        if not s:
            s = os.getenv("UW_AUTH_SECRET", None)
        if not s:
            # fallback: non ideale ma evita crash in demo locale
            s = "uw-local-dev-secret"
        return str(s).encode("utf-8")
    except Exception:
        return b"uw-local-dev-secret"

def _make_local_auth_token(user: str, ttl_days: int = 7) -> str:
    """Crea un token firmato (base64url) valido per ttl_days."""
    user = (user or "").strip()
    ts = int(_time.time())
    payload = f"{user}|{ts}"
    sig = hmac.new(_get_local_auth_secret(), payload.encode("utf-8"), digestmod=_hashlib.sha256).hexdigest()
    raw = f"{payload}|{sig}".encode("utf-8")
    return _base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def _validate_local_auth_token(user: str, token: str, ttl_days: int = 7) -> bool:
    """Valida token firmato e scadenza."""
    try:
        if not user or not token:
            return False
        pad = "=" * (-len(token) % 4)
        raw = _base64.urlsafe_b64decode((token + pad).encode("utf-8")).decode("utf-8")
        parts = raw.split("|")
        if len(parts) != 3:
            return False
        u, ts_str, sig = parts
        if str(u) != str(user):
            return False
        payload = f"{u}|{ts_str}"
        expected = hmac.new(_get_local_auth_secret(), payload.encode("utf-8"), digestmod=_hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(sig), str(expected)):
            return False
        ts = int(ts_str)
        if ts <= 0:
            return False
        age = int(_time.time()) - ts
        return age <= int(ttl_days) * 24 * 3600
    except Exception:
        return False

def _restore_local_auth_from_query_params() -> None:
    """Se nei query params ci sono uwu/uwt validi, ripristina l'autenticazione locale."""
    try:
        if st.session_state.get("auth_logged_in") and st.session_state.get("auth_user"):
            return
        try:
            qp = st.query_params
            uwu = qp.get("uwu", None)
            uwt = qp.get("uwt", None)
        except Exception:
            qp = st.experimental_get_query_params()
            uwu = qp.get("uwu", [None])
            uwt = qp.get("uwt", [None])
        if isinstance(uwu, list):
            uwu = uwu[0] if uwu else None
        if isinstance(uwt, list):
            uwt = uwt[0] if uwt else None
        uwu = str(uwu).strip() if uwu else ""
        uwt = str(uwt).strip() if uwt else ""
        if uwu and uwt and _validate_local_auth_token(uwu, uwt):
            st.session_state["auth_logged_in"] = True
            st.session_state["auth_user"] = uwu
            st.session_state["auth_token"] = uwt
    except Exception:
        pass

def _get_auth_provider() -> str | None:
    try:
        p = st.secrets.get("app", {}).get("auth_provider", None)
        if p is None or str(p).strip() == "":
            return None
        return str(p).strip()
    except Exception:
        return None



def _get_auth_mode() -> str:
    """Modalità autenticazione:
    - 'oidc'  : Streamlit login (default)
    - 'local' : registrazione + user/password gestiti dall'app (demo)
    """
    try:
        m = None
        if hasattr(st, "secrets"):
            m = st.secrets.get("app", {}).get("auth_mode", None)
        if not m:
            m = os.getenv("UW_AUTH_MODE", "oidc")
        m = str(m).strip().lower()
        return m if m in ("oidc", "local") else "oidc"
    except Exception:
        return "oidc"


def _get_storage_config() -> dict:
    """Config storage (backend swappable senza cambiare UI)."""
    backend = None
    dsn = None
    bucket = None
    prefix = "uw"
    try:
        backend = st.secrets.get("storage", {}).get("backend", None)
        dsn = st.secrets.get("storage", {}).get("dsn", None)
        bucket = st.secrets.get("storage", {}).get("bucket", None)
        prefix = st.secrets.get("storage", {}).get("prefix", prefix)
    except Exception:
        pass
    if not backend:
        backend = os.getenv("UW_STORAGE_BACKEND", "filesystem")
    if not dsn:
        dsn = os.getenv("UW_PG_DSN", None)
    if not bucket:
        bucket = os.getenv("UW_OBJECT_BUCKET", None)
    return {"backend": str(backend).strip().lower(), "dsn": dsn, "bucket": bucket, "prefix": prefix}



def _render_local_auth_page() -> None:
    """Pagina unica di accesso/registrazione per AUTH_MODE='local'."""
    import re as _re
    import pickle as _pickle
    import secrets as _secrets
    import hashlib as _hashlib

    # inizializza chiavi sessione (senza sovrascrivere)
    st.session_state.setdefault("auth_logged_in", False)
    st.session_state.setdefault("auth_user", None)

    def _slug(s: str) -> str:
        s = (s or "").strip().lower()
        s = _re.sub(r"[^a-z0-9_\-\.]+", "_", s)
        return s[:64] if s else ""

    AUTH_DIR = Path(__file__).resolve().parent / "auth_storage"
    AUTH_DIR.mkdir(exist_ok=True)
    AUTH_DB = AUTH_DIR / "users.pkl"

    def _load_users() -> dict:
        try:
            if AUTH_DB.exists():
                with open(AUTH_DB, "rb") as f:
                    obj = _pickle.load(f)
                    return obj if isinstance(obj, dict) else {}
        except Exception:
            pass
        return {}

    def _save_users(db: dict) -> None:
        try:
            with open(AUTH_DB, "wb") as f:
                _pickle.dump(db, f)
        except Exception:
            st.error("Impossibile salvare l’utenza (storage non scrivibile).")
            st.stop()

    def _hash_pwd(pwd: str, salt_b64: str | None = None) -> tuple[str, str]:
        pwd_b = (pwd or "").encode("utf-8")
        if not salt_b64:
            salt = _secrets.token_bytes(16)
            salt_b64 = base64.b64encode(salt).decode("ascii")
        else:
            salt = base64.b64decode(salt_b64.encode("ascii"))
        dk = _hashlib.pbkdf2_hmac("sha256", pwd_b, salt, 200_000)
        return base64.b64encode(dk).decode("ascii"), salt_b64

    def _verify_pwd(pwd: str, stored_hash_b64: str, salt_b64: str) -> bool:
        cand_hash, _ = _hash_pwd(pwd, salt_b64=salt_b64)
        try:
            return hmac.compare_digest(cand_hash, stored_hash_b64)
        except Exception:
            return cand_hash == stored_hash_b64

    db = _load_users()

    st.markdown(
        "<div class='uw-card'><h2>Accesso</h2>"
        "<p>Per utilizzare l’app è necessario registrarsi e poi accedere con User e Password.</p>"
        "</div>",
        unsafe_allow_html=True,
    )

    tabs = st.tabs(["Accedi", "Registrati"])

    with tabs[0]:
        user = st.text_input("User", key="_login_user")
        pwd = st.text_input("Password", type="password", key="_login_pwd")
        if st.button("Accedi", use_container_width=True, key="_btn_login"):
            u = _slug(user)
            rec = db.get(u)
            if not u or rec is None:
                st.error("User non valida o non registrata.")
            else:
                if _verify_pwd(pwd, rec.get("pwd_hash", ""), rec.get("pwd_salt", "")):
                    st.session_state["auth_logged_in"] = True
                    st.session_state["auth_user"] = u
                    tok = _make_local_auth_token(u)
                    st.session_state["auth_token"] = tok
                    # Propaga token nei query params per mantenere la sessione anche su navigazione via link
                    try:
                        st.query_params["uwu"] = u
                        st.query_params["uwt"] = tok
                    except Exception:
                        try:
                            st.experimental_set_query_params(uwu=u, uwt=tok)
                        except Exception:
                            pass
                    st.success("Accesso effettuato.")
                    st.rerun()
                else:
                    st.error("Password errata.")

    with tabs[1]:
        st.markdown("<div class='uw-card'><h3>Registrati</h3></div>", unsafe_allow_html=True)
        with st.form(key="_form_register", clear_on_submit=False):
            st.text_input("Nome", key="_reg_nome")
            st.text_input("Cognome", key="_reg_cognome")
            st.text_input("Indirizzo", key="_reg_indirizzo")
            st.text_input("User (scegli un identificativo)", key="_reg_user")
            st.text_input("Password", type="password", key="_reg_pwd1")
            st.text_input("Conferma Password", type="password", key="_reg_pwd2")
            submitted = st.form_submit_button("Crea account", use_container_width=True)

        if submitted:
            nome = str(st.session_state.get("_reg_nome", "")).strip()
            cognome = str(st.session_state.get("_reg_cognome", "")).strip()
            indirizzo = str(st.session_state.get("_reg_indirizzo", "")).strip()
            new_user = str(st.session_state.get("_reg_user", ""))
            pwd1 = str(st.session_state.get("_reg_pwd1", ""))
            pwd2 = str(st.session_state.get("_reg_pwd2", ""))

            u = _slug(new_user)
            if not nome or not cognome or not indirizzo:
                st.error("Compilare Nome, Cognome e Indirizzo.")
            elif not u or len(u) < 3:
                st.error("La User deve avere almeno 3 caratteri (lettere/numeri).")
            elif u in db:
                st.error("Questa User è già registrata.")
            elif not pwd1 or len(pwd1) < 8:
                st.error("La Password deve avere almeno 8 caratteri.")
            elif pwd1 != pwd2:
                st.error("Le due password non coincidono.")
            else:
                h, s = _hash_pwd(pwd1)
                db[u] = {
                    "nome": nome,
                    "cognome": cognome,
                    "indirizzo": indirizzo,
                    "pwd_hash": h,
                    "pwd_salt": s,
                }
                _save_users(db)
                st.success("Registrazione completata. Ora può accedere dalla tab 'Accedi'.")

def _resolve_user_id() -> str:
    """
    Ritorna l'identificativo utente.

    - DEV: user_id="dev"
    - PROD + AUTH_MODE="local": richiede login/registrazione una sola volta per sessione browser.
    - PROD + AUTH_MODE!="local": usa Streamlit OIDC (st.login / st.user).
    """
    # --- DEV mode ---
    if str(APP_MODE).lower() != "prod":
        return "dev"

    mode = str(globals().get("AUTH_MODE", "local")).strip().lower() or "local"

    # --- Local auth (username/password) ---
    if mode == "local":
        _restore_local_auth_from_query_params()
        # Se già loggato, ritorna subito l'utente
        if st.session_state.get("auth_logged_in") and st.session_state.get("auth_user"):
            return str(st.session_state.get("auth_user"))

        # Altrimenti mostra la pagina di accesso/registrazione e ferma l'app
        _render_local_auth_page()
        st.stop()

    # --- Streamlit OIDC login (fallback) ---
    provider = _get_auth_provider()
    try:
        is_logged = bool(getattr(st.user, "is_logged_in", False))
    except Exception:
        is_logged = False

    if not is_logged:
        st.markdown(
            "<div class='uw-card'><h2>Accesso</h2><p>Per utilizzare l’app è necessario effettuare il login.</p></div>",
            unsafe_allow_html=True,
        )
        if st.button("Log in", use_container_width=True):
            if provider is None:
                st.login()
            else:
                st.login(provider)
        st.stop()

    try:
        if hasattr(st.user, "get"):
            email = st.user.get("email", None)
            sub = st.user.get("sub", None)
        else:
            email = getattr(st.user, "email", None)
            sub = None
        if email:
            return str(email)
        if sub:
            return str(sub)
        name = getattr(st.user, "name", None)
        if name:
            return str(name)
    except Exception:
        pass

    return "unknown_user"

    # -----------------------
    # (2) AUTH LOCALE (demo)
    # -----------------------
    import re as _re
    import pickle as _pickle
    import secrets as _secrets
    import hashlib as _hashlib

    def _slug(s: str) -> str:
        s = (s or "").strip().lower()
        s = _re.sub(r"[^a-z0-9_\-\.]+", "_", s)
        return s[:64] if s else ""

    AUTH_DIR = Path(__file__).resolve().parent / "auth_storage"
    AUTH_DIR.mkdir(exist_ok=True)
    AUTH_DB = AUTH_DIR / "users.pkl"

    def _load_users() -> dict:
        try:
            if AUTH_DB.exists():
                with open(AUTH_DB, "rb") as f:
                    obj = _pickle.load(f)
                    return obj if isinstance(obj, dict) else {}
        except Exception:
            pass
        return {}

    def _save_users(db: dict) -> None:
        try:
            with open(AUTH_DB, "wb") as f:
                _pickle.dump(db, f)
        except Exception:
            st.error("Impossibile salvare l’utenza (storage non scrivibile).")
            st.stop()

    def _hash_pwd(pwd: str, salt_b64: str | None = None) -> tuple[str, str]:
        pwd_b = (pwd or "").encode("utf-8")
        if not salt_b64:
            salt = _secrets.token_bytes(16)
            salt_b64 = base64.b64encode(salt).decode("ascii")
        else:
            salt = base64.b64decode(salt_b64.encode("ascii"))
        dk = _hashlib.pbkdf2_hmac("sha256", pwd_b, salt, 200_000)
        return base64.b64encode(dk).decode("ascii"), salt_b64

    def _verify_pwd(pwd: str, stored_hash_b64: str, salt_b64: str) -> bool:
        cand_hash, _ = _hash_pwd(pwd, salt_b64=salt_b64)
        try:
            return hmac.compare_digest(cand_hash, stored_hash_b64)
        except Exception:
            return cand_hash == stored_hash_b64

    if st.session_state.get("_auth_local_ok") and st.session_state.get("_auth_user"):
        return str(st.session_state.get("_auth_user"))

    db = _load_users()

    st.markdown(
        "<div class='uw-card'><h2>Accesso</h2>"
        "<p>Per utilizzare l’app è necessario registrarsi e poi accedere con User e Password.</p>"
        "</div>",
        unsafe_allow_html=True,
    )

    tabs = st.tabs(["Accedi", "Registrati"])

    with tabs[0]:
        user = st.text_input("User", key="_login_user")
        pwd = st.text_input("Password", type="password", key="_login_pwd")
        if st.button("Accedi", use_container_width=True, key="_btn_login"):
            u = _slug(user)
            rec = db.get(u)
            if not u or rec is None:
                st.error("User non valida o non registrata.")
            else:
                if _verify_pwd(pwd, rec.get("pwd_hash",""), rec.get("pwd_salt","")):
                    st.session_state["_auth_local_ok"] = True
                    st.session_state["_auth_user"] = u
                    st.success("Accesso effettuato.")
                    st.rerun()
                else:
                    st.error("Password errata.")

    with tabs[1]:
        st.markdown("<div class='uw-card'><h3>Registrati</h3></div>", unsafe_allow_html=True)
        # Uso di un form per evitare che, al click, Streamlit perda/alteri i valori dei campi
        with st.form(key="_form_register", clear_on_submit=False):
            st.text_input("Nome", key="_reg_nome")
            st.text_input("Cognome", key="_reg_cognome")
            st.text_input("Indirizzo", key="_reg_indirizzo")
            st.text_input("User (scegli un identificativo)", key="_reg_user")
            st.text_input("Password", type="password", key="_reg_pwd1")
            st.text_input("Conferma Password", type="password", key="_reg_pwd2")
            submitted = st.form_submit_button("Crea account", use_container_width=True)

        if submitted:
            nome = str(st.session_state.get("_reg_nome", "")).strip()
            cognome = str(st.session_state.get("_reg_cognome", "")).strip()
            indirizzo = str(st.session_state.get("_reg_indirizzo", "")).strip()
            new_user = str(st.session_state.get("_reg_user", ""))
            pwd1 = str(st.session_state.get("_reg_pwd1", ""))
            pwd2 = str(st.session_state.get("_reg_pwd2", ""))

            u = _slug(new_user)
            if not nome or not cognome or not indirizzo:
                st.error("Compilare Nome, Cognome e Indirizzo.")
            elif not u or len(u) < 3:
                st.error("La User deve avere almeno 3 caratteri (lettere/numeri).")
            elif u in db:
                st.error("Questa User è già registrata.")
            elif not pwd1 or len(pwd1) < 8:
                st.error("La Password deve avere almeno 8 caratteri.")
            elif pwd1 != pwd2:
                st.error("Le due password non coincidono.")
            else:
                h, s = _hash_pwd(pwd1)
                db[u] = {
                    "nome": nome,
                    "cognome": cognome,
                    "indirizzo": indirizzo,
                    "pwd_hash": h,
                    "pwd_salt": s,
                }
                _save_users(db)
                st.success("Registrazione completata. Ora può accedere dalla tab 'Accedi'.")
    st.stop()


# Storage per-utente (filesystem, backend provvisorio)
from pathlib import Path
_USER_ID = _resolve_user_id()

# =======================
# Action handler (query params) – es. logout
# =======================
def _get_query_param_value(key: str) -> str | None:
    """Ritorna il valore di un query-param come stringa (compatibile vecchie API)."""
    try:
        qp = st.query_params
        v = qp.get(key, None)
    except Exception:
        qp = st.experimental_get_query_params()
        v = qp.get(key, [None])
    if isinstance(v, list):
        v = v[0] if v else None
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None

def _handle_app_actions() -> None:
    """Gestisce azioni via query params (es. logout)."""
    action = _get_query_param_value("action")
    if not action:
        return

    if str(action).strip().lower() == "logout":
        # Reset sessione auth (locale o OIDC) + pulizia query params
        try:
            for k in ("auth_logged_in", "auth_user", "auth_token"):
                if k in st.session_state:
                    st.session_state.pop(k, None)
        except Exception:
            pass

        # Pulizia query params (compatibile vecchie API)
        try:
            # Nuova API (st.query_params)
            st.query_params.clear()
        except Exception:
            try:
                st.experimental_set_query_params()
            except Exception:
                pass

        # Se presente, esegue logout OIDC (non necessario in locale, ma innocuo se non supportato)
        try:
            if hasattr(st, "logout"):
                st.logout()
        except Exception:
            pass

        st.rerun()


def _render_floating_logout_button() -> None:
    """Pulsante logout non invasivo (in alto a destra) visibile solo dentro l'app."""
    try:
        if not st.session_state.get("auth_logged_in"):
            return
    except Exception:
        return

    # Stile minimal e non invasivo
    st.markdown(
        """<style>
        .uw-logout { position: fixed; top: 10px; right: 14px; z-index: 99999; }
        .uw-logout a{
            display:inline-block; padding:6px 10px; border-radius: 10px;
            font-size: 12px; text-decoration:none;
            border: 1px solid rgba(0,0,0,0.15);
            background: rgba(255,255,255,0.85);
            color: rgba(0,0,0,0.75);
        }
        .uw-logout a:hover{
            background: rgba(255,255,255,1.0);
            color: rgba(0,0,0,0.9);
            border-color: rgba(0,0,0,0.25);
        }
        </style>""",
        unsafe_allow_html=True,
    )

    # Link-azione: viene gestito da _handle_app_actions all'inizio del run successivo
    st.markdown('<div class="uw-logout"><a href="?action=logout">Logout</a></div>', unsafe_allow_html=True)


_handle_app_actions()
_render_floating_logout_button()

if "_user_storage" not in st.session_state:
    cfg = _get_storage_config()
    st.session_state["_user_storage"] = UserStorage(base_dir=Path(__file__).resolve().parent / "user_storage", backend=cfg["backend"], dsn=cfg["dsn"], bucket=cfg["bucket"], prefix=cfg["prefix"])
_STORAGE: UserStorage = st.session_state["_user_storage"]

# =======================
# Persistenza locale (per mantenere Set e input anche dopo reload / navigazione via link)
# Nota: in ambiente multi-utente condividerebbe lo stesso storage. Per uso demo/single-user va bene.
# =======================
from pathlib import Path
import pickle

_STORAGE_DIR = Path(__file__).resolve().parent / "app_storage"
_STORAGE_DIR.mkdir(exist_ok=True)

_ASSET_SETS_FILE = _STORAGE_DIR / "asset_selections.pkl"

_MARKET_DB_FILE = _STORAGE_DIR / "market_database.pkl"

def _load_pickle(path: Path, default):
    try:
        if path.exists():
            with open(path, "rb") as f:
                return pickle.load(f)
    except Exception:
        pass
    return default

def _save_pickle(path: Path, obj) -> None:
    try:
        with open(path, "wb") as f:
            pickle.dump(obj, f)
    except Exception:
        # non bloccare l'app se non si riesce a scrivere
        pass


def load_persisted_asset_selections_into_session() -> None:
    """Carica i Set (Tools → Portafogli in Asset Class) da storage per-utente, se mancanti in sessione."""
    if "asset_selections" not in st.session_state or not st.session_state.get("asset_selections"):
        persisted = _STORAGE.load(_USER_ID, "asset_selections", {})
        if isinstance(persisted, dict) and persisted:
            st.session_state["asset_selections"] = persisted

def persist_asset_selections_from_session() -> None:
    sets_dict = st.session_state.get("asset_selections", {})
    if isinstance(sets_dict, dict):
        _STORAGE.save(_USER_ID, "asset_selections", sets_dict)




def load_persisted_anagrafiche_into_session() -> None:
    """Carica le Anagrafiche (Clienti/Investitori → Anagrafica) da storage per-utente, se mancanti in sessione."""
    if "anagrafiche" not in st.session_state or not st.session_state.get("anagrafiche"):
        persisted = _STORAGE.load(_USER_ID, "anagrafiche", {})
        if isinstance(persisted, dict) and persisted:
            st.session_state["anagrafiche"] = persisted

def persist_anagrafiche_from_session() -> None:
    anags = st.session_state.get("anagrafiche", {})
    if isinstance(anags, dict):
        _STORAGE.save(_USER_ID, "anagrafiche", anags)
    # Coerenza: se l'utente cancella un'anagrafica, aggiorniamo anche i portafogli associati
    cp = st.session_state.get("client_portfolios", {})
    if isinstance(cp, dict):
        _STORAGE.save(_USER_ID, "client_portfolios", cp)

def load_persisted_market_database_into_session() -> None:
    """Carica il Database Mercati (Tools → Database Mercati) da storage per-utente, se mancante in sessione."""
    if st.session_state.get("market_database") is None:
        persisted = _STORAGE.load(_USER_ID, "market_database", None)
        if isinstance(persisted, dict) and isinstance(persisted.get("df"), pd.DataFrame):
            st.session_state["market_database"] = {
                "df": persisted["df"],
                "source_name": persisted.get("source_name", ""),
                "saved_at": persisted.get("saved_at", ""),
            }

def persist_market_database_from_session() -> None:
    db = st.session_state.get("market_database", None)
    if isinstance(db, dict) and isinstance(db.get("df"), pd.DataFrame):
        _STORAGE.save(_USER_ID, "market_database", db)



def load_persisted_portfolios_into_session() -> None:
    """Carica i Portafogli (Crea Soluzione di Investimento) da storage per-utente, se mancanti in sessione."""
    if "portfolios" not in st.session_state or not isinstance(st.session_state.get("portfolios"), dict) or len(st.session_state.get("portfolios", {})) == 0:
        persisted = _STORAGE.load(_USER_ID, "portfolios", {})
        if isinstance(persisted, dict) and persisted:
            st.session_state["portfolios"] = persisted

def persist_portfolios_from_session() -> None:
    pf = st.session_state.get("portfolios", {})
    if isinstance(pf, dict):
        _STORAGE.save(_USER_ID, "portfolios", pf)

# =======================
# CSS – TEMA CHIARO + UI premium
# =======================
CSS = """
<style>
  .stApp { background: #f6f7fb; color: #1f2937; }
  section.main > div { padding-top: 0rem; }

  #MainMenu {visibility:hidden;}
  footer {visibility:hidden;}
  header {visibility:hidden;}

  /* Navbar */
  .uw-navbar-wrap{
    position: sticky; top: 0; z-index: 9999;
    padding: 0; /* gestito da strip + barra */
    background: transparent;
  }
  .uw-topstrip{
    height: 96px;
    background: linear-gradient(90deg,
      rgba(37,99,235,0.92),
      rgba(14,165,164,0.88),
      rgba(34,197,94,0.84));
    border-bottom: 1px solid rgba(255,255,255,0.18);
  }
  .uw-topstrip-inner{
    max-width: 1300px;
    margin: 0 auto;
    height: 96px;
    display:flex;
    align-items:center;
    padding: 0 18px;
  }
  .uw-topstrip .uw-brand{min-width: unset;}
  .uw-topstrip .uw-brand-title b{color: rgba(255,255,255,0.96); font-size: 22px; letter-spacing: 0.2px;}
  .uw-topstrip .uw-brand-title span{color: rgba(255,255,255,0.78); font-size: 14px;}
  .uw-topstrip .uw-avatar{background: rgba(255,255,255,0.20); border-color: rgba(255,255,255,0.30); color: rgba(255,255,255,0.92);}
  .uw-topstrip .uw-logout{display:inline-flex; align-items:center; padding: 8px 12px; border-radius: 14px; text-decoration:none; font-weight:700; font-size: 13px; background: rgba(255,255,255,0.16); border: 1px solid rgba(255,255,255,0.28); color: rgba(255,255,255,0.92);} 
  .uw-topstrip .uw-logout:hover{background: rgba(255,255,255,0.22); border-color: rgba(255,255,255,0.40);} 
  
  .uw-topstrip-right{
    display:flex;
    align-items:center;
    justify-content:flex-end;
    gap: 12px;
  }
  .uw-topstrip-airlogo{
    display:flex;
    flex-direction:column;
    align-items:center;
    justify-content:center;
    padding: 8px 12px;
    border-radius: 14px;
    background: rgba(255,255,255,0.14);
    border: 1px solid rgba(255,255,255,0.26);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
  }
  .uw-topstrip-airlogo .lbl{
    margin-top: 4px;
    font-size: 12px;
    font-weight: 700;
    color: rgba(255,255,255,0.92);
    letter-spacing: 0.25px;
    line-height: 1;
  }

.uw-topstrip .uw-pill{background: rgba(255,255,255,0.18); border-color: rgba(255,255,255,0.28); color: rgba(255,255,255,0.92);}
  .uw-navbar-bar{
    padding: 12px 18px;
    background: rgba(255,255,255,0.88);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    border-bottom: 1px solid rgba(0,0,0,0.06);
  }
  .uw-navbar{
    max-width: 1300px; margin: 0 auto;
    display:flex; align-items:center; gap:18px;
  }
  .uw-brand{display:flex; align-items:center; gap:10px; min-width:240px;}
  .uw-logo{
    width:40px; height:40px; border-radius:14px;
    display:flex; align-items:center; justify-content:center;
    overflow:hidden;
  }
  .uw-brand-title{display:flex; flex-direction:column; line-height:1.1;}
  .uw-brand-title b{font-size:15px; color:#111827;}
  .uw-brand-title span{font-size:12px; color:#6b7280;}

  .uw-menus{display:flex; align-items:center; gap:10px; flex:1;}
  .uw-dd{position:relative; display:inline-flex; align-items:center;}
  .uw-dd-btn{
    display:inline-flex; align-items:center; gap:8px;
    padding: 10px 12px; border-radius: 10px;
    font-size: 13px; white-space: nowrap;
    color: #1f2937;
    border: 1px solid #e5e7eb;
    background: #ffffff;
    transition: all 160ms ease;
    user-select:none;
  }
  .uw-dd-btn:hover{ background:#f3f4f6; border-color:#d1d5db; }
  .uw-dd-btn.primary{ border-color:#2563eb; background:#eff6ff; color:#1d4ed8; }
  .uw-caret{
    width:0; height:0;
    border-left:5px solid transparent;
    border-right:5px solid transparent;
    border-top:6px solid #6b7280;
    margin-top: 1px;
  }
  .uw-dd-panel{
    position:absolute; top:44px; left:0;
    min-width: 260px;
    padding: 10px;
    border-radius: 14px;
    background: #ffffff;
    border: 1px solid #e5e7eb;
    box-shadow: 0 20px 40px rgba(0,0,0,0.10);
    opacity: 0;
    transform: translateY(6px);
    pointer-events: none;
    transition: all 160ms ease;
  }
  .uw-dd:hover .uw-dd-panel{ opacity: 1; transform: translateY(0); pointer-events: auto; }
  .uw-dd-item{
    display:flex; flex-direction:column; gap:2px;
    padding: 10px; border-radius: 10px;
    text-decoration:none; color:#1f2937;
    transition: background 140ms ease;
  }
  .uw-dd-item:hover{ background:#f3f4f6; }
  .uw-dd-item b{ font-size:13px; }
  .uw-dd-item span{ font-size:12px; color:#6b7280; }

  .uw-right{display:flex; align-items:center; gap:10px; min-width:260px; justify-content:flex-end;}
  .uw-pill{
    padding: 8px 12px; border-radius: 999px;
    border: 1px solid #e5e7eb;
    background: #ffffff;
    font-size: 12px; color:#374151;
  }
  .uw-avatar{
    width:34px; height:34px; border-radius:10px;
    background:#f3f4f6; border: 1px solid #e5e7eb;
    display:grid; place-items:center;
    font-weight:700; color:#374151;
  }

  /* Content shell */
  .uw-content{max-width:1300px; margin: 18px auto 34px auto; padding: 0 10px;}
  .uw-breadcrumb{
    display:flex; align-items:center; gap:8px;
    font-size: 12px; color:#6b7280;
    margin: 6px 2px 14px 2px;
  }
  .uw-dot{width:4px; height:4px; border-radius: 99px; background:#cbd5e1;}

  .uw-shell{
    border-radius: 20px;
    background: #ffffff;
    border: 1px solid #e5e7eb;
    box-shadow: 0 30px 60px rgba(0,0,0,0.06);
    overflow: hidden;
  }
  .uw-shell-header{
    padding: 18px 18px 16px 18px;
    border-bottom: 1px solid #eef2f7;
    background: linear-gradient(180deg, #ffffff, #fbfcff);
    display:flex; align-items:flex-start; justify-content:space-between; gap:18px;
  }
  .uw-title{display:flex; flex-direction:column; gap:6px;}
  .uw-title h1{margin:0; font-size: 18px; color:#111827; letter-spacing: 0.2px;}
  .uw-title p{margin:0; font-size: 12.5px; color:#6b7280; line-height: 1.5; max-width: 900px;}
  .uw-badge{
    padding: 2px 8px; border-radius: 999px;
    font-size: 11px; color:#1d4ed8;
    background:#eff6ff; border: 1px solid #dbeafe;
    margin-left: 8px;
  }

  /* Cards */
  .uw-card{
    border-radius: 18px;
    border: 1px solid #e5e7eb;
    background: #ffffff;
    box-shadow: 0 18px 40px rgba(0,0,0,0.04);
    padding: 14px;
    margin-bottom: 14px;
  }
  .uw-card h2{margin:0; font-size: 14px; color:#111827;}
  .uw-card p{margin:8px 0 0 0; font-size: 12.5px; color:#6b7280; line-height: 1.6;}

  /* Buttons alignment row */
  .uw-actions{
    display:flex; gap:10px; flex-wrap:wrap;
    padding-top: 6px;
  }

  /* Final grid preview: light but not white */
  .uw-gridwrap{
    border-radius: 18px;
    border: 1px solid #e5e7eb;
    overflow: hidden;
    background: #f1f5f9;
  }
  table.uw-grid{
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
  }
  table.uw-grid th{
    padding: 10px 10px;
    background: #eaf0f6;
    border-bottom: 1px solid #dde6ef;
    color: #111827;
    text-align: center;
    font-weight: 700;
  }
  table.uw-grid td{
    padding: 10px 10px;
    border-bottom: 1px solid #e6eef6;
    border-right: 1px solid #e6eef6;
    text-align: center;
    color:#111827;
    font-variant-numeric: tabular-nums;
    background: rgba(255,255,255,0.35);
  }
  table.uw-grid td:first-child{
    text-align: left;
    font-weight: 700;
    color:#111827;
    background: #eaf0f6;
    border-right: 1px solid #dde6ef;
    white-space: nowrap;
  }
  table.uw-grid tr:last-child td{ border-bottom: none; }
  table.uw-grid td:last-child{ border-right: none; }

  @media (max-width: 1050px){
    .uw-right{display:none;}
  }

  /* ---------- Streamlit widgets: look uniforme ---------- */
  .stButton > button{
    border-radius: 12px !important;
    padding: 0.55rem 0.95rem !important;
    border: 1px solid rgba(0,0,0,0.08) !important;
    box-shadow: 0 10px 22px rgba(0,0,0,0.06) !important;
    transition: all 140ms ease !important;
  }
  .stButton > button:hover{
    transform: translateY(-1px);
    box-shadow: 0 14px 28px rgba(0,0,0,0.08) !important;
  }
  .stButton > button[kind="primary"]{
    border: 1px solid rgba(37,99,235,0.35) !important;
    background: linear-gradient(135deg, rgba(37,99,235,0.95), rgba(14,165,164,0.95)) !important;
    color: #ffffff !important;
  }
  div[data-baseweb="input"] > div,
  div[data-baseweb="select"] > div{
    border-radius: 12px !important;
    border-color: rgba(0,0,0,0.10) !important;
    box-shadow: none !important;
  }
  div[data-baseweb="select"] > div:hover,
  div[data-baseweb="input"] > div:hover{
    border-color: rgba(37,99,235,0.28) !important;
  }
  div[role="radiogroup"] > label{
    background: rgba(255,255,255,0.85);
    border: 1px solid rgba(0,0,0,0.07);
    padding: 8px 10px;
    border-radius: 12px;
    margin-right: 8px;
  }
  details{
    border-radius: 14px !important;
    border: 1px solid rgba(0,0,0,0.08) !important;
    background: rgba(255,255,255,0.9) !important;
    box-shadow: 0 14px 30px rgba(0,0,0,0.04) !important;
  }


  .uw-logo-img{height:40px;width:auto;display:block;object-fit:contain;}

  /* --- Pulsanti specifici: verde chiaro (solo estetica) --- */
  button[aria-label="Simula"],
  button[aria-label="Step 1: Genera scenari Monte Carlo"],
  button[aria-label="Step 2: Esegui Algoritmo Genetico"]{
    border: 1px solid rgba(34,197,94,0.55) !important;
    background: rgba(34,197,94,0.22) !important;
    color: rgba(20,83,45,1) !important;
  }
  button[aria-label="Simula"]:hover,
  button[aria-label="Step 1: Genera scenari Monte Carlo"]:hover,
  button[aria-label="Step 2: Esegui Algoritmo Genetico"]:hover{
    background: rgba(34,197,94,0.30) !important;
  }

  /* --- Titoli piccoli usati in alcune sezioni --- */
  .uw-sec-title-sm{
    font-size: 1.05rem;
    font-weight: 700;
    margin: 0.25rem 0 0.5rem 0;
  }
  .uw-h3-sm{
    font-size: 1.12rem !important;
    margin: 0 0 0.25rem 0 !important;
  }
  .uw-metric-sm{
    background: rgba(255,255,255,0.92);
    border: 1px solid rgba(0,0,0,0.06);
    border-radius: 12px;
    padding: 0.55rem 0.75rem;
    box-shadow: 0 10px 22px rgba(0,0,0,0.05);
  }
  .uw-metric-sm .uw-metric-label{
    font-size: 0.78rem;
    color: rgba(31,41,55,0.85);
    line-height: 1.05;
    margin-bottom: 0.12rem;
    font-weight: 600;
  }
  .uw-metric-sm .uw-metric-value{
    font-size: 1.18rem;
    font-weight: 800;
    color: rgba(17,24,39,1);
    line-height: 1.1;
  }


  /* Metric value più piccolo (solo estetica) */
  .uw-metric-value-xs{ font-size:18px !important; font-weight:800; margin-top:2px; }
  .uw-sec-title-sm{ font-size:22px !important; font-weight:800; margin: 0 0 6px 0; }

</style>
"""

NAVBAR_HTML_TEMPLATE = """
<div class="uw-navbar-wrap">
  <div class="uw-topstrip">
    <div class="uw-topstrip-inner">
      <div class="uw-brand">
        <div class="uw-logo">
          {logo_html}
        </div>
        <div class="uw-brand-title">
          <b>ETF Wrapper</b>
          <span>Portfolio Construction App</span>
        </div>
      </div>

      <div class="uw-topstrip-right">
        <div class="uw-topstrip-airlogo">
          <div class="lbl">UI</div>
          <div class="val">Premium</div>
        </div>
        {logout_html}
        <div class="uw-avatar">{avatar_txt}</div>
      </div>
    </div>
  </div>

  <div class="uw-navbar">
    <div class="uw-navbar-inner">
      <div class="uw-menus">

        <div class="uw-dd">
          <a class="uw-dd-btn" href="?{auth_qs}main=Clienti%2FInvestitori" target="_self">
            Clienti/Investitori <span class="uw-caret"></span>
          </a>
          <div class="uw-dd-panel">
            <a class="uw-dd-item" href="?{auth_qs}main=Clienti%2FInvestitori" target="_self">
              <b>Anagrafica</b><span>Gestione profili e dati cliente</span>
            </a>
          </div>
        </div>

        <div class="uw-dd">
          <a class="uw-dd-btn" href="?{auth_qs}main=Crea%20Soluzione%20di%20Investimento" target="_self">
            Crea Soluzione di Investimento <span class="uw-caret"></span>
          </a>
          <div class="uw-dd-panel">
            <a class="uw-dd-item" href="?{auth_qs}main=Crea%20Soluzione%20di%20Investimento&crea=Asset-Only" target="_self">
              <b>Asset-Only</b><span>Asset Allocation, Life Cycle, Monte Carlo</span>
            </a>
            <a class="uw-dd-item" href="?{auth_qs}main=Crea%20Soluzione%20di%20Investimento&crea=Goal-Based%20Investing" target="_self">
              <b>Goal-Based Investing</b><span>Soluzioni dinamiche per obiettivi</span>
            </a>
          </div>
        </div>

        <div class="uw-dd">
          <a class="uw-dd-btn" href="?{auth_qs}main=Selezione%20Prodotti" target="_self">
            Selezione Prodotti <span class="uw-caret"></span>
          </a>
          <div class="uw-dd-panel">
            <a class="uw-dd-item" href="?{auth_qs}main=Selezione%20Prodotti" target="_self">
              <b>Selezione Prodotti</b><span>Scelta degli strumenti per l’allocazione</span>
            </a>
          </div>
        </div>
        <div class="uw-dd">
          <a class="uw-dd-btn" href="?{auth_qs}main=Monitoraggio%20Portafoglio" target="_self">
            Monitoraggio Portafoglio <span class="uw-caret"></span>
          </a>
          <div class="uw-dd-panel">
            <a class="uw-dd-item" href="?{auth_qs}main=Monitoraggio%20Portafoglio" target="_self">
              <b>Monitoraggio Portafoglio</b><span>Andamento, scostamenti e alert di controllo</span>
            </a>
          </div>
        </div>

        <div class="uw-dd">
          <a class="uw-dd-btn" href="?{auth_qs}main=Analisi%20Asset%20Allocation" target="_self">
            Analisi Asset Allocation <span class="uw-caret"></span>
          </a>
          <div class="uw-dd-panel">
            <a class="uw-dd-item" href="?{auth_qs}main=Analisi%20Asset%20Allocation" target="_self">
              <b>Analisi Asset Allocation</b><span>Backtesting, rischio/rendimento, indicatori</span>
            </a>
          </div>
        </div>
<div class="uw-dd">
          <a class="uw-dd-btn" href="?{auth_qs}main=Tools&tools=Griglie%20Clientela" target="_self">
            Tools <span class="uw-caret"></span>
          </a>
          <div class="uw-dd-panel">
            <a class="uw-dd-item" href="?{auth_qs}main=Tools&tools=Griglie%20Clientela" target="_self">
              <b>Griglie Clientela</b><span>Profili e griglie obiettivo/rischio</span>
            </a>
            <a class="uw-dd-item" href="?{auth_qs}main=Tools&tools=Portafogli%20in%20Asset%20Class" target="_self">
              <b>Portafogli in Asset Class</b><span>Frontiera e portafogli caricati</span>
            </a>
            <a class="uw-dd-item" href="?{auth_qs}main=Tools&tools=Database%20Prodotti" target="_self">
              <b>Database Prodotti</b><span>Upload universo ETF/fondi e metriche</span>
            </a>
            <a class="uw-dd-item" href="?{auth_qs}main=Tools&tools=Database%20Mercati" target="_self">
              <b>Database Mercati</b><span>Upload rendimenti e controlli qualità</span>
            </a>
          </div>
        </div>

      </div>
    </div>
  </div>
</div>
"""


def _avatar_initials_from_user() -> str:
    # Default
    initials = "UP"
    if APP_MODE != "prod":
        return initials
    try:
        if not bool(getattr(st.user, "is_logged_in", False)):
            return initials
        # Proviamo name/cognome o email
        name = None
        if hasattr(st.user, "get"):
            name = st.user.get("name") or st.user.get("preferred_username") or st.user.get("email")
        if not name:
            name = getattr(st.user, "name", None) or getattr(st.user, "email", None)
        if not name:
            return initials
        s = str(name).strip()
        if "@" in s:
            s = s.split("@")[0]
        parts = [p for p in re.split(r"[\s\._\-]+", s) if p]
        if len(parts) == 1:
            initials = parts[0][:2].upper()
        else:
            initials = (parts[0][0] + parts[-1][0]).upper()
        return initials
    except Exception:
        return initials


def _build_logo_html() -> str:
    """Restituisce HTML per il logo in header.
    Usa Logo.png (nella stessa cartella dello script) se disponibile, incorporandolo come data URI
    per essere compatibile con Streamlit (evita problemi di path/static serving).
    Fallback: SVG di default.
    """
    try:
        # percorso Logo.png: stessa cartella dello script
        base_dir = os.path.dirname(__file__) if "__file__" in globals() else os.getcwd()
        logo_path = os.path.join(base_dir, "Logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
            # altezza allineata alla topstrip (40px) – CSS gestisce il resto
            return f'<img class="uw-logo-img" src="data:image/png;base64,{b64}" alt="Logo" />'
    except Exception:
        pass

    # fallback svg (logo semplice)
    return '''
      <svg viewBox="0 0 64 64" width="40" height="40" aria-hidden="true">
        <defs>
          <linearGradient id="g1" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#2563eb"/>
            <stop offset="55%" stop-color="#0ea5a4"/>
            <stop offset="100%" stop-color="#22c55e"/>
          </linearGradient>
        </defs>
        <rect x="8" y="8" width="48" height="48" rx="14" fill="url(#g1)"/>
        <path d="M18 40 L28 30 L36 38 L46 24" stroke="rgba(255,255,255,0.92)" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    '''


def render_navbar() -> None:
    """Render della navbar premium.
    Usa st.html (Streamlit recente) se disponibile; altrimenti fallback su st.markdown unsafe.

    Nota: per AUTH_MODE='local' la navbar usa link con query params; per evitare nuove richieste di login
    propaghiamo (se presente) il token firmato uwu/uwt nei link.
    """
    logout_html = ""  # logout disabilitato (richiesta utente)

    # Prefisso querystring per persistenza auth locale (se disponibile)
    auth_qs = ""
    try:
        if APP_MODE == "prod" and str(globals().get("AUTH_MODE", "local")).strip().lower() == "local":
            import urllib.parse as _urlparse
            try:
                qp = st.query_params
                uwu = qp.get("uwu", None)
                uwt = qp.get("uwt", None)
            except Exception:
                qp = st.experimental_get_query_params()
                uwu = qp.get("uwu", [None])
                uwt = qp.get("uwt", [None])
            if isinstance(uwu, list):
                uwu = uwu[0] if uwu else None
            if isinstance(uwt, list):
                uwt = uwt[0] if uwt else None

            uwu = (uwu or st.session_state.get("auth_user") or "").strip()
            uwt = (uwt or st.session_state.get("auth_token") or "").strip()

            if uwu and uwt:
                auth_qs = f"uwu={_urlparse.quote(str(uwu))}&uwt={_urlparse.quote(str(uwt))}&"
    except Exception:
        auth_qs = ""

    avatar_txt = _avatar_initials_from_user()
    logo_html = _build_logo_html()
    html = NAVBAR_HTML_TEMPLATE.format(logout_html=logout_html, avatar_txt=avatar_txt, logo_html=logo_html, auth_qs=auth_qs)

    # Streamlit recente espone st.html() (render HTML in-page). Se non disponibile, fallback a markdown.
    try:
        st.html(html)  # type: ignore[attr-defined]
    except Exception:
        st.markdown(html, unsafe_allow_html=True)


def default_risk_names(n: int) -> list[str]:
    base = ["Bassa", "Medio-Bassa", "Medio-Alta", "Alta"]
    if n <= len(base):
        return base[:n]
    return base + [f"Classe {i}" for i in range(len(base)+1, n+1)]

def default_horizon_names(n: int) -> list[str]:
    base = ["Brevissimo", "Breve", "Medio-Lungo", "Lungo", "Molto Lungo", "Lunghissimo"]
    if n <= len(base):
        return base[:n]
    return base + [f"Orizzonte {i}" for i in range(len(base)+1, n+1)]

def build_grid_preview_html(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    rows = list(df.index)

    html = ['<div class="uw-gridwrap">', '<table class="uw-grid">']
    html.append("<tr><th>Orizzonte / Rischio</th>" + "".join([f"<th>{c}</th>" for c in cols]) + "</tr>")

    for r in rows:
        html.append("<tr>")
        html.append(f"<td>{r}</td>")
        for c in cols:
            v = df.loc[r, c]
            try:
                vx = float(v)
            except Exception:
                vx = 0.0
            html.append(f"<td>{vx:.0f}%</td>")
        html.append("</tr>")

    html.append("</table></div>")
    return "".join(html)


def load_persisted_client_grids_into_session() -> None:
    """Carica Griglie Clientela (Tools → Griglie Clientela) da storage per-utente, se mancanti in sessione."""
    if "client_classes" not in st.session_state or not isinstance(st.session_state.get("client_classes"), dict) or len(st.session_state.get("client_classes", {})) == 0:
        persisted = _STORAGE.load(_USER_ID, "client_classes", {})
        if isinstance(persisted, dict) and persisted:
            st.session_state["client_classes"] = persisted

    if "client_portfolios" not in st.session_state or not isinstance(st.session_state.get("client_portfolios"), dict) or len(st.session_state.get("client_portfolios", {})) == 0:
        persisted = _STORAGE.load(_USER_ID, "client_portfolios", {})
        if isinstance(persisted, dict) and persisted:
            st.session_state["client_portfolios"] = persisted

def persist_client_grids_from_session() -> None:
    cc = st.session_state.get("client_classes", {})
    if isinstance(cc, dict):
        _STORAGE.save(_USER_ID, "client_classes", cc)
    cp = st.session_state.get("client_portfolios", {})
    if isinstance(cp, dict):
        _STORAGE.save(_USER_ID, "client_portfolios", cp)

def ensure_storage():
    if "client_classes" not in st.session_state:
        # Dict: name -> payload
        st.session_state["client_classes"] = {}
    if "client_portfolios" not in st.session_state:
        st.session_state["client_portfolios"] = {}

    # reload per-utente (utile dopo cambio sezione / reload sessione)
    load_persisted_client_grids_into_session()

def top_nav_controls():
    """
    Navigazione reale (Streamlit) coerente con la navbar HTML (link con query-params).
    Ritorna: (main_section, tools_subsection, crea_subsection).
    """
    valid_main = ["Clienti/Investitori", "Crea Soluzione di Investimento", "Selezione Prodotti", "Monitoraggio Portafoglio", "Analisi Asset Allocation", "Tools"]
    valid_tools = ["Griglie Clientela", "Portafogli in Asset Class", "Database Mercati", "Database Prodotti"]
    valid_crea = ["Asset-Only", "Goal-Based Investing"]

    # default
    if "main_section" not in st.session_state:
        st.session_state["main_section"] = "Clienti/Investitori"
    if "tools_subsection" not in st.session_state:
        st.session_state["tools_subsection"] = "Griglie Clientela"
    if "crea_subsection" not in st.session_state:
        st.session_state["crea_subsection"] = "Asset-Only"

    # read query params (compatibilità)
    try:
        qp = st.query_params  # Streamlit >= 1.30
        main_q = qp.get("main", None)
        tools_q = qp.get("tools", None)
        crea_q = qp.get("crea", None)
    except Exception:
        qp = st.experimental_get_query_params()
        main_q = qp.get("main", [None])
        tools_q = qp.get("tools", [None])
        crea_q = qp.get("crea", [None])

    # normalizza (stringa singola vs lista)
    if isinstance(main_q, list):
        main_q = main_q[0] if len(main_q) else None
    if isinstance(tools_q, list):
        tools_q = tools_q[0] if len(tools_q) else None
    if isinstance(crea_q, list):
        crea_q = crea_q[0] if len(crea_q) else None

    # applica se valido
    if isinstance(main_q, str) and main_q.strip() in valid_main:
        st.session_state["main_section"] = main_q.strip()

    if st.session_state["main_section"] == "Tools":
        if isinstance(tools_q, str) and tools_q.strip() in valid_tools:
            st.session_state["tools_subsection"] = tools_q.strip()

    if st.session_state["main_section"] == "Crea Soluzione di Investimento":
        if isinstance(crea_q, str) and crea_q.strip() in valid_crea:
            st.session_state["crea_subsection"] = crea_q.strip()
        else:
            # se il parametro non è presente, mantengo default/precedente
            if st.session_state.get("crea_subsection") not in valid_crea:
                st.session_state["crea_subsection"] = "Asset-Only"

    return st.session_state["main_section"], st.session_state["tools_subsection"], st.session_state["crea_subsection"]

def load_to_form(payload: dict):
    # Carico valori in session_state dei widget
    st.session_state["risk_n"] = int(payload["risk_n"])
    st.session_state["hor_n"] = int(payload["hor_n"])

    for i, name in enumerate(payload["risk_names"]):
        st.session_state[f"risk_name_{i}"] = name

    for i, (hn, y0, y1) in enumerate(payload["horizons"]):
        st.session_state[f"hor_name_{i}"] = hn
        st.session_state[f"hor_from_{i}"] = int(y0)
        if y1 is not None:
            st.session_state[f"hor_to_{i}"] = int(y1)

def build_grid_highlight_html(df: pd.DataFrame, highlight_row: str | None, highlight_col: str | None) -> str:
    """Render della griglia con evidenza della cella (row,col) selezionata."""
    cols = list(df.columns)
    rows = list(df.index)

    html = ['<div class="uw-gridwrap">', '<table class="uw-grid">']
    html.append("<tr><th>Orizzonte / Rischio</th>" + "".join([f"<th>{c}</th>" for c in cols]) + "</tr>")

    for r in rows:
        html.append("<tr>")
        html.append(f"<td>{r}</td>")
        for c in cols:
            v = df.loc[r, c]
            try:
                vx = float(v)
            except Exception:
                vx = 0.0
            is_hl = (highlight_row == r) and (highlight_col == c)
            style = ' style="background: rgba(14,165,233,0.18); border: 1px solid rgba(14,165,233,0.55);"' if is_hl else ""
            html.append(f"<td{style}>{vx:.0f}%</td>")
        html.append("</tr>")

    html.append("</table></div>")
    return "".join(html)

    df = payload["weights_df"].copy()
    st.session_state["weights_df"] = df

    # Pre-carico i selectbox cella per cella (chiavi coerenti con la griglia: w__{r}__{c})
    row_labels = list(df.index)
    col_labels = list(df.columns)
    for r in row_labels:
        for c in col_labels:
            cell_key = f"w__{r}__{c}"
            st.session_state[cell_key] = int(df.loc[r, c])

        # Pre-carico anche i selectbox cella per cella (chiavi coerenti con la griglia: w__{r}__{c})
    

def build_payload(class_name: str, risk_n: int, risk_names: list[str], hor_n: int, horizons: list[tuple], df: pd.DataFrame):
    return {
        "name": class_name,
        "risk_n": int(risk_n),
        "risk_names": list(risk_names),
        "hor_n": int(hor_n),
        "horizons": list(horizons),
        "weights_df": df.copy(),
        "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

# =======================
# Tools → Portafogli in Asset Class (UI)
# =======================
def ensure_asset_selection_storage():
    if "asset_selections" not in st.session_state:
        st.session_state["asset_selections"] = {}  # name -> payload

def build_asset_set_template_excel_bytes():
    """Crea un template Excel (bytes) per l'upload 'Input' + 'Portafogli'."""
    allowed_macros = ["Liquidità", "Obbligazionario", "Azionario", "Alternativo"]

    # Esempio minimo (3 asset class) – l'utente può sostituire/estendere liberamente
    asset_names = ["Liquidità EUR", "Obbligazionario Globale", "Azionario Globale"]
    macros = ["Liquidità", "Obbligazionario", "Azionario"]
    exp_ret = [0.02, 0.03, 0.06]
    vol = [0.01, 0.05, 0.15]
    corr = np.array([
        [1.00, 0.10, 0.00],
        [0.10, 1.00, 0.20],
        [0.00, 0.20, 1.00],
    ])

    # Foglio Input: prime 4 colonne + colonna 5 vuota + matrice correlazioni dalla 6ª colonna
    df_in = pd.DataFrame({
        "Asset Class": asset_names,
        "Macro-Asset Class": macros,
        "Rendimento atteso annuo": exp_ret,
        "Deviazione standard annua": vol,
        "": [""] * len(asset_names),  # colonna placeholder (5ª)
    })
    # Aggiungo le colonne della matrice correlazioni (header = asset class)
    for j, an in enumerate(asset_names):
        df_in[an] = corr[:, j]

    # Foglio Portafogli
    df_pf = pd.DataFrame({
        "Nome Portafoglio": ["Portafoglio 1", "Portafoglio 2"],
        asset_names[0]: [0.20, 0.10],
        asset_names[1]: [0.50, 0.40],
        asset_names[2]: [0.30, 0.50],
    })

    bio = io.BytesIO()
    with pd.ExcelWriter(bio, engine="openpyxl") as writer:
        df_in.to_excel(writer, sheet_name="Input", index=False)
        df_pf.to_excel(writer, sheet_name="Portafogli", index=False)

        # Nota rapida (rende il template auto-esplicativo)
        note = pd.DataFrame({
            "NOTE": [
                "Foglio 'Input': dalla 6ª colonna in poi inserire la matrice delle correlazioni (valori in [-1,1], diagonale=1, simmetrica).",
                "Foglio 'Portafogli': i pesi devono essere numerici, non negativi, e sommare a 1 (o 100 se in percentuale).",
                "Le Macro-Asset Class ammesse sono: " + ", ".join(allowed_macros) + "."
            ]
        })
        note.to_excel(writer, sheet_name="Istruzioni", index=False)

    bio.seek(0)
    return bio.getvalue()

def parse_excel_asset_set(file):
    """
    Excel schema richiesto (1 file, 2 fogli):
    A) Foglio "Input"
       - Colonna 1: nomi Asset Class
       - Colonna 2: nomi Macro-Asset Class (Liquidità, Obbligazionario, Azionario, Alternativo)
       - Colonna 3: rendimenti attesi annui
       - Colonna 4: deviazioni standard annue
       - Da colonna 6 in poi: matrice delle correlazioni (n_asset x n_asset)

    B) Foglio "Portafogli"
       - Righe: portafogli
       - Colonne: pesi per asset class (header = nomi asset class, coerenti con foglio Input)
       - Prima colonna opzionale: nome portafoglio (se presente viene usata come indice)

    Output:
      assets_df (Asset Class, Macro-Asset Class),
      exp_ret (Series), vol (Series), corr (DataFrame), alloc_df (DataFrame)
    """
    try:
        xls = pd.ExcelFile(file)
    except Exception as e:
        raise ValueError(f"Impossibile leggere il file Excel: {e}")

    if "Input" not in xls.sheet_names:
        raise ValueError('Manca il foglio "Input" nel file Excel.')
    if "Portafogli" not in xls.sheet_names:
        raise ValueError('Manca il foglio "Portafogli" nel file Excel.')

    # ---- Foglio Input ----
    df_in = pd.read_excel(xls, sheet_name="Input")
    if df_in.shape[1] < 6:
        raise ValueError('Il foglio "Input" deve avere almeno 6 colonne (correlazioni dalla 6ª).')

    # Prendo le prime 4 colonne per definizione asset class
    ac = df_in.iloc[:, 0].astype(str)
    macro = df_in.iloc[:, 1].astype(str)

    # Righe valide: asset class non vuota
    valid_mask = ac.str.strip().replace({"nan": ""}) != ""
    if valid_mask.sum() == 0:
        raise ValueError('Nel foglio "Input" non risultano nomi di Asset Class nella prima colonna.')

    df_in = df_in.loc[valid_mask].copy().reset_index(drop=True)

    asset_names = df_in.iloc[:, 0].astype(str).str.strip().tolist()
    macro_names = df_in.iloc[:, 1].astype(str).str.strip().tolist()

    # --- Controlli stringenti (nomi e macro) ---
    # Asset class: non vuote, univoche
    if any(a is None or str(a).strip() == "" for a in asset_names):
        raise ValueError('Foglio "Input": sono presenti Asset Class vuote o non valide nella prima colonna.')
    if len(set(asset_names)) != len(asset_names):
        dup = pd.Series(asset_names).value_counts()
        dup = dup[dup > 1].index.tolist()
        raise ValueError('Foglio "Input": nomi Asset Class duplicati: ' + ", ".join([str(d) for d in dup]))

    # Macro-asset class: normalizzazione + validazione
    allowed_macros = {"liquidità": "Liquidità", "liquidita": "Liquidità",
                      "obbligazionario": "Obbligazionario",
                      "azionario": "Azionario",
                      "alternativo": "Alternativo"}
    norm_macros = []
    invalid_macros = []
    for m in macro_names:
        key = str(m).strip().lower()
        if key in allowed_macros:
            norm_macros.append(allowed_macros[key])
        else:
            norm_macros.append(str(m).strip())
            invalid_macros.append(str(m).strip())

    if any(str(m).strip() == "" for m in norm_macros):
        raise ValueError('Foglio "Input": sono presenti Macro-Asset Class vuote nella seconda colonna.')

    if invalid_macros:
        valid_list = ", ".join(sorted(set(allowed_macros.values())))
        bad_list = ", ".join(sorted(set([x for x in invalid_macros if x != ""])))
        raise ValueError(
            'Foglio "Input": Macro-Asset Class non valida/e: ' + bad_list +
            f'. Valori ammessi: {valid_list}.'
        )

    macro_names = norm_macros

    n_assets = len(asset_names)

    exp_ret = pd.to_numeric(df_in.iloc[:, 2], errors="coerce")
    vol = pd.to_numeric(df_in.iloc[:, 3], errors="coerce")

    if exp_ret.isna().any():
        raise ValueError('Rendimenti attesi: presenti valori non numerici o mancanti nella 3ª colonna del foglio "Input".')
    if vol.isna().any():
        raise ValueError('Deviazioni standard: presenti valori non numerici o mancanti nella 4ª colonna del foglio "Input".')

    if (vol <= 0).any() or (~np.isfinite(vol)).any():
        raise ValueError('Deviazioni standard: devono essere valori finiti e strettamente positivi nella 4ª colonna del foglio "Input".')
    if (~np.isfinite(exp_ret)).any():
        raise ValueError('Rendimenti attesi: devono essere valori finiti nella 3ª colonna del foglio "Input".')

    # Matrice correlazioni: da colonna 6 (index 5) per n_assets colonne e n_assets righe
    if df_in.shape[1] < 5 + n_assets:
        raise ValueError(
            f'Nel foglio "Input" non ci sono abbastanza colonne per la matrice delle correlazioni: '
            f'per {n_assets} asset class servono almeno {5 + n_assets} colonne.'
        )

    corr_block = df_in.iloc[:n_assets, 5:5 + n_assets]
    corr = corr_block.apply(pd.to_numeric, errors="coerce")

    if corr.isna().any().any():
        raise ValueError('Matrice correlazioni: presenti valori non numerici o mancanti (dal 6° campo in poi nel foglio "Input").')
    if (corr.values < -1).any() or (corr.values > 1).any():
        raise ValueError('Matrice correlazioni: trovati valori fuori dall’intervallo [-1, 1].')

    corr.index = asset_names
    corr.columns = asset_names

    # Controlli di coerenza minimi
    if not np.allclose(np.diag(corr.values), 1.0, atol=1e-6, rtol=0):
        raise ValueError('Matrice correlazioni: la diagonale deve essere pari a 1 per tutte le asset class.')
    if not np.allclose(corr.values, corr.values.T, atol=1e-6, rtol=0):
        raise ValueError('Matrice correlazioni: la matrice deve essere simmetrica.')

    assets_df = pd.DataFrame(
        {"Asset Class": asset_names, "Macro-Asset Class": macro_names}
    )

    # ---- Foglio Portafogli ----
    df_pf = pd.read_excel(xls, sheet_name="Portafogli")
    if df_pf.shape[1] < 1:
        raise ValueError('Il foglio "Portafogli" è vuoto.')

    # Se la prima colonna NON corrisponde a una asset class, la uso come nome portafoglio (indice)
    first_col = str(df_pf.columns[0]).strip()
    if first_col not in asset_names:
        df_pf = df_pf.set_index(df_pf.columns[0])
    else:
        # Indice numerico di default, ma con etichetta più leggibile
        df_pf.index = [f"Portafoglio {i+1}" for i in range(df_pf.shape[0])]

    # Controllo nomi portafogli (indice)
    # NOTA: df_pf.index è un pandas Index; non usare .replace() (metodo di Series).
    idx = pd.Index(df_pf.index).astype(str).str.strip()

    # Normalizzo valori "vuoti" tipici (NaN/None/stringa vuota)
    idx = pd.Index(["" if str(x).strip().lower() in {"nan", "none", ""} else str(x).strip() for x in idx])

    if (idx == "").any():
        raise ValueError('Nel foglio "Portafogli" sono presenti nomi portafoglio vuoti nella prima colonna.')
    if idx.duplicated().any():
        dups = idx[idx.duplicated()].unique().tolist()
        raise ValueError('Nel foglio "Portafogli" sono presenti nomi portafoglio duplicati: ' + ", ".join(dups))
    df_pf.index = idx

    # Allineo colonne alle asset class e converto a numerico
    missing_cols = [a for a in asset_names if a not in df_pf.columns.astype(str).tolist()]
    extra_cols = [c for c in df_pf.columns.astype(str).tolist() if c not in asset_names]
    if missing_cols:
        raise ValueError(
            'Nel foglio "Portafogli" mancano colonne per alcune Asset Class definite nel foglio "Input": '
            + ", ".join(missing_cols)
        )
    if extra_cols:
        # non blocco: ignoro colonne extra, ma in modo esplicito
        df_pf = df_pf.loc[:, [c for c in df_pf.columns if str(c).strip() in asset_names]]

    df_pf = df_pf.loc[:, asset_names].copy()
    df_pf = df_pf.apply(pd.to_numeric, errors="coerce")
    if df_pf.isna().any().any():
        raise ValueError('Nel foglio "Portafogli" sono presenti celle non numeriche o mancanti.')

    # --- Controlli stringenti sui pesi ---
    if (df_pf < 0).any().any():
        raise ValueError('Nel foglio "Portafogli" sono presenti pesi negativi (non ammessi).')

    # Se i pesi sembrano in percentuale (somma ~ 100), converto in frazione
    WEIGHT_TOL = 0.01   # tolleranza su somma a 1 (±1%)
    PCT_TOL = 1.0       # tolleranza su somma a 100 (±1 punto percentuale)

    row_sums = df_pf.sum(axis=1)

    is_percent = (row_sums.median() > 1.5)
    if is_percent:
        # Validazione: somma pesi ~ 100
        bad = row_sums[(row_sums < 100 - PCT_TOL) | (row_sums > 100 + PCT_TOL)]
        if len(bad) > 0:
            raise ValueError(
                'Nel foglio "Portafogli" alcuni portafogli non sommano a 100% (tolleranza ±1). '
                'Portafogli non validi: ' + ", ".join([str(i) for i in bad.index.tolist()])
            )
        if (df_pf > 100 + PCT_TOL).any().any():
            raise ValueError('Nel foglio "Portafogli" sono presenti pesi > 100% (non ammessi).')
        df_pf = df_pf / 100.0
    else:
        # Validazione: somma pesi ~ 1
        bad = row_sums[(row_sums < 1 - WEIGHT_TOL) | (row_sums > 1 + WEIGHT_TOL)]
        if len(bad) > 0:
            raise ValueError(
                'Nel foglio "Portafogli" alcuni portafogli non sommano a 1 (tolleranza ±1%). '
                'Portafogli non validi: ' + ", ".join([str(i) for i in bad.index.tolist()])
            )
        if (df_pf > 1 + WEIGHT_TOL).any().any():
            raise ValueError('Nel foglio "Portafogli" sono presenti pesi > 1 (non ammessi).')

    row_sums = df_pf.sum(axis=1)
    if (row_sums <= 0).any():
        raise ValueError('Nel foglio "Portafogli" esistono portafogli con somma pesi <= 0.')

    # Normalizzo per eliminare piccoli errori numerici e ottenere somme esattamente a 1
    alloc_df = df_pf.div(row_sums, axis=0)

    exp_ret.index = asset_names
    vol.index = asset_names

    return assets_df, exp_ret, vol, corr, alloc_df

def asset_selection_payload(name: str,
                            assets_df: pd.DataFrame,
                            exp_ret: pd.Series | None,
                            vol: pd.Series | None,
                            corr: pd.DataFrame | None,
                            uploaded_filename: str | None,
                            alloc_df: pd.DataFrame | None = None,
                            alloc_uploaded_filename: str | None = None):
    return {
        "name": name,
        "assets_df": assets_df.copy(),
        "exp_ret": None if exp_ret is None else exp_ret.copy(),
        "vol": None if vol is None else vol.copy(),
        "corr": None if corr is None else corr.copy(),
        "uploaded_filename": uploaded_filename,
        "alloc_df": None if alloc_df is None else alloc_df.copy(),
        "alloc_uploaded_filename": alloc_uploaded_filename,
        "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

def load_asset_selection_to_state(payload: dict):
    assets_df = payload["assets_df"].copy().reset_index(drop=True)
    st.session_state["as_n_assets"] = int(len(assets_df))

    for i in range(len(assets_df)):
        st.session_state[f"as_name_{i}"] = str(assets_df.loc[i, "Asset Class"])
        st.session_state[f"as_macro_{i}"] = str(assets_df.loc[i, "Macro-Asset Class"])

    if payload.get("exp_ret") is not None and payload.get("vol") is not None and payload.get("corr") is not None:
        st.session_state["as_exp_ret"] = payload["exp_ret"].copy()
        st.session_state["as_vol"] = payload["vol"].copy()
        st.session_state["as_corr"] = payload["corr"].copy()

    if payload.get("alloc_df") is not None:
        st.session_state["as_alloc_df"] = payload["alloc_df"].copy()
        st.session_state["as_alloc_filename"] = payload.get("alloc_uploaded_filename", None)

# =======================
# Tools → Database Mercati
# =======================
def ensure_market_database_storage():
    if "market_database" not in st.session_state:
        st.session_state["market_database"] = None  # dict: {"df": DataFrame, "saved_at": str}
    # prova a ripristinare da disco (utile quando la navigazione via link resetta la sessione)
    load_persisted_market_database_into_session()
    load_persisted_product_database_into_session()

def build_market_database_template_excel_bytes() -> bytes:
    """
    Template Excel consigliato per il Database Mercati:
    - Colonna A: Date
    - Riga 1 (da colonna B in poi): Nomi mercati / asset class
    - Valori: rendimenti periodici in forma decimale (0.01 = 1%)
    """
    example = pd.DataFrame(
        {
            "Date": pd.date_range("2020-01-31", periods=6, freq="M"),
            "Azionario Globale": [0.01, -0.02, 0.015, 0.005, -0.01, 0.02],
            "Obbligazionario Globale": [0.002, 0.001, -0.001, 0.0005, 0.0015, -0.0002],
        }
    )
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        example.to_excel(writer, sheet_name="Database", index=False)
    return buffer.getvalue()

def parse_market_database_excel(uploaded_file) -> pd.DataFrame:
    """Legge e valida il file Excel del Database Mercati."""
    try:
        df = pd.read_excel(uploaded_file, sheet_name=0)
    except Exception:
        df = pd.read_excel(uploaded_file, sheet_name="Database")

    if df.shape[1] < 2:
        raise ValueError("Il file deve contenere almeno 2 colonne: Date + almeno 1 mercato.")

    df.columns = [str(c).strip() for c in df.columns]
    date_col = df.columns[0]
    df = df.rename(columns={date_col: "Date"}).copy()

    df["Date"] = pd.to_datetime(df["Date"], errors="coerce")
    if df["Date"].isna().any():
        raise ValueError("Sono presenti date non valide nella prima colonna.")

    df = df.sort_values("Date").drop_duplicates(subset=["Date"]).set_index("Date")

    for c in df.columns:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    if df.isna().any().any():
        raise ValueError("Nel Database Mercati ci sono celle non numeriche o mancanti (NaN).")

    return df

def render_database_mercati():
    """Tools → Database Mercati."""
    ensure_market_database_storage()

    st.markdown(
        '<div class="uw-card"><h2>Database Mercati</h2>'
        "<p>Carichi un file Excel con le serie storiche dei <b>rendimenti</b> delle Asset Class.</p>"
        "<ul>"
        "<li><b>Colonna A</b>: date</li>"
        "<li><b>Riga 1</b>: nomi mercati/asset class</li>"
        "<li>Dalla <b>colonna B</b> in poi: rendimenti (es. 0,01 = 1%)</li>"
        "</ul></div>",
        unsafe_allow_html=True,
    )

    template_bytes = build_market_database_template_excel_bytes()
    st.download_button(
        "Scarica Template Excel (consigliato)",
        data=template_bytes,
        file_name="template_database_mercati.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        use_container_width=True,
        key="dl_template_db_mercati",
    )

    up = st.file_uploader(
        "Upload Database Mercati (Excel)",
        type=["xlsx", "xls"],
        key="upload_db_mercati",
    )

    parsed_df = None
    if up is not None:
        try:
            parsed_df = parse_market_database_excel(up)
            n_assets = int(parsed_df.shape[1])
            last_date = parsed_df.index.max().date()

            st.success("File caricato correttamente.")
            c1, c2 = st.columns(2)
            with c1:
                st.metric("Numero Asset Class presenti", n_assets)
            with c2:
                st.metric("Ultima data disponibile", last_date.strftime("%d/%m/%Y"))

            st.markdown('<div class="uw-card"><h3>Anteprima</h3></div>', unsafe_allow_html=True)
            st.dataframe(parsed_df.tail(12), use_container_width=True)

        except Exception as e:
            st.error(f"Errore nel parsing del file: {e}")

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("Salva", use_container_width=True, key="save_db_mercati"):
        if parsed_df is None:
            st.warning("Caricare prima un file valido.")
        else:
            st.session_state["market_database"] = {
                "df": parsed_df.copy(),
                "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            persist_market_database_from_session()
            st.success("Database Mercati salvato con successo.")

# =======================
# Sezione → Analisi Portafoglio
# =======================

# =======================
# Tools → Database Prodotti (ETF/Fondi)
# =======================
def ensure_product_database_storage():
    if "product_database" not in st.session_state:
        st.session_state["product_database"] = None  # dict: {"df": DataFrame, "saved_at": str, "source_name": str}
    # prova a ripristinare da disco (utile quando la navigazione via link resetta la sessione)
    load_persisted_product_database_into_session()

def load_persisted_product_database_into_session() -> None:
    """Carica il Database Prodotti (Tools → Database Prodotti) da storage per-utente, se mancante in sessione."""
    if st.session_state.get("product_database") is None:
        persisted = _STORAGE.load(_USER_ID, "product_database", None)
        if isinstance(persisted, dict) and isinstance(persisted.get("df"), pd.DataFrame):
            st.session_state["product_database"] = {
                "df": persisted["df"],
                "source_name": persisted.get("source_name", ""),
                "saved_at": persisted.get("saved_at", ""),
            }

def persist_product_database_from_session() -> None:
    db = st.session_state.get("product_database", None)
    if isinstance(db, dict) and isinstance(db.get("df"), pd.DataFrame):
        _STORAGE.save(_USER_ID, "product_database", db)

def parse_product_database_excel(uploaded_file) -> pd.DataFrame:
    """Parsa l'Excel universo prodotti. Accetta colonne extra; valida solo le obbligatorie."""
    try:
        xls = pd.ExcelFile(uploaded_file)
        sheet = "ETF" if "ETF" in xls.sheet_names else xls.sheet_names[0]
        df = pd.read_excel(xls, sheet_name=sheet)
    except Exception:
        df = pd.read_excel(uploaded_file)

    # Normalizza nomi colonne
    df.columns = [str(c).strip() for c in df.columns]

    required = ["isin", "name", "provider", "asset_class", "ter", "aum_eur", "currency", "hedged", "accumulating", "replication", "ucits"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Colonne obbligatorie mancanti: {', '.join(missing)}")

    # Pulizia minima: rimuovi righe senza ISIN o asset_class
    df = df.copy()
    df["isin"] = df["isin"].astype(str).str.strip()
    df["asset_class"] = df["asset_class"].astype(str).str.strip()
    df = df[(df["isin"] != "") & (df["asset_class"] != "")]

    # Standardizza booleani (TRUE/FALSE) se stringhe
    def _to_bool(x):
        if isinstance(x, bool):
            return x
        if pd.isna(x):
            return None
        s = str(x).strip().lower()
        if s in ["true", "t", "1", "yes", "y"]:
            return True
        if s in ["false", "f", "0", "no", "n"]:
            return False
        return None

    for bcol in ["hedged", "accumulating", "ucits"]:
        df[bcol] = df[bcol].apply(_to_bool)

    # Standardizza replication
    df["replication"] = df["replication"].astype(str).str.strip().str.lower()
    df.loc[~df["replication"].isin(["physical", "synthetic"]), "replication"] = df["replication"]

    # Numerici (tolleranti)
    for ncol in ["ter", "aum_eur"]:
        df[ncol] = pd.to_numeric(df[ncol], errors="coerce")

    # Deduplica su ISIN mantenendo la prima occorrenza
    df = df.drop_duplicates(subset=["isin"], keep="first").reset_index(drop=True)

    return df

def render_database_prodotti():
    """Tools → Database Prodotti."""
    ensure_product_database_storage()

    st.markdown(
        '<div class="uw-card"><h2>Database Prodotti</h2>'
        '<p>Carichi un file Excel con l\'universo ETF/fondi e le metriche di valutazione (TER, AUM, rischio, performance, ESG, ecc.). '
        'Il foglio consigliato è <b>ETF</b>; in alternativa verrà letto il primo foglio.</p>'
        '<ul>'
        '<li><b>Colonne obbligatorie</b>: isin, name, provider, asset_class, ter, aum_eur, currency, hedged, accumulating, replication, ucits</li>'
        '<li>Le colonne extra sono ammesse e verranno utilizzate dal motore AI se disponibili.</li>'
        '</ul></div>',
        unsafe_allow_html=True,
    )

    up = st.file_uploader(
        "Upload Database Prodotti (Excel)",
        type=["xlsx", "xls"],
        key="upload_db_prodotti",
    )

    parsed_df = None
    if up is not None:
        try:
            parsed_df = parse_product_database_excel(up)
            st.success(f"File caricato: {up.name} — {len(parsed_df)} strumenti, {parsed_df['asset_class'].nunique()} asset class.")
        except Exception as e:
            st.error(f"Errore nel file: {e}")
            parsed_df = None

    # Mostra DB corrente (da sessione/storage) se presente
    current = st.session_state.get("product_database", None)
    current_meta = current if isinstance(current, dict) else {}
    if parsed_df is None and isinstance(current_meta.get("df"), pd.DataFrame):
        st.info(
            f"Database Prodotti attivo: {current_meta.get('source_name','(file)')} — salvato il {current_meta.get('saved_at','')}"
        )
        parsed_df = current_meta["df"]

    if parsed_df is None:
        st.warning("Nessun Database Prodotti attivo. Carichi un file Excel per poter usare la selezione AI dei prodotti.")
        return

    st.markdown('<div class="uw-card"><h3>Anteprima</h3></div>', unsafe_allow_html=True)
    st.dataframe(parsed_df.head(50), use_container_width=True, height=420)

    col1, col2 = st.columns([1,1])
    with col1:
        if st.button("Salva Database Prodotti", use_container_width=True, key="btn_save_db_prodotti"):
            # current_meta può essere {} al primo salvataggio; evitare .get su None
            st.session_state["product_database"] = {
                "df": parsed_df,
                "source_name": getattr(up, "name", current_meta.get("source_name", ""))
                if up is not None
                else current_meta.get("source_name", ""),
                "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            persist_product_database_from_session()
            st.success("Database Prodotti salvato.")
    with col2:
        if st.button("Rimuovi Database Prodotti", use_container_width=True, key="btn_rm_db_prodotti"):
            st.session_state["product_database"] = None
            _STORAGE.save(_USER_ID, "product_database", None)
            st.success("Database Prodotti rimosso.")


def render_analisi_portafoglio():
    """Analisi grafica e tabellare di un portafoglio appartenente a un Set."""
    ensure_asset_selection_storage()
    ensure_market_database_storage()

    st.markdown(
        '<div class="uw-card"><h2>Analisi Asset Allocation</h2>'
        "<p>Selezioni un <b>Set di Portafogli</b> (Tools → Portafogli in Asset Class), "
        "poi un <b>Portafoglio</b> del Set. L’analisi viene aggiornata automaticamente.</p></div>",
        unsafe_allow_html=True,
    )

    asset_sets = sorted(list(st.session_state.get("asset_selections", {}).keys()))
    if not asset_sets:
        st.warning('Nessun Set disponibile. Crearlo prima in Tools → Portafogli in Asset Class.')
        return

    set_name = st.selectbox("Seleziona Set di Portafogli", asset_sets, key="ap_set_select")
    payload = st.session_state["asset_selections"][set_name]

    assets_df = payload.get("assets_df")
    exp_ret = payload.get("exp_ret")
    vol = payload.get("vol")
    corr = payload.get("corr")
    alloc_df = payload.get("alloc_df")

    if assets_df is None or alloc_df is None or assets_df.empty or alloc_df.empty:
        st.error("Il Set selezionato non contiene input/composizioni validi.")
        return
    if exp_ret is None or vol is None or corr is None:
        st.error("Il Set selezionato non contiene (rendimenti/volatilità/correlazioni).")
        return

    asset_names = [str(a) for a in assets_df["Asset Class"].astype(str).tolist()]
    pf_names = [str(x) for x in alloc_df.index.tolist()]
    # Selezione Portafoglio tramite barra di scorrimento (dal primo all'ultimo)
    if "ap_pf_idx" not in st.session_state:
        st.session_state["ap_pf_idx"] = 1

    # Se cambio Set, riallineo l'indice
    prev_set = st.session_state.get("_ap_prev_set_for_idx")
    if prev_set != set_name:
        st.session_state["ap_pf_idx"] = 1
        st.session_state["_ap_prev_set_for_idx"] = set_name

    pf_idx = st.slider(
        "Seleziona Portafoglio",
        min_value=1,
        max_value=len(pf_names),
        value=int(st.session_state["ap_pf_idx"]),
        step=1,
        key="ap_pf_idx_slider",
    )
    st.session_state["ap_pf_idx"] = int(pf_idx)

    pf_name = pf_names[int(pf_idx) - 1]
    st.caption(f"Portafoglio selezionato: **{pf_name}**")

    st.markdown("<br>", unsafe_allow_html=True)
    if st.session_state.get("market_database") is None:
        st.error("Caricare e salvare prima il Database Mercati (Tools → Database Mercati).")
        return

    db_df = st.session_state["market_database"]["df"].copy()

    # Allineo serie storiche
    missing = [a for a in asset_names if a not in db_df.columns]
    if missing:
        st.error("Nel Database Mercati mancano queste Asset Class (colonne): " + ", ".join(missing))
        return

    returns_ac = db_df.loc[:, asset_names].copy()
    returns_ac = returns_ac.apply(pd.to_numeric, errors="coerce")
    if returns_ac.isna().any().any():
        st.error("Nel Database Mercati ci sono NaN/valori non numerici per le Asset Class del Set.")
        return

    # Pesi (in decimali)
    w = alloc_df.loc[pf_name, asset_names].astype(float).values
    s = float(np.sum(w))
    if s == 0:
        st.error("Pesi nulli.")
        return
    # se somma ~100 interpreto come %
    if abs(s - 100.0) < 1e-6:
        w = w / 100.0
    elif abs(s - 1.0) > 1e-6:
        st.warning("I pesi del portafoglio non sommano a 1 (o 100). Verranno normalizzati.")
        w = w / s

        
    # -----------------------
    # Composizione del portafoglio (grafico a torta) + Tabelle sintetiche (a destra)
    # (stesso stile della torta in "Crea Soluzione di Investimento" → "Azionario + Opportunità consigliato")
    # -----------------------

    # Input: rendimenti annui, sd annue, correlazioni
    mu_ac = exp_ret.reindex(asset_names).astype(float).values
    sd_ac = vol.reindex(asset_names).astype(float).values
    corr_m = corr.reindex(index=asset_names, columns=asset_names).astype(float).values
    cov_ac = np.outer(sd_ac, sd_ac) * corr_m

    # ------------------------------------------------------------------
    # Indicatori sintetici
    # ------------------------------------------------------------------
    def fmt_pct(x: float) -> str:
        return f"{x*100:.1f}%".replace(".", ",")

    port_er = float(np.dot(w, mu_ac))
    port_var = float(w @ cov_ac @ w)
    port_sd = math.sqrt(port_var) if port_var > 0 else 0.0

    macros = assets_df["Macro-Asset Class"].astype(str).tolist()
    peso_liq  = 100.0 * sum(w[i] for i, m in enumerate(macros) if m == "Liquidità")
    peso_bond = 100.0 * sum(w[i] for i, m in enumerate(macros) if m == "Obbligazionario")
    peso_eq   = 100.0 * sum(w[i] for i, m in enumerate(macros) if m == "Azionario")
    peso_alt  = 100.0 * sum(w[i] for i, m in enumerate(macros) if m == "Alternativo")

    # Layout: Torta a sinistra, Tabelle a destra
    c_left, c_right = st.columns([0.50, 0.50], gap="large")

    with c_left:
        try:
            pie_df = pd.DataFrame({
                "Asset Class": asset_names,
                "Peso": w.astype(float),
            })
            pie_df = pie_df[pie_df["Peso"] > 1e-10].copy()

            # robustezza: normalizzo a somma 1
            s_pie = float(pie_df["Peso"].sum())
            if s_pie <= 0:
                raise ValueError("pesi nulli")
            pie_df["Peso"] = pie_df["Peso"] / s_pie

            st.markdown(
                '<div class="uw-card"><h3 class="uw-h3-sm">Composizione del portafoglio selezionato</h3></div>',
                unsafe_allow_html=True
            )

            asset_color_map = _build_asset_color_map(asset_names)
            fig_pie = px.pie(
                pie_df,
                names="Asset Class",
                values="Peso",
                color="Asset Class",
                color_discrete_map=asset_color_map,
            )
            fig_pie.update_traces(
                textposition="inside",
                textinfo="percent+label",
                insidetextorientation="radial",
            )
            fig_pie.update_layout(
                margin=dict(l=10, r=10, t=10, b=10),
                height=300,
                showlegend=False,
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        except Exception as _e_pie:
            st.warning(f"Impossibile creare il grafico a torta della composizione: {_e_pie}")

    with c_right:
        # Box Rendimento / Rischio (grigio)
        st.markdown(
            f"""
            <div style="display:inline-block;border:1px solid #0f172a;font-size:16px;width:100%;">
              <div style="background-color:#f2f2f2;padding:6px 14px;">
                <span>Rendimento Atteso</span>
                <span style="float:right;">{fmt_pct(port_er)}</span>
              </div>
              <div style="background-color:#f2f2f2;padding:6px 14px;">
                <span>Rischio</span>
                <span style="float:right;">{fmt_pct(port_sd)}</span>
              </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Box Macro-composizione (4 righe)
        st.markdown(
            f"""
            <div style="margin-top:10px;display:inline-block;border:1px solid #0f172a;font-size:16px;width:100%;">
              <div style="background-color:#dae8fc;color:#0f172a;padding:6px 14px;">
                <span>Peso Liquidità</span>
                <span style="float:right;">{peso_liq:.0f}%</span>
              </div>
              <div style="background-color:#2d6a4f;color:#ffffff;padding:6px 14px;">
                <span>Peso Obbligazionario</span>
                <span style="float:right;">{peso_bond:.0f}%</span>
              </div>
              <div style="background-color:#b23a48;color:#ffffff;padding:6px 14px;">
                <span>Peso Azionario</span>
                <span style="float:right;">{peso_eq:.0f}%</span>
              </div>
              <div style="background-color:#f6b26b;color:#0f172a;padding:6px 14px;">
                <span>Peso Alternativo</span>
                <span style="float:right;">{peso_alt:.0f}%</span>
              </div>
            </div>
            """,
            unsafe_allow_html=True
        )
# Titolo sezione Orso–Toro
    st.markdown(
        """
        <div style="margin-top:18px;text-align:center;font-weight:bold;
                    border-top:1px solid #0f172a;border-bottom:1px solid #0f172a;
                    padding:4px 0;">
        Comportamento della Asse Allocation nelle fasi Orso-Toro
        </div>
        """,
        unsafe_allow_html=True
    )

    # Serie del portafoglio
    port_daily = (returns_ac * w).sum(axis=1)
    port_cum = (1.0 + port_daily).cumprod()

    # ------------------------------------------------------------------
    # Scenari Orso
    # ------------------------------------------------------------------
    SCENARI_ORSO = [
        ("La crisi russa dell'agosto 1998", "1998-08-19", "1998-09-02"),
        ("L'aumento dei tassi di interesse del '99", "1998-12-30", "1999-12-29"),
        ('La crisi delle ".com"', "2000-03-29", "2003-04-02"),
        ("L'attacco terroristico alle torri gemelle", "2001-09-05", "2001-09-21"),
        ("Il tracollo dell'equity del 2002", "2002-01-02", "2002-12-31"),
        ('La crisi dei "subprime"', "2007-07-24", "2009-03-09"),
        ('Il "Default" di Lehman Brothers', "2008-09-03", "2008-09-17"),
        ("L'Ottobre Nero del 2008", "2008-09-22", "2008-11-06"),
        ('Il picco della crisi del debito € "periferico"', "2011-08-18", "2011-11-10"),
        ("La crisi Covid di inizio 2020", "2020-02-18", "2020-03-23"),
        ("Il rialzo dei tassi del 2022", "2021-12-07", "2022-12-31"),
    ]

    righe_orso = []
    for nome, d_start, d_end in SCENARI_ORSO:
        start = pd.to_datetime(d_start)
        end = pd.to_datetime(d_end)
        mask = (port_daily.index >= start) & (port_daily.index <= end)
        if mask.sum() == 0:
            rend = None
        else:
            rend = (1.0 + port_daily[mask]).prod() - 1.0

        if rend is None:
            rend_str = "n.d."
        elif rend >= 0:
            rend_str = "POSITIVO"
        else:
            rend_str = fmt_pct(rend)
        righe_orso.append((nome, start.strftime("%d/%m/%Y"), end.strftime("%d/%m/%Y"), rend_str))

    rows_html = ""
    for nome, dal, al, rend_str in righe_orso:
        rows_html += f"""
        <tr style="background-color:#fbe7ea;">
          <td style="padding:3px 6px;">{nome}</td>
          <td style="padding:3px 6px;text-align:center;">{dal}</td>
          <td style="padding:3px 6px;text-align:center;">{al}</td>
          <td style="padding:3px 6px;text-align:right;background-color:#f3ead1;font-weight:bold;">
            {rend_str}
          </td>
        </tr>
        """

    st.markdown(
        f"""
        <table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:13px;table-layout:fixed;">
          <colgroup>
            <col style="width:58%;">
            <col style="width:14%;">
            <col style="width:14%;">
            <col style="width:14%;">
          </colgroup>
          <tr style="background-color:#b23a48;color:#ffffff;font-weight:bold;">
            <th style="padding:4px 6px;text-align:left;word-break:break-word;">Peggiori scenari</th>
            <th style="padding:4px 6px;text-align:center;">Dal:</th>
            <th style="padding:4px 6px;text-align:center;">Al:</th>
            <th style="padding:4px 6px;text-align:right;">Rend %</th>
          </tr>
          {rows_html}
        </table>
        """,
        unsafe_allow_html=True
    )
# ------------------------------------------------------------------
    # Scenari Toro
    # ------------------------------------------------------------------
    SCENARI_TORO = [
        ('Il "Boom" delle ".com"', "1998-10-09", "2000-03-29"),
        ("Lo straordinario 1999 dell'Azionario", "1998-12-31", "1999-12-31"),
        ('La ripresa dopo la crisi delle ".com"', "2003-04-01", "2006-01-09"),
        ('Il rimbalzo dopo la crisi dei "subprime"', "2009-03-10", "2010-01-19"),
        ("L'eccellente 2021", "2020-12-31", "2021-12-31"),
        ("L'eccellente 2023", "2022-12-31", "2023-12-29"),
    ]

    righe_toro = []
    for nome, d_start, d_end in SCENARI_TORO:
        start = pd.to_datetime(d_start)
        end = pd.to_datetime(d_end)
        mask = (port_daily.index >= start) & (port_daily.index <= end)
        if mask.sum() == 0:
            rend = None
        else:
            rend = (1.0 + port_daily[mask]).prod() - 1.0

        righe_toro.append((nome, start.strftime("%d/%m/%Y"), end.strftime("%d/%m/%Y"), "n.d." if rend is None else fmt_pct(rend)))

    rows_html_toro = ""
    for nome, dal, al, rend_str in righe_toro:
        rows_html_toro += f"""
        <tr style="background-color:#e9f7ef;">
          <td style="padding:3px 6px;">{nome}</td>
          <td style="padding:3px 6px;text-align:center;">{dal}</td>
          <td style="padding:3px 6px;text-align:center;">{al}</td>
          <td style="padding:3px 6px;text-align:right;background-color:#d6f0e3;font-weight:bold;">
            {rend_str}
          </td>
        </tr>
        """

    st.markdown(
        f"""
        <table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:13px;table-layout:fixed;">
          <colgroup>
            <col style="width:58%;">
            <col style="width:14%;">
            <col style="width:14%;">
            <col style="width:14%;">
          </colgroup>
          <tr style="background-color:#2d6a4f;color:#ffffff;font-weight:bold;">
            <th style="padding:4px 6px;text-align:left;word-break:break-word;">Migliori scenari</th>
            <th style="padding:4px 6px;text-align:center;">Dal:</th>
            <th style="padding:4px 6px;text-align:center;">Al:</th>
            <th style="padding:4px 6px;text-align:right;">Rend %</th>
          </tr>
          {rows_html_toro}
        </table>
        """,
        unsafe_allow_html=True
    )
# ------------------------------------------------------------------
    # Stima parametrica 1 anno
    # ------------------------------------------------------------------
    scen_neg1 = port_er - 1.645 * port_sd
    scen_neg2 = port_er - 2.326 * port_sd
    scen_pos1 = port_er + 1.645 * port_sd
    scen_pos2 = port_er + 2.326 * port_sd

    st.markdown(
        f"""
        <div style="margin-top:14px;">
          <div style="background-color:#b23a48;color:#ffffff;padding:4px 10px;font-size:13px;">
            <span>Cosa potrebbe accadere in 1 anno particolarmente negativo</span>
            <span style="float:right;font-weight:bold;">{fmt_pct(scen_neg1)}</span>
          </div>
          <div style="background-color:#b23a48;color:#ffffff;padding:4px 10px;font-size:13px;margin-top:2px;">
            <span>Cosa potrebbe accadere in 1 anno MOLTO negativo</span>
            <span style="float:right;font-weight:bold;">{fmt_pct(scen_neg2)}</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        f"""
        <div style="margin-top:8px;">
          <div style="background-color:#2d6a4f;color:#ffffff;padding:4px 10px;font-size:13px;">
            <span>Cosa potrebbe accadere in 1 anno particolarmente positivo</span>
            <span style="float:right;font-weight:bold;">{fmt_pct(scen_pos1)}</span>
          </div>
          <div style="background-color:#2d6a4f;color:#ffffff;padding:4px 10px;font-size:13px;margin-top:2px;">
            <span>Cosa potrebbe accadere in 1 anno MOLTO positivo</span>
            <span style="float:right;font-weight:bold;">{fmt_pct(scen_pos2)}</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # ------------------------------------------------------------------
    # Miglior / Peggior mese, trimestre, anno (21,63,262)
    # ------------------------------------------------------------------
    def best_worst_window(serie: pd.Series, window: int):
        if serie.empty or len(serie) < window:
            return None, None, None, None
        r = serie.values.astype(float)
        cum = np.empty(len(r) + 1, dtype=float)
        cum[0] = 1.0
        cum[1:] = np.cumprod(1.0 + r)

        best_ret = -1e9
        worst_ret = 1e9
        best_k = None
        worst_k = None

        for k in range(0, len(r) - window + 1):
            ret = cum[k + window] / cum[k] - 1.0
            if ret > best_ret:
                best_ret = ret
                best_k = k
            if ret < worst_ret:
                worst_ret = ret
                worst_k = k

        if best_k is None or worst_k is None:
            return None, None, None, None

        start_best = serie.index[best_k].date()
        start_worst = serie.index[worst_k].date()
        return start_best, float(best_ret), start_worst, float(worst_ret)

    best_m_d, best_m_r, worst_m_d, worst_m_r = best_worst_window(port_daily, 21)
    best_q_d, best_q_r, worst_q_d, worst_q_r = best_worst_window(port_daily, 63)
    best_y_d, best_y_r, worst_y_d, worst_y_r = best_worst_window(port_daily, 262)

    def box_best(titolo, data, rend):
        if data is None:
            return ""
        return f"""
        <div style="background-color:#2d6a4f;color:#ffffff;padding:6px 10px;
                    margin-top:6px;font-size:13px;border:1px solid #0f172a;">
          <div style="font-weight:bold;text-align:center;">{titolo}</div>
          <div><i>Dal:</i> {data.strftime("%d/%m/%Y")}</div>
          <div style="text-align:right;font-weight:bold;">{fmt_pct(rend)}</div>
        </div>
        """

    def box_worst(titolo, data, rend):
        if data is None:
            return ""
        return f"""
        <div style="background-color:#b23a48;color:#ffffff;padding:6px 10px;
                    margin-top:6px;font-size:13px;border:1px solid #0f172a;">
          <div style="font-weight:bold;text-align:center;">{titolo}</div>
          <div><i>Dal:</i> {data.strftime("%d/%m/%Y")}</div>
          <div style="text-align:right;font-weight:bold;">{fmt_pct(rend)}</div>
        </div>
        """

    blocco_best = (
        box_best("Miglior mese (nella storia):", best_m_d, best_m_r) +
        box_best("Miglior trimestre (nella storia):", best_q_d, best_q_r) +
        box_best("Miglior anno (nella storia):", best_y_d, best_y_r)
    )
    blocco_worst = (
        box_worst("Peggior mese (nella storia):", worst_m_d, worst_m_r) +
        box_worst("Peggior trimestre (nella storia):", worst_q_d, worst_q_r) +
        box_worst("Peggior anno (nella storia):", worst_y_d, worst_y_r)
    )

    st.markdown(
        f"""
        <div style="display:flex;gap:20px;margin-top:16px;">
          <div style="flex:1;">{blocco_best}</div>
          <div style="flex:1;">{blocco_worst}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # ------------------------------------------------------------------
    # Periodo custom + andamento storico
    # ------------------------------------------------------------------
    st.markdown(
        """
        <div style="margin-top:16px;background-color:#1f3a5f;color:#ffffff;
                    padding:4px 8px;font-size:13px;font-weight:bold;">
            Fissa tu il periodo da analizzare (dal 16 marzo 1998 in poi):
        </div>
        """,
        unsafe_allow_html=True
    )

    min_date = port_daily.index.min().date()
    max_date = port_daily.index.max().date()
    c1, c2 = st.columns(2)
    with c1:
        data_inizio = st.date_input("Dal (aaaa/mm/gg):", value=min_date, min_value=min_date, max_value=max_date, key="ap_dal")
    with c2:
        data_fine = st.date_input("Al (aaaa/mm/gg):", value=max_date, min_value=min_date, max_value=max_date, key="ap_al")

    risultato_custom = ""
    if data_inizio <= data_fine:
        mask = (port_daily.index >= pd.to_datetime(data_inizio)) & (port_daily.index <= pd.to_datetime(data_fine))
        if mask.sum() > 0:
            rend_pers = (1.0 + port_daily[mask]).prod() - 1.0
            risultato_custom = fmt_pct(rend_pers)

    if risultato_custom:
        st.markdown(
            f"""
            <div style="background-color:#0f172a;color:#ffffff;
                        padding:4px 8px;font-size:13px;">
                <span><i>Giorni lavorativi</i></span>
                <span style="float:right;background-color:#d6f0e3;color:#0f172a;
                             padding:2px 6px;font-weight:bold;">
                    {risultato_custom}
                </span>
                <br>
                <span>Dal: {data_inizio.strftime("%d/%m/%Y")} &nbsp;&nbsp;
                      Al: {data_fine.strftime("%d/%m/%Y")}</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    if data_inizio <= data_fine:
        mask = (port_cum.index >= pd.to_datetime(data_inizio)) & (port_cum.index <= pd.to_datetime(data_fine))
        serie_plot = port_cum[mask]
    else:
        serie_plot = port_cum

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("#### Andamento storico del portafoglio", unsafe_allow_html=True)

    if not serie_plot.empty:
                # --- Grafico interattivo (Plotly) con Drawdown + bande di stress + annotazioni ---
        serie_plot_norm = serie_plot / serie_plot.iloc[0] * 100.0

        # Drawdown (%) rispetto al massimo precedente
        running_max = serie_plot_norm.cummax()
        drawdown_pct = (serie_plot_norm / running_max - 1.0) * 100.0

        y_min = float(serie_plot_norm.min())
        y_max = float(serie_plot_norm.max())
        y_lower = y_min * 0.98
        y_upper = y_max * 1.02

        from plotly.subplots import make_subplots

        fig = make_subplots(
            rows=2, cols=1, shared_xaxes=True,
            vertical_spacing=0.12,
            row_heights=[0.70, 0.30]
        )

        # Linea montante (base 100)
        fig.add_trace(
            go.Scatter(
                x=serie_plot_norm.index,
                y=serie_plot_norm.values,
                mode="lines",
                line=dict(width=2.5),
                name="Portafoglio (base 100)",
                hovertemplate="Data: %{x|%d/%m/%Y}<br>Montante: %{y:.1f}<extra></extra>",
            ),
            row=1, col=1
        )

        # Area drawdown
        fig.add_trace(
            go.Scatter(
                x=drawdown_pct.index,
                y=drawdown_pct.values,
                mode="lines",
                fill="tozeroy",
                line=dict(width=1.5),
                name="Drawdown (%)",
                hovertemplate="Data: %{x|%d/%m/%Y}<br>Drawdown: %{y:.2f}%<extra></extra>",
            ),
            row=2, col=1
        )

        # Bande di stress (mostrate solo se la finestra è presente nei dati)
        stress_periods = [
            ("2008-09-15", "2009-06-30", "Crisi finanziaria"),
            ("2020-02-20", "2020-04-30", "Covid"),
            ("2022-01-01", "2022-10-31", "Shock tassi / inflazione"),
        ]
        x_min = pd.to_datetime(serie_plot_norm.index.min())
        x_max = pd.to_datetime(serie_plot_norm.index.max())

        for s, e, label in stress_periods:
            s_dt = pd.to_datetime(s)
            e_dt = pd.to_datetime(e)
            if e_dt < x_min or s_dt > x_max:
                continue
            s_dt = max(s_dt, x_min)
            e_dt = min(e_dt, x_max)
            fig.add_vrect(
                x0=s_dt, x1=e_dt,
                fillcolor="rgba(200,200,200,0.18)",
                line_width=0,
                annotation_text=label,
                annotation_position="top left"
            )

        # Annotazioni (massimo, minimo, ultimo)
        idx_max = serie_plot_norm.idxmax()
        idx_min = serie_plot_norm.idxmin()
        idx_last = serie_plot_norm.index[-1]

        fig.add_annotation(
            x=idx_max, y=float(serie_plot_norm.loc[idx_max]),
            text=f"Massimo: {float(serie_plot_norm.loc[idx_max]):.1f}",
            showarrow=True, arrowhead=2, xanchor="left",
            row=1, col=1
        )
        fig.add_annotation(
            x=idx_min, y=float(serie_plot_norm.loc[idx_min]),
            text=f"Minimo: {float(serie_plot_norm.loc[idx_min]):.1f}",
            showarrow=True, arrowhead=2, xanchor="left",
            row=1, col=1
        )
        fig.add_annotation(
            x=idx_last, y=float(serie_plot_norm.loc[idx_last]),
            text=f"Ultimo: {float(serie_plot_norm.loc[idx_last]):.1f}",
            showarrow=True, arrowhead=2, xanchor="right",
            row=1, col=1
        )

        # Evidenzio anche il massimo drawdown
        idx_mdd = drawdown_pct.idxmin()
        fig.add_annotation(
            x=idx_mdd, y=float(drawdown_pct.loc[idx_mdd]),
            text=f"Max DD: {float(drawdown_pct.loc[idx_mdd]):.2f}%",
            showarrow=True, arrowhead=2, xanchor="left",
            row=2, col=1
        )

        fig.update_yaxes(title_text="Valore (base 100)", range=[y_lower, y_upper], row=1, col=1)
        fig.update_yaxes(title_text="Drawdown (%)", row=2, col=1, zeroline=True)

        fig.update_layout(
            height=560,
            margin=dict(l=20, r=20, t=20, b=10),
            hovermode="x unified",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
        )

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.write("Nessun dato disponibile per il periodo selezionato.")

    # ==========================================================
    # Analisi di una specifica Asset Class (opzionale)
    # ==========================================================
    st.markdown("<br>", unsafe_allow_html=True)

    ac_choice = st.radio(
        "Vuole effettuare l’analisi di una specifica Asset Class?",
        ["No", "Sì"],
        horizontal=True,
        key="ap_ac_analysis_toggle",
    )

    if ac_choice == "Sì":
        st.markdown(
            '<div class="uw-card"><h3 class="uw-h3-sm">Analisi di una Asset Class</h3>'
            '<p>Selezioni una Asset Class tra quelle presenti nel portafoglio. '
            'L’analisi sottostante replica (con colori differenti) la stessa struttura dell’analisi di portafoglio.</p></div>',
            unsafe_allow_html=True,
        )

        ac_sel = st.selectbox(
            "Seleziona Asset Class",
            asset_names,
            key="ap_ac_select",
        )

        # Pesi (100% sulla Asset Class selezionata)
        w_ac = pd.Series({ac_sel: 1.0})

        # -----------------------
        # Composizione (torta)
        # -----------------------
        cL, cR = st.columns([0.55, 0.45], gap="large")

        with cL:
            try:
                pie_df_ac = pd.DataFrame({"Asset Class": [ac_sel], "Peso": [1.0]})
                asset_color_map = _build_asset_color_map(asset_names)
                fig_pie_ac = px.pie(
                    pie_df_ac,
                    names="Asset Class",
                    values="Peso",
                    color="Asset Class",
                    color_discrete_map=asset_color_map,
                )
                fig_pie_ac.update_traces(
                    textposition="inside",
                    textinfo="percent+label",
                    insidetextorientation="radial",
                )
                fig_pie_ac.update_layout(
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=280,
                    showlegend=False,
                )
                st.plotly_chart(fig_pie_ac, use_container_width=True)
            except Exception as _e_pie_ac:
                st.warning(f"Impossibile creare il grafico a torta della composizione (Asset Class): {_e_pie_ac}")

        # -----------------------
        # Rendimento atteso / rischio (box)
        # -----------------------
        with cR:
            try:
                mu_ac_map = exp_ret.reindex(asset_names).astype(float)
                sd_ac_map = vol.reindex(asset_names).astype(float)

                mu_i = float(mu_ac_map.loc[ac_sel])
                sd_i = float(sd_ac_map.loc[ac_sel])

                st.markdown(
                    f"""
                    <div style="display:inline-block;border:1px solid #0f172a;font-size:16px;width:100%;">
                      <div style="background-color:#eef2ff;padding:6px 14px;">
                        <span>Rendimento Atteso</span>
                        <span style="float:right;"><b>{mu_i:.2%}</b></span>
                      </div>
                      <div style="background-color:#e0e7ff;padding:6px 14px;">
                        <span>Rischio (Volatilità)</span>
                        <span style="float:right;"><b>{sd_i:.2%}</b></span>
                      </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            except Exception as _e_mu_sig_ac:
                st.warning(f"Impossibile calcolare rendimento/volatilità della Asset Class: {_e_mu_sig_ac}")

        # ----------------------------------------------------------
        # Comportamento Orso–Toro (stessa logica, su singola Asset Class)
        # ----------------------------------------------------------
        st.markdown(
            """
            <div style="margin-top:18px;text-align:center;font-weight:bold;
                        border-top:1px solid #0f172a;border-bottom:1px solid #0f172a;
                        padding:4px 0;">
            Comportamento della Asse Allocation nelle fasi Orso-Toro
            </div>
            """,
            unsafe_allow_html=True
        )

        try:
            asset_daily = returns_ac[ac_sel].astype(float)
            asset_cum = (1.0 + asset_daily).cumprod()

            def _scenario_stats(series_cum: pd.Series, start_s: str, end_s: str):
                s = series_cum.loc[start_s:end_s].copy()
                if s.empty:
                    return None
                base = float(s.iloc[0])
                rel = s / base
                dd = rel / rel.cummax() - 1.0
                return {
                    "Start": pd.to_datetime(start_s).date(),
                    "End": pd.to_datetime(end_s).date(),
                    "Rendimento cumulato": float(rel.iloc[-1] - 1.0),
                    "Max Drawdown": float(dd.min()),
                }

            rows_orso = []
            if "SCENARI_ORSO" in locals():
                for name, d0, d1 in SCENARI_ORSO:
                    out = _scenario_stats(asset_cum, d0, d1)
                    if out is not None:
                        out["Scenario (Orso)"] = name
                        rows_orso.append(out)

            rows_toro = []
            if "SCENARI_TORO" in locals():
                for name, d0, d1 in SCENARI_TORO:
                    out = _scenario_stats(asset_cum, d0, d1)
                    if out is not None:
                        out["Scenario (Toro)"] = name
                        rows_toro.append(out)

            cc1, cc2 = st.columns(2, gap="large")
            with cc1:
                if rows_orso:
                    df_orso = pd.DataFrame(rows_orso)[["Scenario (Orso)", "Start", "End", "Rendimento cumulato", "Max Drawdown"]]
                    df_orso["Rendimento cumulato"] = df_orso["Rendimento cumulato"].map(lambda x: f"{x:.1%}")
                    df_orso["Max Drawdown"] = df_orso["Max Drawdown"].map(lambda x: f"{x:.1%}")
                    st.markdown("<b>Scenari Orso</b>", unsafe_allow_html=True)
                    st.dataframe(df_orso, use_container_width=True, hide_index=True)
                else:
                    st.info("Nessuno scenario Orso disponibile nel periodo coperto dai dati.")

            with cc2:
                if rows_toro:
                    df_toro = pd.DataFrame(rows_toro)[["Scenario (Toro)", "Start", "End", "Rendimento cumulato", "Max Drawdown"]]
                    df_toro["Rendimento cumulato"] = df_toro["Rendimento cumulato"].map(lambda x: f"{x:.1%}")
                    df_toro["Max Drawdown"] = df_toro["Max Drawdown"].map(lambda x: f"{x:.1%}")
                    st.markdown("<b>Scenari Toro</b>", unsafe_allow_html=True)
                    st.dataframe(df_toro, use_container_width=True, hide_index=True)
                else:
                    st.info("Nessuno scenario Toro disponibile nel periodo coperto dai dati.")

        except Exception as _e_scen_ac:
            st.warning(f"Impossibile calcolare gli scenari Orso–Toro per la Asset Class: {_e_scen_ac}")

        # ----------------------------------------------------------
        # Andamento storico (stesso grafico a linea + drawdown, colori diversi)
        # ----------------------------------------------------------
        st.markdown(
            '<div class="uw-card"><h3 class="uw-h3-sm">Andamento storico della Asset Class</h3></div>',
            unsafe_allow_html=True
        )

        try:
            r_full = returns_ac[ac_sel].astype(float).dropna()

            # ---------------------------------------------
            # Selettore intervallo date (solo Asset Class)
            #   - due date_input separati (evita che la modifica di una data influenzi anche l'altra)
            #   - box nero + rendimento cumulato nel periodo selezionato (stile Analisi Portafoglio)
            # ---------------------------------------------
            if len(r_full) >= 2:
                _min_d = r_full.index.min().date()
                _max_d = r_full.index.max().date()

                st.markdown(
                    '''
                    <div style="margin-top:16px;background-color:#000000;color:#ffffff;
                                padding:6px 10px;font-size:13px;font-weight:bold;border-radius:8px;">
                        Intervallo di analisi (Asset Class)
                    </div>
                    ''',
                    unsafe_allow_html=True
                )

                c1, c2 = st.columns(2, gap="large")

                key_dal = f"ap_ac_dal_{ac_sel}"
                key_al = f"ap_ac_al_{ac_sel}"

                # inizializzo valori una sola volta (per evitare reset indesiderati)
                if key_dal not in st.session_state:
                    st.session_state[key_dal] = _min_d
                if key_al not in st.session_state:
                    st.session_state[key_al] = _max_d

                with c1:
                    _d0 = st.date_input(
                        "Dal (aaaa/mm/gg):",
                        value=st.session_state[key_dal],
                        min_value=_min_d,
                        max_value=_max_d,
                        key=key_dal,
                    )
                with c2:
                    _d1 = st.date_input(
                        "Al (aaaa/mm/gg):",
                        value=st.session_state[key_al],
                        min_value=_min_d,
                        max_value=_max_d,
                        key=key_al,
                    )

                # correzione soft: se l'utente imposta un intervallo non valido, allineo la data finale
                if _d0 > _d1:
                    _d1 = _d0
                    st.session_state[key_al] = _d1

                _t0 = pd.Timestamp(_d0)
                _t1 = pd.Timestamp(_d1) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
                r = r_full.loc[(r_full.index >= _t0) & (r_full.index <= _t1)]

                # rendimento cumulato nel periodo selezionato
                rend_cum_txt = ""
                try:
                    if len(r) >= 1:
                        rend_cum = float((1.0 + r).prod() - 1.0)
                        rend_cum_txt = f"{rend_cum:.1%}"
                except Exception:
                    rend_cum_txt = ""

                if rend_cum_txt:
                    st.markdown(
                        f'''
                        <div style="background-color:#000000;color:#ffffff;
                                    padding:6px 10px;font-size:13px;border-radius:8px;margin-top:8px;">
                            Rendimento cumulato nel periodo selezionato: <b>{rend_cum_txt}</b>
                        </div>
                        ''',
                        unsafe_allow_html=True
                    )
            else:
                r = r_full

            if len(r) >= 2:
                v = (1.0 + r).cumprod() * 100.0
                dd = v / v.cummax() - 1.0

                y_lower = float(min(v.min(), 98))
                y_upper = float(max(v.max(), 102))

                fig_ac = make_subplots(
                    rows=2, cols=1,
                    shared_xaxes=True,
                    vertical_spacing=0.08,
                    row_heights=[0.72, 0.28],
                )

                fig_ac.add_trace(
                    go.Scatter(
                        x=v.index,
                        y=v.values,
                        mode="lines",
                        name="Montante (base 100)",
                        line=dict(width=3, color="#4f46e5"),
                        hovertemplate="%{x|%d/%m/%Y}<br>Montante: %{y:.1f}<extra></extra>",
                    ),
                    row=1, col=1,
                )

                fig_ac.add_trace(
                    go.Scatter(
                        x=dd.index,
                        y=(dd.values * 100.0),
                        mode="lines",
                        name="Drawdown (%)",
                        line=dict(width=2, color="#a855f7"),
                        fill="tozeroy",
                        hovertemplate="%{x|%d/%m/%Y}<br>Drawdown: %{y:.2f}%<extra></extra>",
                    ),
                    row=2, col=1,
                )

                idx_last = v.index[-1]
                fig_ac.add_annotation(
                    x=idx_last, y=float(v.loc[idx_last]),
                    text=f"Ultimo: {float(v.loc[idx_last]):.1f}",
                    showarrow=True, arrowhead=2, xanchor="right",
                    row=1, col=1
                )

                idx_mdd = dd.idxmin()
                fig_ac.add_annotation(
                    x=idx_mdd, y=float(dd.loc[idx_mdd] * 100.0),
                    text=f"Max DD: {float(dd.loc[idx_mdd] * 100.0):.2f}%",
                    showarrow=True, arrowhead=2, xanchor="left",
                    row=2, col=1
                )

                fig_ac.update_yaxes(title_text="Valore (base 100)", range=[y_lower, y_upper], row=1, col=1)
                fig_ac.update_yaxes(title_text="Drawdown (%)", row=2, col=1, zeroline=True)

                fig_ac.update_layout(
                    height=560,
                    margin=dict(l=20, r=20, t=20, b=10),
                    hovermode="x unified",
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
                )

                st.plotly_chart(fig_ac, use_container_width=True)
            else:
                st.info("Dati insufficienti per costruire l’andamento storico della Asset Class.")
        except Exception as _e_hist_ac:
            st.warning(f"Impossibile creare il grafico storico della Asset Class: {_e_hist_ac}")


def render_selezione_asset_class():
    """Tools → Portafogli in Asset Class (ex: Selezione Asset Class)."""
    ensure_asset_selection_storage()

    st.markdown(
        '<div class="uw-card"><h2>Portafogli in Asset Class</h2>'
        '<p>Crea, modifica o cancella un <b>Set di Asset Allocation</b>. '
        'Il set include: mercati (asset class e macro-asset class), input di mercato (rendimenti attesi, volatilità, correlazioni) '
        'e composizioni dei portafogli (pesi per asset class).</p></div>',
        unsafe_allow_html=True
    )

    mode_as = st.radio(
        "Operazione",
        ["Crea un nuovo set di Asset Allocation", "Modifica/Cancella un Set preesistente"],
        horizontal=True,
        key="as_mode"
    )

    set_name = ""
    selected_existing = None
    loaded_payload = None

    if mode_as == "Crea un nuovo set di Asset Allocation":
        set_name = st.text_input("Nome del nuovo Set di Asset Allocation", value="", key="as_new_name").strip()
    else:
        existing = sorted(list(st.session_state["asset_selections"].keys()))
        if len(existing) == 0:
            st.info("Non esistono ancora Set salvati. Crei un nuovo Set per iniziare.")
            set_name = st.text_input("Nome del nuovo Set di Asset Allocation", value="", key="as_new_name_fallback").strip()
            mode_as = "Crea un nuovo set di Asset Allocation"
        else:
            selected_existing = st.selectbox("Set da modificare", existing, key="as_existing_select")
            set_name = selected_existing

            c_load, c_del = st.columns([0.20, 0.20], gap="small")
            with c_load:
                if st.button("Carica", key="as_load_btn"):
                    loaded_payload = st.session_state["asset_selections"][selected_existing]
                    st.session_state["as_current_payload"] = loaded_payload
                    st.success("Set caricato. Può sostituire il file Excel e poi salvare.")
            with c_del:
                if st.button("Cancella", key="as_delete_btn"):
                    st.session_state["asset_selections"].pop(selected_existing, None)
                    st.session_state.pop("as_current_payload", None)
                    st.success(f'Set "{selected_existing}" eliminato correttamente.')
                    persist_asset_selections_from_session()
                    st.rerun()

    # Recupero payload caricato (se presente)
    if loaded_payload is None and "as_current_payload" in st.session_state:
        loaded_payload = st.session_state["as_current_payload"]

    # =======================
    # 1) Carica Input (Mercati, Input, Composizioni)
    # =======================
    st.markdown(
        '<div class="uw-card"><h2>1) Carica Input (Mercati, Input, Composizioni)</h2>'
        '<p>Carichi <b>un unico file Excel</b> con due fogli: <b>Input</b> e <b>Portafogli</b>.</p>'
        '<p><b>Foglio “Input”</b>: colonna 1 = Asset Class; colonna 2 = Macro-Asset Class (Liquidità, Obbligazionario, Azionario, Alternativo); '
        'colonna 3 = rendimento atteso annuo; colonna 4 = deviazione standard annua; dalla <b>6ª colonna</b> in poi = matrice correlazioni.</p>'
        '<p><b>Foglio “Portafogli”</b>: righe = portafogli; colonne = pesi per asset class (header = nomi asset class coerenti con foglio Input). '
        'La prima colonna può contenere il nome del portafoglio.</p></div>',
        unsafe_allow_html=True
    )

    # Template Excel scaricabile (per ridurre errori di formato)
    with st.expander("Template Excel (consigliato)", expanded=False):
        st.write("Scarichi il template, lo compili e poi lo ricarichi qui sotto. Il file include i fogli: **Input**, **Portafogli** e **Istruzioni**.")
        tpl_bytes = build_asset_set_template_excel_bytes()
        st.download_button(
            label="Scarica template Excel",
            data=tpl_bytes,
            file_name="Template_Input_Portafogli.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            key="as_template_download"
        )

    up = st.file_uploader("Carica file Excel (Input + Portafogli)", type=["xlsx", "xls"], key="as_excel_uploader")

    assets_df = None
    exp_ret = None
    vol = None
    corr = None
    alloc_df = None
    uploaded_filename = None

    if up is not None:
        uploaded_filename = up.name
        try:
            assets_df, exp_ret, vol, corr, alloc_df = parse_excel_asset_set(up)
            st.success("File Excel acquisito correttamente.")
            # Salvo in session_state come bozza (per non perdere su rerun)
            st.session_state["as_assets_df"] = assets_df.copy()
            st.session_state["as_exp_ret"] = exp_ret.copy()
            st.session_state["as_vol"] = vol.copy()
            st.session_state["as_corr"] = corr.copy()
            st.session_state["as_alloc_df"] = alloc_df.copy()
            st.session_state["as_alloc_filename"] = up.name
        except Exception as e:
            st.error(f"Errore nel parsing del file: {e}")
    else:
        # Se non c'è upload, provo a recuperare da session_state (es. dopo Carica set o rerun)
        if loaded_payload is not None:
            assets_df = loaded_payload.get("assets_df", None)
            exp_ret = loaded_payload.get("exp_ret", None)
            vol = loaded_payload.get("vol", None)
            corr = loaded_payload.get("corr", None)
            alloc_df = loaded_payload.get("alloc_df", None)
            uploaded_filename = loaded_payload.get("uploaded_filename", None)
            if alloc_df is not None:
                st.session_state["as_alloc_df"] = alloc_df.copy()
                st.session_state["as_alloc_filename"] = loaded_payload.get("alloc_uploaded_filename", None)
        else:
            if "as_assets_df" in st.session_state:
                assets_df = st.session_state.get("as_assets_df", None)
            exp_ret = st.session_state.get("as_exp_ret", None)
            vol = st.session_state.get("as_vol", None)
            corr = st.session_state.get("as_corr", None)
            alloc_df = st.session_state.get("as_alloc_df", None)
            uploaded_filename = st.session_state.get("as_uploaded_filename", None)

    # =======================
    # 3) Input e Composizione (ex: 3) Risultati + 5) Composizioni
    # =======================
    st.markdown(
        '<div class="uw-card"><h2>3) Input e Composizione</h2>'
        '<p>Rendimenti attesi, volatilità, matrice delle correlazioni (colorata), composizioni dei portafogli e frontiera rischio-rendimento atteso.</p></div>',
        unsafe_allow_html=True
    )

    if assets_df is None or exp_ret is None or vol is None or corr is None:
        st.warning("Per visualizzare Input e Composizione, caricare il file Excel con i fogli “Input” e “Portafogli”.")
    else:
        asset_names = assets_df["Asset Class"].astype(str).tolist()

        # --- Output numerico (per grafici) ---
        out_num = pd.DataFrame({
            "Rendimento atteso annuo": exp_ret.values.astype(float),
            "Deviazione standard annua": vol.values.astype(float),
            "Macro-Asset Class": assets_df["Macro-Asset Class"].astype(str).values,
        }, index=asset_names)

        # --- Output formattato (per tabella) ---
        out_disp = out_num.copy()
        out_disp["Rendimento atteso annuo"] = out_disp["Rendimento atteso annuo"].map(lambda x: f"{x:.2%}")
        out_disp["Deviazione standard annua"] = out_disp["Deviazione standard annua"].map(lambda x: f"{x:.2%}")

        st.subheader("Rendimenti attesi e volatilità")
        st.dataframe(out_disp, use_container_width=True)

        # --- Barre orizzontali affiancate ---
        st.subheader("Rendimenti attesi e rischi (barre orizzontali)")
        bar_df = out_num.reset_index().rename(columns={"index": "Asset Class"})
        c_ret, c_vol = st.columns(2, gap="large")

        with c_ret:
            fig_ret = px.bar(
                bar_df.sort_values("Rendimento atteso annuo"),
                x="Rendimento atteso annuo",
                y="Asset Class",
                orientation="h",
                title="Rendimenti attesi (annui)",
            )
            fig_ret.update_layout(margin=dict(l=10, r=10, t=40, b=10), showlegend=False)
            fig_ret.update_xaxes(tickformat=".0%")
            st.plotly_chart(fig_ret, use_container_width=True)

        with c_vol:
            fig_vol = px.bar(
                bar_df.sort_values("Deviazione standard annua"),
                x="Deviazione standard annua",
                y="Asset Class",
                orientation="h",
                title="Deviazioni standard (annue)",
            )
            fig_vol.update_layout(margin=dict(l=10, r=10, t=40, b=10), showlegend=False)
            fig_vol.update_xaxes(tickformat=".0%")
            st.plotly_chart(fig_vol, use_container_width=True)

        # --- Matrice correlazioni ---
        st.subheader("Matrice delle correlazioni")
        corr_styler = (
            corr.style
            .background_gradient(axis=None, cmap="Blues", vmin=-1, vmax=1)
            .format("{:.2f}")
        )
        st.dataframe(corr_styler, use_container_width=True)

        # --- Scatter rischio/rendimento (Asset Class in legenda) ---
        st.subheader("Scatter: Rischio vs Rendimento atteso")
        plot_df = pd.DataFrame({
            "Asset Class": asset_names,
            "Rischio (σ annua)": out_num["Deviazione standard annua"].astype(float),
            "Rendimento atteso annuo": out_num["Rendimento atteso annuo"].astype(float),
            "Macro-Asset Class": out_num["Macro-Asset Class"].astype(str),
        })

        fig = px.scatter(
            plot_df,
            x="Rischio (σ annua)",
            y="Rendimento atteso annuo",
            hover_name="Asset Class",
            color="Asset Class",
        )
        # Pallini leggermente più piccoli e senza mostrare informazioni di "size" nel tooltip
        fig.update_traces(
            marker=dict(size=15),
            hovertemplate=(
                "<b>%{hovertext}</b><br>"
                "Rischio: %{x:.2%}<br>"
                "Rendimento atteso: %{y:.2%}"
                "<extra></extra>"
            ),
        )
        fig.update_layout(
            title="Rischio vs Rendimento atteso",
            xaxis_tickformat=".0%",
            yaxis_tickformat=".0%",
            margin=dict(l=10, r=10, t=40, b=10),
        )
        st.plotly_chart(fig, use_container_width=True)

        # --- Composizioni ---
        if alloc_df is None:
            st.info("Nel file Excel non risultano composizioni portafogli (foglio “Portafogli”).")
        else:
            st.subheader("Composizioni dei portafogli (area chart)")
            long_alloc = alloc_df.reset_index().melt(id_vars=alloc_df.index.name or "index", var_name="Asset Class", value_name="Peso")
            # robusto: se indice non ha nome
            if "index" not in long_alloc.columns:
                long_alloc.rename(columns={alloc_df.index.name: "index"}, inplace=True)
            long_alloc.rename(columns={"index": "Portafoglio"}, inplace=True)

            area_fig = px.area(
                long_alloc,
                x="Portafoglio",
                y="Peso",
                color="Asset Class",
            )
            area_fig.update_layout(
                margin=dict(l=10, r=10, t=20, b=10),
                xaxis_title="Portafogli",
                yaxis_title="Peso",
                yaxis_tickformat=".0%",
            )
            st.plotly_chart(area_fig, use_container_width=True)

            # Frontiera rischio-rendimento (portafogli caricati)
            st.subheader("Frontiera rischio-rendimento atteso (portafogli caricati)")
            mu = np.asarray(exp_ret.astype(float).values)
            sig = np.asarray(vol.astype(float).values)
            rho = np.asarray(corr.astype(float).values)
            cov = np.outer(sig, sig) * rho

            W = alloc_df.loc[:, asset_names].values.astype(float)
            port_ret = W @ mu
            port_var = np.einsum("ij,jk,ik->i", W, cov, W)
            port_risk = np.sqrt(np.maximum(port_var, 0.0))

            # Matrice var-cov e correlazioni tra portafogli selezionati
            cov_pf = (W @ cov) @ W.T
            sig_pf = np.sqrt(np.maximum(np.diag(cov_pf), 0.0))
            denom = np.outer(sig_pf, sig_pf)
            with np.errstate(divide="ignore", invalid="ignore"):
                corr_pf = np.where(denom > 0, cov_pf / denom, 0.0)
            np.fill_diagonal(corr_pf, 1.0)

            # Salvo in sessione: servirà per la generazione scenari Monte Carlo nella sezione dinamica
            st.session_state["gbi_dyn_port_names"] = list(alloc_df.index.astype(str))
            st.session_state["gbi_dyn_port_mu"] = port_ret.astype(float)
            st.session_state["gbi_dyn_port_sigma"] = port_risk.astype(float)
            st.session_state["gbi_dyn_port_corr"] = corr_pf.astype(float)
            pf_df = pd.DataFrame({
                "Portafoglio": alloc_df.index.astype(str),
                "Rischio (σ annuo)": port_risk,
                "Rendimento atteso annuo": port_ret,
            })

            scat = px.scatter(
                pf_df,
                x="Rischio (σ annuo)",
                y="Rendimento atteso annuo",
                hover_name="Portafoglio",
            )
            scat.update_layout(
                margin=dict(l=10, r=10, t=20, b=10),
                xaxis_tickformat=".0%",
                yaxis_tickformat=".0%",
            )
            scat.update_traces(marker=dict(size=18))
            st.plotly_chart(scat, use_container_width=True)

    # =======================
    # Salva
    # =======================
    st.markdown(
        '<div class="uw-card"><h2>Salva</h2>'
        '<p>Salva il Set di Asset Allocation (mercati, input e composizioni) con il Nome specificato.</p></div>',
        unsafe_allow_html=True
    )

    if st.button("Salva", type="primary", key="as_save_btn"):
        if set_name.strip() == "":
            st.error("Inserire un Nome per il Set prima di salvare.")
        elif assets_df is None or exp_ret is None or vol is None or corr is None:
            st.error("Caricare prima il file Excel con i fogli “Input” e “Portafogli”.")
        else:
            payload = asset_selection_payload(
                name=set_name.strip(),
                assets_df=assets_df,
                exp_ret=exp_ret,
                vol=vol,
                corr=corr,
                uploaded_filename=uploaded_filename,
                alloc_df=alloc_df,
                alloc_uploaded_filename=st.session_state.get("as_alloc_filename", None),
            )
            st.session_state["asset_selections"][set_name.strip()] = payload
            st.session_state["as_current_payload"] = payload
            st.success(f'Set "{set_name.strip()}" salvato correttamente.')
            persist_asset_selections_from_session()

# =======================
# Render header
# =======================

# =======================
# Clienti/Investitori – Anagrafica
# =======================

# =======================
# Clienti/Investitori – Anagrafica
# =======================



# =======================
# Sezione → Selezione Prodotti
# =======================

# =======================
# Selezione Prodotti → AI Selection helpers
# =======================
def _minmax_norm(s: pd.Series, higher_is_better: bool = True) -> pd.Series:
    s2 = pd.to_numeric(s, errors="coerce")
    lo = s2.min(skipna=True)
    hi = s2.max(skipna=True)
    if pd.isna(lo) or pd.isna(hi) or hi == lo:
        out = pd.Series([0.5] * len(s2), index=s2.index)
    else:
        out = (s2 - lo) / (hi - lo)
    if not higher_is_better:
        out = 1.0 - out
    return out.fillna(0.5)

def _safe_col(df: pd.DataFrame, *cands: str) -> str | None:
    for c in cands:
        if c in df.columns:
            return c
    return None

def compute_product_scores(cand: pd.DataFrame, prefs: dict) -> pd.DataFrame:
    """Score 0–100 basato su colonne disponibili (TER, AUM, NAV, risk metrics, performance, rating)."""
    df = cand.copy()

    # Base features
    ter_c = _safe_col(df, "ter", "TER")
    aum_c = _safe_col(df, "aum_eur", "AUM", "aum")
    nav_c = _safe_col(df, "NAV", "nav")
    esg_c = _safe_col(df, "Rating ESG", "rating_esg", "esg_rating", "ESG")
    quant_c = _safe_col(df, "Rating Quantalys", "rating_quantalys", "quantalys", "Quantalys")
    coh_c = _safe_col(df, "Coerenza con il Mercato", "Coerenza Mercato", "coerenza_mercato", "coerenza")

    risk5_c = _safe_col(df, "Rischio a 5 anni", "risk_5y", "vol_5y", "std_5y")
    dd5_c   = _safe_col(df, "Max drawdown a 5 anni", "max_drawdown_5y", "mdd_5y")
    sharpe_c= _safe_col(df, "Sharpe Ratio", "sharpe_5y", "sharpe")
    sortino_c= _safe_col(df, "Sortino Ratio", "sortino_5y", "sortino")
    ir_c    = _safe_col(df, "Information Ratio", "information_ratio_5y", "ir_5y")
    alpha_c = _safe_col(df, "Alfa del prodotto a 5 anni", "alpha_5y", "alpha")
    beta_c  = _safe_col(df, "Beta del prodotto a 5 anni", "beta_5y", "beta")

    perf1_c = _safe_col(df, "Perf Cum 1Y", "Perf 1Y", "perf_1y", "U")
    perf3_c = _safe_col(df, "Perf Cum 3Y", "Perf 3Y", "perf_3y", "V")
    perf5_c = _safe_col(df, "Perf Cum 5Y", "Perf 5Y", "perf_5y", "W")
    perf8_c = _safe_col(df, "Perf Cum 8Y", "Perf 8Y", "perf_8y", "X")

    # Preferences weights (0..1)
    w_cost = float(prefs.get("w_cost", 0.25))
    w_size = float(prefs.get("w_size", 0.15))
    w_quality = float(prefs.get("w_quality", 0.30))
    w_perf = float(prefs.get("w_perf", 0.20))
    w_esg = float(prefs.get("w_esg", 0.10))
    w_coh = float(prefs.get("w_coh", 0.00))

    # Build sub-scores (each 0..1)
    sub_cost = _minmax_norm(df[ter_c], higher_is_better=False) if ter_c else pd.Series([0.5]*len(df), index=df.index)
    sub_size = pd.Series([0.5]*len(df), index=df.index)
    if aum_c:
        sub_size = _minmax_norm(df[aum_c], higher_is_better=True)
    # NAV as investibility: lower is better (optional)
    if nav_c and prefs.get("nav_matters", False):
        sub_nav = _minmax_norm(df[nav_c], higher_is_better=False)
        sub_size = 0.65*sub_size + 0.35*sub_nav

    # Quality = combine risk & ratios if available
    parts = []
    if risk5_c: parts.append(_minmax_norm(df[risk5_c], higher_is_better=False))
    if dd5_c:   parts.append(_minmax_norm(df[dd5_c], higher_is_better=False))
    if sharpe_c: parts.append(_minmax_norm(df[sharpe_c], higher_is_better=True))
    if sortino_c: parts.append(_minmax_norm(df[sortino_c], higher_is_better=True))
    if ir_c and prefs.get("use_ir", False): parts.append(_minmax_norm(df[ir_c], higher_is_better=True))
    if alpha_c and prefs.get("use_alpha", False): parts.append(_minmax_norm(df[alpha_c], higher_is_better=True))
    if beta_c and prefs.get("use_beta", False): parts.append(_minmax_norm(df[beta_c], higher_is_better=False))
    sub_quality = sum(parts)/len(parts) if parts else pd.Series([0.5]*len(df), index=df.index)

    # Performance (prefer longer horizons)
    pparts=[]
    if perf3_c: pparts.append(_minmax_norm(df[perf3_c], higher_is_better=True)*0.35)
    if perf5_c: pparts.append(_minmax_norm(df[perf5_c], higher_is_better=True)*0.45)
    if perf1_c: pparts.append(_minmax_norm(df[perf1_c], higher_is_better=True)*0.10)
    if perf8_c: pparts.append(_minmax_norm(df[perf8_c], higher_is_better=True)*0.10)
    if pparts:
        sub_perf = sum(pparts)
        sub_perf = sub_perf / sub_perf.max() if sub_perf.max() != 0 else sub_perf
    else:
        sub_perf = pd.Series([0.5]*len(df), index=df.index)

    # ESG / Ratings
    sub_esg = pd.Series([0.5]*len(df), index=df.index)
    if w_esg > 0:
        esg_parts=[]
        if esg_c: esg_parts.append(_minmax_norm(df[esg_c], higher_is_better=True))
        if quant_c and prefs.get("use_quantalys", True): esg_parts.append(_minmax_norm(df[quant_c], higher_is_better=True))
        if esg_parts:
            sub_esg = sum(esg_parts)/len(esg_parts)

    
    # Coerenza con il Mercato (1=massima coerenza, 4=minima) -> più basso è meglio
    sub_coh = pd.Series([0.5]*len(df), index=df.index)
    if coh_c and w_coh > 0:
        sub_coh = _minmax_norm(df[coh_c], higher_is_better=False)
# Weighted score
    wsum = max(w_cost + w_size + w_quality + w_perf + w_esg + w_coh, 1e-9)
    score01 = (w_cost*sub_cost + w_size*sub_size + w_quality*sub_quality + w_perf*sub_perf + w_esg*sub_esg + w_coh*sub_coh) / wsum
    df["ai_base_score"] = (score01 * 100).round(1)
    return df

def build_product_rationale(row: dict, prefs: dict) -> str:
    reasons = []
    def add(label, cond=True):
        if cond:
            reasons.append(label)
    ter = row.get("ter", row.get("TER", None))
    if ter is not None and not pd.isna(ter):
        add(f"Costi (TER) contenuti: {float(ter):.2f}%")
    aum = row.get("aum_eur", row.get("AUM", None))
    if aum is not None and not pd.isna(aum):
        try:
            add(f"Dimensione rilevante (AUM): €{float(aum):,.0f}".replace(",", "."))
        except Exception:
            pass
    coh = row.get("Coerenza con il Mercato", row.get("Coerenza Mercato", row.get("coerenza_mercato", None)))
    if coh is not None and not pd.isna(coh):
        try:
            add(f"Coerenza con il mercato elevata: {int(float(coh))} (1=massima)")
        except Exception:
            pass
    rep = str(row.get("replication","")).lower()
    if rep in ["physical","synthetic"]:
        add(f"Replica: {rep}")
    if prefs.get("esg_focus", 0.0) > 0:
        esg = row.get("Rating ESG", row.get("rating_esg", None))
        if esg is not None and not pd.isna(esg):
            add(f"Rating ESG: {esg}")
    # fallback
    if not reasons:
        reasons = ["Selezionato dall’AI per miglior equilibrio tra costi, qualità e coerenza con l’asset class."]
    return " • ".join(reasons[:3])




def _norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", str(s).strip().lower())

def _try_parse_number(x):
    if x is None:
        return None
    s = str(x).strip()
    s = s.replace("€", "").replace("%", "").replace("bps", "")
    s = s.replace(".", "").replace(",", ".") if re.search(r"\d+,\d+", s) else s.replace(",", ".")
    s = re.sub(r"[^\d\.\-]", "", s)
    try:
        return float(s)
    except Exception:
        return None

def parse_hard_constraints(notes: str, df_cols: list[str]) -> tuple[list[dict], list[str]]:
    """
    Estrae vincoli 'hard' dal testo libero. Restituisce:
    - constraints: lista di dict {col, op, value, raw}
    - unparsed: lista di stringhe (frasi non traducibili in vincolo rigido)
    """
    notes = (notes or "").strip()
    if not notes:
        return [], []

    # mapping colonne (normalizzate -> originali)
    col_map = {_norm_text(c): c for c in df_cols}
    # ordina per lunghezza desc per match più specifici
    cols_sorted = sorted(df_cols, key=lambda x: len(str(x)), reverse=True)

    # split in frasi
    parts = [p.strip(" \n\r\t;•-") for p in re.split(r"[;\n\r]+", notes) if p.strip()]
    constraints = []
    unparsed = []

    for raw in parts:
        t = _norm_text(raw)

        # trova colonna citata nella frase
        found_col = None
        for c in cols_sorted:
            cn = _norm_text(c)
            if cn and cn in t:
                found_col = c
                break

        if not found_col:
            unparsed.append(raw)
            continue

        # operatori espliciti
        op = None
        val_str = None

        m = re.search(r"(==|=|>=|<=|!=|>|<)\s*(.+)$", t)
        if m:
            op = m.group(1)
            val_str = m.group(2).strip()
        else:
            # operatori "italiani"
            for key, mapped in [
                ("pari a", "=="),
                ("uguale a", "=="),
                ("= ", "=="),
                ("almeno", ">="),
                ("minimo", ">="),
                ("non meno di", ">="),
                ("massimo", "<="),
                ("non oltre", "<="),
                ("non più di", "<="),
                ("inferiore a", "<"),
                ("minore di", "<"),
                ("superiore a", ">"),
                ("maggiore di", ">"),
                ("diverso da", "!="),
                ("contiene", "contains"),
            ]:
                if key in t:
                    op = mapped
                    # prende ciò che segue la keyword
                    val_str = t.split(key, 1)[1].strip()
                    break

        if not op or val_str is None or val_str == "":
            unparsed.append(raw)
            continue

        # ripulisci valore (rimuove eventuale colonna ripetuta)
        val_str = val_str.strip().strip('"').strip("'")
        # se inizia con "deve" ecc.
        val_str = re.sub(r"^(deve|devono|essere|avere)\s+", "", val_str).strip()

        # parse valore in base al tipo (tentativo)
        # bool
        if val_str.lower() in ["true", "false", "vero", "falso", "si", "sì", "no"]:
            v = val_str.lower() in ["true", "vero", "si", "sì"]
        else:
            vnum = _try_parse_number(val_str)
            v = vnum if vnum is not None else val_str

        constraints.append({"col": found_col, "op": op, "value": v, "raw": raw})

    return constraints, unparsed

def apply_hard_constraints(df: pd.DataFrame, constraints: list[dict]) -> pd.DataFrame:
    """Applica vincoli hard su un DataFrame e restituisce il sottoinsieme filtrato."""
    out = df.copy()
    for c in constraints:
        col = c["col"]
        op = c["op"]
        v = c["value"]

        if col not in out.columns:
            continue

        s = out[col]

        # contains
        if op == "contains":
            out = out[s.astype(str).str.lower().str.contains(str(v).lower(), na=False)]
            continue

        # numerico
        if isinstance(v, (int, float)):
            s_num = pd.to_numeric(s, errors="coerce")
            if op in ["=", "=="]:
                out = out[s_num == float(v)]
            elif op == ">=":
                out = out[s_num >= float(v)]
            elif op == "<=":
                out = out[s_num <= float(v)]
            elif op == ">":
                out = out[s_num > float(v)]
            elif op == "<":
                out = out[s_num < float(v)]
            elif op == "!=":
                out = out[s_num != float(v)]
            continue

        # stringhe
        s_str = s.astype(str).str.strip().str.lower()
        v_str = str(v).strip().lower()
        if op in ["=", "=="]:
            out = out[s_str == v_str]
        elif op == "!=":
            out = out[s_str != v_str]

    return out


def _render_ai_products_from_portfolio(client_key: str, pid: str, payload: dict) -> None:
    """Selezione Prodotti → Trasforma in Portafoglio di Prodotti (AI)."""
    ensure_product_database_storage()
    db = st.session_state.get("product_database", None)

    st.markdown(
        '<div class="uw-card"><h2>Trasforma in Portafoglio di Prodotti (AI)</h2>'
        '<p>Selezione automatica (AI) di ETF/fondi coerenti con il portafoglio in asset class. '
        'L’AI utilizza il Database Prodotti caricato in Tools → Database Prodotti.</p></div>',
        unsafe_allow_html=True
    )

    if not (isinstance(db, dict) and isinstance(db.get("df"), pd.DataFrame)):
        st.warning("Database Prodotti non disponibile. Carichi prima il file in Tools → Database Prodotti.")
        st.markdown('👉 <a href="?{auth_qs}main=Tools&tools=Database%20Prodotti" target="_self">Apri Tools → Database Prodotti</a>', unsafe_allow_html=True)
        return

    products_df = db["df"].copy()

    # --- scelta composizione: t=0 oppure dinamica
    has_path = isinstance(payload.get("composition_path", None), list) and len(payload.get("composition_path", [])) > 0
    mode = st.radio(
        "Composizione da replicare",
        ["t=0 (iniziale)"] + (["Dinamica (usa traiettoria pesi)"] if has_path else []),
        horizontal=True,
        key=f"ai_prod_mode_{pid}",
    )

    # target weights (t=0)
    w0 = payload.get("composition", {}) or {}
    if not isinstance(w0, dict) or len(w0) == 0:
        st.error("Il portafoglio non contiene una composizione iniziale valida.")
        return

    # --- preferenze (semplici)
    st.markdown('<div class="uw-card"><h3>Preferenze di selezione</h3></div>', unsafe_allow_html=True)

    colA, colB, colC = st.columns([1,1,1])
    with colA:
        n_products = st.slider("Numero prodotti per asset class", 1, 3, 1, key=f"ai_nprod_{pid}")
        replication_pref = st.selectbox("Replica preferita", ["Indifferente", "physical", "synthetic"], key=f"ai_rep_{pid}")
        nav_matters = st.checkbox("Ticket minimo (NAV) importante", value=False, key=f"ai_nav_{pid}")
    with colB:
        esg_focus = st.slider("Peso ESG/Rating", 0.0, 1.0, 0.3, 0.05, key=f"ai_esg_{pid}")
        use_quantalys = st.checkbox("Usa Rating Quantalys (se disponibile)", value=True, key=f"ai_qua_{pid}")
        use_ir = st.checkbox("Usa Information Ratio (se disponibile)", value=False, key=f"ai_ir_{pid}")
    with colC:
        w_cost = st.slider("Peso Costi (TER)", 0.0, 1.0, 0.25, 0.05, key=f"ai_wcost_{pid}")
        w_quality = st.slider("Peso Qualità/Rischio (5Y)", 0.0, 1.0, 0.30, 0.05, key=f"ai_wqual_{pid}")
        w_perf = st.slider("Peso Performance (rolling)", 0.0, 1.0, 0.20, 0.05, key=f"ai_wperf_{pid}")
        w_size = st.slider("Peso Dimensione/Investibilità", 0.0, 1.0, 0.15, 0.05, key=f"ai_wsize_{pid}")
        w_coh = st.slider("Peso Coerenza Mercato (1=alta coerenza)", 0.0, 1.0, 0.00, 0.05, key=f"ai_wcoh_{pid}")

    notes = st.text_area(
        "Scriva all’AI eventuali preferenze/ vincoli (linguaggio naturale)",
        value="",
        height=90,
        key=f"ai_notes_{pid}",
        placeholder="Esempio: Preferisco ETF grandi e molto liquidi; evito replica sintetica; per l'azionario globale privilegio un ETF core semplice da spiegare.",
    )

    prefs = {
        "w_cost": w_cost,
        "w_size": w_size,
        "w_quality": w_quality,
        "w_perf": w_perf,
        "w_esg": float(esg_focus),
        "w_coh": float(w_coh),
        "nav_matters": bool(nav_matters),
        "use_quantalys": bool(use_quantalys),
        "use_ir": bool(use_ir),
        "esg_focus": float(esg_focus),
    }

    run = st.button("Avvia AI Selection", use_container_width=True, key=f"ai_run_{pid}")

    # cache risultati: se l'utente ha già lanciato l'AI, li mostriamo anche senza rilanciare
    _res_key = f"ai_prod_results_{pid}"

    if run:
        st.session_state.pop(_res_key, None)  # rigenera da zero ad ogni run
    else:
        _cached = st.session_state.get(_res_key)
        if _cached is None:
            return

    prog = None
    if run:
        # --- “AI in azione” (percepibile)
        prog = st.progress(0)
        st.info("🧠 L’Intelligenza Artificiale sta analizzando l’universo prodotti e i trade-off (costi, rischio, rating, coerenza).")
        if prog is not None:
            prog.progress(15)

        # hard filters generali
        if replication_pref != "Indifferente" and "replication" in products_df.columns:
            products_df = products_df[products_df["replication"].astype(str).str.lower() == replication_pref]

        if "ucits" in products_df.columns:
            # accetta True o 1
            products_df = products_df[(products_df["ucits"] == True) | (products_df["ucits"] == 1)]

        if prog is not None:

            prog.progress(35)

        # ============================
        # VINCOLI HARD (da testo libero)
        # ============================
        hard_constraints, unparsed_constraints = parse_hard_constraints(notes, list(products_df.columns))

        if unparsed_constraints:
            st.error(
                "Non posso procedere: alcune richieste nel testo non sono traducibili in vincoli rigidi sulle variabili del Database Prodotti.\n\n"
                "Richieste non applicabili come vincolo hard:\n- " + "\n- ".join(unparsed_constraints) +
                "\n\nEsempi validi: 'Rating Quantalys = 5', 'ter <= 0.20', 'aum_eur >= 500000000', 'provider contiene iShares'."
            )
            if prog is not None:
                prog.progress(100)
            return

        if hard_constraints:
            st.success(
                "Vincoli hard riconosciuti (applicati come filtri):\n- " +
                "\n- ".join([f"{c['col']} {c['op']} {c['value']}" for c in hard_constraints])
            )

        results = []
        for ac, w in w0.items():
            try:
                w = float(w)
            except Exception:
                continue
            if w <= 0:
                continue

            # cand per asset class
            cand = products_df[products_df["asset_class"].astype(str).str.strip() == str(ac).strip()].copy()

            # applica vincoli hard (da testo libero)
            if hard_constraints:
                cand = apply_hard_constraints(cand, hard_constraints)

            if cand.empty:
                results.append({"asset_class": ac, "weight": w, "error": "Nessun prodotto nel Database per questa asset class."})
                continue

            # se i candidati sono insufficienti per rispettare il numero di prodotti richiesto
            if len(cand) < int(n_products):
                results.append({
                    "asset_class": ac,
                    "weight": w,
                    "error": f"Vincoli hard non soddisfabili: disponibili {len(cand)} prodotti per questa asset class, ma ne sono richiesti {int(n_products)}. Ampliare il database o ridurre 'Numero prodotti per asset class'."
                })
                continue

            # scoring
            scored = compute_product_scores(cand, prefs).sort_values("ai_base_score", ascending=False)
            top = scored.head(int(n_products)).copy()

            # allocazione pesi: split uniforme dentro asset class
            split_w = w / max(len(top), 1)
            selected = []
            for _, r in top.iterrows():
                rdict = r.to_dict()
                selected.append({
                    "isin": rdict.get("isin"),
                    "name": rdict.get("name"),
                    "provider": rdict.get("provider"),
                    "asset_class": ac,
                    "weight": split_w,
                    "ai_score": float(rdict.get("ai_base_score", 50.0)),
                    "rationale": build_product_rationale(rdict, prefs),
                })

            # alternative: successivi 2
            alts = scored.iloc[int(n_products):int(n_products)+2]
            alternatives = []
            for _, r in alts.iterrows():
                rdict = r.to_dict()
                alternatives.append({
                    "isin": rdict.get("isin"),
                    "name": rdict.get("name"),
                    "ai_score": float(rdict.get("ai_base_score", 50.0)),
                    "why": build_product_rationale(rdict, prefs),
                })

            results.append({
                "asset_class": ac,
                "weight": w,
                "selected": selected,
                "alternatives": alternatives,
                "n_candidates": int(len(cand)),
            })

        if prog is not None:

            prog.progress(75)


        st.session_state[_res_key] = results
    else:
        results = st.session_state.get(_res_key, [])
    # --- Output
    st.markdown('<div class="uw-card"><h3>Risultato AI</h3></div>', unsafe_allow_html=True)

    def _fmt_eur(_x):
        try:
            v = float(_x)
        except Exception:
            return "—"
        s = f"{v:,.0f}".replace(",", "X").replace(".", ",").replace("X", ".")
        return f"{s}€"

    # conferimento iniziale (t=0) per importi
    _initial_amt = 0.0
    for _k in ["initial_amount", "gbi_initial_amount", "initial_contribution", "conferimento_iniziale"]:
        if _k in payload and payload.get(_k) not in [None, ""]:
            try:
                _initial_amt = float(payload.get(_k))
                break
            except Exception:
                pass

    for item in results:
        ac = item.get("asset_class")
        w = float(item.get("weight", 0.0))
        st.markdown(f"#### {ac}  —  peso asset class: **{w:.1%}**" + (f"  —  Importo da investire: **{_fmt_eur(_initial_amt * w)}**" if _initial_amt > 0 else ""))

        if item.get("error"):
            st.warning(item["error"])
            continue

        st.caption(f"Candidati analizzati: {item.get('n_candidates', 0)}")

        for s in item.get("selected", []):
            st.markdown(
                f"<div class='uw-card' style='margin-top:8px;'>"
                f"<b>{s.get('name','')}</b> ({s.get('isin','')}) — <b>{s.get('weight',0):.1%}</b><br>"
                f"<span class='uw-badge'>AI Score {float(s.get('ai_score',50)):.0f}/100</span><br>"
                f"<small>{s.get('rationale','')}</small>"
                f"</div>",
                unsafe_allow_html=True
            )

        alts = item.get("alternatives", [])
        if alts:
            with st.expander("Alternative (trade-off)"):
                for a in alts:
                    a_name = a.get("name","")
                    a_isin = a.get("isin","")
                    st.write(f"- {a_name} ({a_isin}) — AI Score {float(a.get('ai_score',50)):.0f}/100")
                    st.caption(a.get("why",""))

                    # Sostituzione: l'alternativa diventa il prodotto prescelto (slot 1..n)
                    for _j, _sel in enumerate(item.get("selected", [])):
                        _btn = st.button(
                            f"Usa questa alternativa al posto del prodotto #{_j+1}",
                            key=f"swap_{pid}_{str(ac).replace(' ','_')}_{a_isin}_{_j}"
                        )
                        if _btn:
                            # mantieni il peso dello slot
                            keep_w = float(_sel.get("weight", 0.0))
                            new_sel = {
                                **_sel,
                                "isin": a.get("isin"),
                                "name": a.get("name"),
                                "ai_score": float(a.get("ai_score", 50.0)),
                                "rationale": a.get("why",""),
                                "weight": keep_w,
                            }
                            item["selected"][_j] = new_sel
                            st.session_state[_res_key] = results
                            st.success("Prodotto sostituito.")
                            st.rerun()

    if prog is not None:

        prog.progress(90)

    

    # --- Sintesi: composizione del portafoglio in prodotti
    st.markdown('<div class="uw-card"><h3>Sintesi: Portafoglio in Prodotti</h3></div>', unsafe_allow_html=True)

    _rows = []
    for _it in results:
        _ac = _it.get("asset_class")
        for _s in _it.get("selected", []):
            _w = float(_s.get("weight", 0.0))
            _label = f"{_s.get('name','')} ({_s.get('isin','')})"
            _rows.append({
                "Prodotto": _label,
                "ISIN": str(_s.get("isin","")),
                "Asset Class": _ac,
                "Peso (%)": _w * 100.0,
                "Importo (€)": (_initial_amt * _w) if _initial_amt > 0 else None,
            })

    if len(_rows) == 0:
        st.warning("Nessun prodotto selezionato da sintetizzare.")
    else:
        _df_prod = pd.DataFrame(_rows)
        _tot_w = float(_df_prod["Peso (%)"].sum()) if "Peso (%)" in _df_prod.columns else 0.0
        _tot_amt = float(_df_prod["Importo (€)"].sum()) if (_initial_amt > 0 and "Importo (€)" in _df_prod.columns) else None

        colP1, colP2 = st.columns([1.1, 0.9])
        with colP1:
            import plotly.express as px
            fig_pie = px.pie(_df_prod, names="Prodotto", values="Peso (%)", title="Composizione del portafoglio in prodotti")
            fig_pie.update_traces(textinfo="percent")
            fig_pie.update_layout(margin=dict(l=10, r=10, t=60, b=10))
            st.plotly_chart(fig_pie, use_container_width=True)

        with colP2:
            _show = _df_prod.copy()
            if "ISIN" in _show.columns:
                _show = _show.drop(columns=["ISIN"])
            _show["Peso (%)"] = _show["Peso (%)"].map(lambda x: f"{x:.1f}%")
            if _initial_amt > 0:
                _show["Importo (€)"] = _show["Importo (€)"].map(_fmt_eur)
            st.dataframe(_show, use_container_width=True, hide_index=True)

            st.markdown(f"**Totale peso:** {(_tot_w):.1f}%")
            if _initial_amt > 0 and _tot_amt is not None:
                st.markdown(f"**Totale importo:** {_fmt_eur(_tot_amt)}")

    # --- Analisi variabili (3 selezioni) sui prodotti scelti ---
    st.markdown('<div class="uw-card"><h4>Analisi variabili sui prodotti selezionati</h4>'
                '<p>Selezioni fino a 3 variabili (tra tutte quelle presenti nel database prodotti). '
                'Per variabili numeriche viene mostrato un grafico a barre con valori per prodotto e linee di riferimento '
                '(minimo, medio, massimo).</p></div>', unsafe_allow_html=True)

    # Costruisce una tabella "df_sel" con una riga per prodotto selezionato, arricchita con tutte le colonne del database
    try:
        _lookup = products_df.copy()
        if "isin" in _lookup.columns:
            _lookup["isin"] = _lookup["isin"].astype(str)
        _base = _df_prod.copy()
        if "ISIN" in _base.columns:
            _base["ISIN"] = _base["ISIN"].astype(str)
        # merge left per portarsi dietro tutte le variabili del database
        df_sel = _base.merge(_lookup, how="left", left_on="ISIN", right_on="isin", suffixes=("", "_db"))
    except Exception:
        df_sel = None

    if df_sel is None or len(df_sel) == 0:
        st.info("Nessun dettaglio aggiuntivo disponibile per l’analisi variabili.")
    else:
        # tutte le variabili del file (colonne) — includiamo anche quelle extra
        all_vars = list(products_df.columns)

        # default intelligenti se presenti
        def _pick_default(candidates):
            for c in candidates:
                if c in all_vars:
                    return c
            return all_vars[0] if len(all_vars) else None

        d1 = _pick_default(["ter", "aum_eur", "risk_5y", "sharpe_5y"])
        d2 = _pick_default(["risk_5y", "max_drawdown_5y", "sortino_5y", "tracking_diff"])
        d3 = _pick_default(["esg_rating", "quantalys_rating", "information_ratio_5y", "beta_5y"])

        cV1, cV2, cV3 = st.columns(3)
        with cV1:
            var1 = st.selectbox("Variabile 1", options=all_vars, index=all_vars.index(d1) if d1 in all_vars else 0, key=f"ai_var1_{pid}")
        with cV2:
            var2 = st.selectbox("Variabile 2", options=all_vars, index=all_vars.index(d2) if d2 in all_vars else min(1, len(all_vars)-1), key=f"ai_var2_{pid}")
        with cV3:
            var3 = st.selectbox("Variabile 3", options=all_vars, index=all_vars.index(d3) if d3 in all_vars else min(2, len(all_vars)-1), key=f"ai_var3_{pid}")

        selected_vars = [v for v in [var1, var2, var3] if v]
        selected_vars = list(dict.fromkeys(selected_vars))  # unique, preserve order

        import numpy as _np
        import plotly.graph_objects as _go

        def _is_number_series(s: pd.Series) -> bool:
            # prova conversione robusta
            try:
                _ = pd.to_numeric(s, errors="coerce")
                return _.notna().any()
            except Exception:
                return False

        def _plot_numeric(varname: str):
            s_raw = df_sel[varname] if varname in df_sel.columns else pd.Series(dtype=float)
            s = pd.to_numeric(s_raw, errors="coerce")
            tmp = df_sel[["Prodotto", "ISIN"]].copy() if "ISIN" in df_sel.columns else df_sel[["Prodotto"]].copy()
            tmp["val"] = s

            tmp = tmp.dropna(subset=["val"])
            if len(tmp) == 0:
                st.warning(f"Nessun valore numerico disponibile per '{varname}' sui prodotti selezionati.")
                return

            vmin = float(tmp["val"].min())
            vmax = float(tmp["val"].max())
            vmean = float(tmp["val"].mean())

            fig = _go.Figure()
            fig.add_trace(_go.Bar(x=tmp["Prodotto"], y=tmp["val"], name=varname))
            # linee di riferimento min/mean/max
            for yv, lab in [(vmin, "Min"), (vmean, "Media"), (vmax, "Max")]:
                fig.add_shape(type="line", xref="paper", x0=0, x1=1, yref="y", y0=yv, y1=yv, line=dict(width=1, dash="dot"))
                fig.add_annotation(xref="paper", x=1.0, y=yv, xanchor="left", text=f"{lab}: {yv:.3g}", showarrow=False)

            fig.update_layout(
                title=f"{varname} — valori sui prodotti selezionati",
                xaxis_title="Prodotti",
                yaxis_title=varname,
                margin=dict(l=10, r=10, t=60, b=10),
                height=380,
            )
            st.plotly_chart(fig, use_container_width=True)

        def _show_categorical(varname: str):
            s = df_sel[varname] if varname in df_sel.columns else pd.Series(dtype=object)
            tmp = df_sel[["Prodotto"]].copy()
            tmp[varname] = s.astype(str)
            st.dataframe(tmp, use_container_width=True, hide_index=True)

        for v in selected_vars:
            st.markdown(f"#### {v}")
            if v in df_sel.columns and _is_number_series(df_sel[v]):
                _plot_numeric(v)
            else:
                st.info("Variabile non numerica: visualizzazione tabellare per prodotto.")
                _show_categorical(v)


    # --- Salva soluzione prodotti dentro il portafoglio
    if st.button("Salva Soluzione di Prodotti (collegata al portafoglio)", use_container_width=True, key=f"ai_save_{pid}"):
        payload2 = dict(payload)
        payload2["product_solution"] = {
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_db": db.get("source_name",""),
            "mode": "dynamic" if (mode.startswith("Dinamica")) else "t0",
            "prefs": {**prefs, "notes_free_text": notes},
            "results": results,
        }
        # aggiorna storage portafogli
        st.session_state["portfolios"][pid] = payload2
        persist_portfolios_from_session()
        st.success("Soluzione di Prodotti salvata nel portafoglio selezionato.")

    if prog is not None:

        prog.progress(100)


def render_selezione_prodotti():
    """Selezione Prodotti."""
    ensure_anagrafica_storage()
    ensure_portfolio_storage()

    st.markdown(
        '<div class="uw-card"><h2>Selezione Prodotti</h2>'
        '<p>In questa sezione si seleziona un portafoglio salvato e si avvia il processo di selezione degli strumenti (es. ETF) coerenti con la composizione in mercati.</p></div>',
        unsafe_allow_html=True
    )

    sub = st.radio(
        "Sotto-sezione",
        ["Selezionare del Portafoglio in Mercati", "Trasforma in Portafoglio di Prodotti (AI)"],
        horizontal=True,
        key="sp_subsection"
    )

    render_ai_productn = (sub == "Trasforma in Portafoglio di Prodotti (AI)")

    # =======================
    # Selezione Cliente + Portafoglio (comune)
    # =======================

    # =======================
    anags = st.session_state.get("anagrafiche", {})
    if not anags:
        st.warning("Nessun cliente salvato. Creare prima un’Anagrafica in “Clienti/Investitori”.")
        return

    portfolios = st.session_state.get("portfolios", {}) or {}
    client_portfolios_idx = st.session_state.get("client_portfolios", {}) or {}

    # 1) Selezione Cliente
    client_keys = list(anags.keys())
    labels = []
    for k in client_keys:
        d = anags[k].get("data", {})
        labels.append(f'{d.get("nome","").strip()} {d.get("cognome","").strip()}  —  ({k})')

    sel_label = st.selectbox("1) Seleziona Cliente / Investitore", labels, key="sp_client_sel")
    client_key = client_keys[labels.index(sel_label)]
    client_data = anags[client_key].get("data", {})

    st.markdown(
        f'<div class="uw-card"><h2>Cliente selezionato</h2>'
        f'<p><b>{client_data.get("nome","")} {client_data.get("cognome","")}</b> · Chiave: <b>{client_key}</b></p></div>',
        unsafe_allow_html=True
    )

    # 2) Elenco portafogli del cliente
    # 2) Elenco portafogli del cliente (unione indice + filtro sui payload, così includiamo sempre anche i portafogli GBI)
    pids_idx = list(client_portfolios_idx.get(client_key, []))
    pids_payload = [pid for pid, p in portfolios.items() if p.get("client_key") == client_key]
    pids = sorted(list(set(pids_idx).union(set(pids_payload))))

    # pulizia: mantengo solo quelli effettivamente presenti
    pids = [pid for pid in pids if pid in portfolios]

    if not pids:
        st.info("Per questo cliente non risultano portafogli salvati. Crearne uno in “Crea Soluzione di Investimento”.")
        return

    # label portafogli
    pf_labels = []
    for pid in pids:
        p = portfolios.get(pid, {})
        nm = str(p.get("portfolio_name", pid))
        created = str(p.get("created_at", ""))
        mode = "GBI" if bool(p.get("gbi", False)) or ("goal-based" in str(p.get("objective","")).lower()) else "Asset-Only"
        pf_labels.append(f'{nm}  ·  {mode}  ·  {created}  —  ({pid})')

    sel_pf_label = st.selectbox("2) Seleziona Portafoglio salvato", pf_labels, key="sp_portfolio_sel")
    pid = pids[pf_labels.index(sel_pf_label)]
    payload = portfolios.get(pid, {})


    # Se l'utente ha scelto la sotto-sezione AI, eseguo la trasformazione in portafoglio prodotti
    if render_ai_productn:
        _render_ai_products_from_portfolio(client_key, pid, payload)
        return

    # 3) Visualizzazione – composizione nel tempo + composizione iniziale
    st.markdown(
        '<div class="uw-card"><h2>Portafoglio in Mercati</h2>'
        '<p>Di seguito: (a) grafico ad area della dinamica di composizione nell’orizzonte di investimento; '
        '(b) composizione iniziale (t=0).</p></div>',
        unsafe_allow_html=True
    )

    # --- Costruzione traiettoria pesi ---
    w0 = payload.get("composition", {}) or {}
    if not isinstance(w0, dict) or len(w0) == 0:
        st.error("Il portafoglio selezionato non contiene una composizione valida.")
        return

    # normalizzo e ordino
    w0 = {str(k): float(v) for k, v in w0.items() if v is not None}
    s0 = float(sum([max(v, 0.0) for v in w0.values()]))
    if s0 <= 0:
        st.error("Il portafoglio selezionato non contiene pesi positivi.")
        return
    w0 = {k: max(v, 0.0) / s0 for k, v in w0.items()}
    asset_names = list(w0.keys())

    # Se disponibile, utilizzo la traiettoria dei pesi salvata (es. Life Cycle).
    comp_path = payload.get("composition_path", None)
    if isinstance(comp_path, list) and len(comp_path) > 0 and isinstance(comp_path[0], dict) and ("Anno" in comp_path[0]):
        df_w = pd.DataFrame(comp_path).copy()
        # garantisco ordinamento e tipo
        df_w["Anno"] = df_w["Anno"].astype(int)
        df_w = df_w.sort_values("Anno").reset_index(drop=True)
        # aggiorno lista asset in base alle colonne effettivamente presenti
        asset_names = [c for c in df_w.columns if c != "Anno"]
        # se manca t=0 (raro), lo ricostruisco dai pesi iniziali
        if 0 not in set(df_w["Anno"].tolist()):
            row0 = {"Anno": 0, **{a: float(w0.get(a, 0.0)) for a in asset_names}}
            df_w = pd.concat([pd.DataFrame([row0]), df_w], ignore_index=True).sort_values("Anno").reset_index(drop=True)
    else:
        H = int(payload.get("horizon_years", 1) or 1)
        years = list(range(0, H + 1))
        df_w = pd.DataFrame([w0 for _ in years])
        df_w["Anno"] = years
        asset_names = list(w0.keys())

    long_df = df_w.melt(id_vars=["Anno"], var_name="Asset Class", value_name="Peso")

    try:
        cmap = _build_asset_color_map(asset_names)
    except Exception:
        cmap = None

    
    # =======================
    # Grafico conferimenti (iniziale + periodici)
    # =======================
    try:
        _init_amt = payload.get("initial_amount", None)
        if _init_amt is None:
            _init_amt = payload.get("gbi_initial_amount", 0.0)
        _init_amt = float(_init_amt or 0.0)
    except Exception:
        _init_amt = 0.0

    try:
        _per_amt = float(payload.get("periodic_amount", 0.0) or 0.0)
    except Exception:
        _per_amt = 0.0

    _per_freq = str(payload.get("periodic_freq", "") or "")
    try:
        _per_years = int(payload.get("periodic_years", 0) or 0)
    except Exception:
        _per_years = 0

    _freq_mult = {"Mensile": 12, "Trimestrale": 4, "Semestrale": 2, "Annuale": 1}
    _per_per_year = _per_amt * _freq_mult.get(_per_freq, 0)

    # Anni considerati: da 0 a max(orizzonte, anni versamenti)
    try:
        _H = int(payload.get("horizon_years", 1) or 1)
    except Exception:
        _H = 1
    _max_year = max(_H, _per_years)

    years_c = list(range(0, _max_year + 1))
    init_series = [0.0 for _ in years_c]
    per_series = [0.0 for _ in years_c]

    # Convenzione: conferimento iniziale al tempo 0; versamenti periodici negli anni 1..periodic_years
    if _init_amt > 0:
        init_series[0] = _init_amt
    if _per_per_year > 0 and _per_years > 0:
        for yy in range(1, min(_per_years, _max_year) + 1):
            per_series[yy] = _per_per_year

    if (sum(init_series) + sum(per_series)) > 0:
        st.markdown('<div class="uw-sec-title-sm">Conferimenti (iniziale e periodici)</div>', unsafe_allow_html=True)
        fig_c = go.Figure()
        fig_c.add_trace(go.Bar(x=years_c, y=init_series, name="Conferimento iniziale"))
        fig_c.add_trace(go.Bar(x=years_c, y=per_series, name="Versamenti periodici"))
        fig_c.update_layout(
            barmode="stack",
            margin=dict(l=10, r=10, t=10, b=10),
            xaxis_title="Anno",
            yaxis_title="Importo (€)",
            hovermode="x unified",
            legend_title_text="",
        )
        st.plotly_chart(fig_c, use_container_width=True)
    else:
        # niente conferimenti disponibili: non mostro il grafico
        pass

    fig_area = px.area(
        long_df,
        x="Anno",
        y="Peso",
        color="Asset Class",
        color_discrete_map=cmap,
    )
    fig_area.update_layout(
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis_title="Anni (t)",
        yaxis_title="Peso",
        yaxis_tickformat=".0%",
        legend_title_text="",
        hovermode="x unified",
    )
    fig_area.update_traces(line=dict(width=0.5))

    st.plotly_chart(fig_area, use_container_width=True)

    st.markdown('<div class="uw-sec-title-sm">Composizione iniziale (t=0)</div>', unsafe_allow_html=True)

    # Conferimento iniziale (t=0): importo effettivamente investito nel portafoglio iniziale
    initial_amount = payload.get("initial_amount", None)
    if initial_amount is None:
        initial_amount = payload.get("gbi_initial_amount", 0.0)
    try:
        initial_amount = float(initial_amount or 0.0)
    except Exception:
        initial_amount = 0.0

    if initial_amount > 0:
        st.markdown(
            f"<div style='margin-top:-6px; margin-bottom:8px; color:#4b5563;'>Conferimento iniziale (t=0): <b>{initial_amount:,.0f} €</b></div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            "<div style='margin-top:-6px; margin-bottom:8px; color:#4b5563;'>Conferimento iniziale (t=0): <b>non disponibile</b></div>",
            unsafe_allow_html=True,
        )


    # Robusto rispetto a differenze di naming (es. maiuscole/minuscole) tra pesi iniziali e colonne del path.
    def _norm_key(x: str) -> str:
        return re.sub(r"\s+", " ", str(x)).strip().lower()

    w0_norm = {_norm_key(k): float(v) for k, v in w0.items()}

    pesi0 = []
    for a in asset_names:
        if a in w0:
            pesi0.append(float(w0[a]))
        else:
            pesi0.append(float(w0_norm.get(_norm_key(a), 0.0)))

    pie_df = pd.DataFrame({
        "Asset Class": asset_names,
        "Peso": pesi0,
    }).sort_values("Peso", ascending=False)

    c1, c2 = st.columns([0.55, 0.45], gap="large")
    with c1:
        fig_pie = px.pie(pie_df, names="Asset Class", values="Peso", color="Asset Class", color_discrete_map=cmap)
        fig_pie.update_traces(textposition="inside", textinfo="percent+label")
        fig_pie.update_layout(margin=dict(l=10, r=10, t=20, b=10), legend_title_text="")
        st.plotly_chart(fig_pie, use_container_width=True)

    with c2:
        tbl = pie_df.copy()
        tbl["Peso (%)"] = (tbl["Peso"] * 100.0).round(2)

        # Importo da investire per asset class (sul conferimento iniziale a t=0)
        if "initial_amount" in locals() and float(initial_amount) > 0:
            tbl["Importo da investire (€)"] = (tbl["Peso"] * float(initial_amount)).round(2)
        else:
            tbl["Importo da investire (€)"] = np.nan

        tbl = tbl[["Asset Class", "Peso (%)", "Importo da investire (€)"]]

        # Totali (utile per verifica immediata)
        try:
            tot_peso = float(tbl["Peso (%)"].sum(skipna=True))
        except Exception:
            tot_peso = np.nan
        try:
            tot_imp = float(tbl["Importo da investire (€)"].sum(skipna=True))
        except Exception:
            tot_imp = np.nan

        total_row = pd.DataFrame([{
            "Asset Class": "TOTALE",
            "Peso (%)": tot_peso,
            "Importo da investire (€)": tot_imp,
        }])
        tbl_show = pd.concat([tbl, total_row], ignore_index=True)

        # Formattazione: peso con 2 decimali; importo con separatore migliaia e 0 decimali
        styler = tbl_show.style.format({
            "Peso (%)": "{:,.2f}",
            "Importo da investire (€)": "{:,.0f}",
        }, na_rep="")

        st.dataframe(styler, use_container_width=True, hide_index=True)

def ensure_anagrafica_storage():
    if "anagrafiche" not in st.session_state:
        # Dict: anagrafica_name -> payload
        st.session_state["anagrafiche"] = {}
    # Carica eventuali anagrafiche persistite (utile quando la navbar provoca rerun/nuova sessione)
    load_persisted_anagrafiche_into_session()
    if "client_portfolios" not in st.session_state:
        # Placeholder: anagrafica_name -> list of portfolios (future use)
        st.session_state["client_portfolios"] = {}

def ensure_portfolio_storage():
    # Dict: portfolio_id -> payload
    if "portfolios" not in st.session_state:
        st.session_state["portfolios"] = {}
    # Convenience index: anagrafica_key -> list of portfolio_id
    if "client_portfolios" not in st.session_state:
        st.session_state["client_portfolios"] = {}

    # reload per-utente (utile dopo cambio sezione / reload sessione)
    load_persisted_portfolios_into_session()

def _anagrafica_payload(name_key: str, data: dict):
    return {
        "key": name_key,
        "data": data,
        "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

def load_anagrafica_to_state(payload: dict):
    data = payload.get("data", {})
    # Identificativo anagrafica
    st.session_state["ana_name_key"] = payload.get("key", "")

    # A) Dati anagrafici
    st.session_state["ana_nome"] = data.get("nome", "")
    st.session_state["ana_cognome"] = data.get("cognome", "")
    st.session_state["ana_indirizzo"] = data.get("indirizzo", "")
    st.session_state["ana_professione"] = data.get("professione", "Altro")

    # B) Bilancio
    for k, v in data.get("attivita", {}).items():
        st.session_state[f"ana_att_{k}"] = float(v or 0.0)
    for k, v in data.get("passivita", {}).items():
        st.session_state[f"ana_pas_{k}"] = float(v or 0.0)

    # C) Reddito e spese
    st.session_state["ana_reddito_mensile"] = float(data.get("reddito_mensile", 0.0) or 0.0)
    st.session_state["ana_spese_mensili"] = float(data.get("spese_mensili", 0.0) or 0.0)
    st.session_state["ana_fonti_reddito"] = list(data.get("fonti_reddito", []))

    # D) Conoscenza investimenti
    st.session_state["ana_knowledge"] = dict(data.get("knowledge", {}))

    # E) Tolleranza al rischio
    st.session_state["ana_segmento"] = data.get("segmento", "")
    st.session_state["ana_classe_rischio"] = data.get("classe_rischio", "")

def _knowledge_cb(key_prefix: str, product: str, chosen_j: int, n_levels: int):
    """
    Callback: quando l'utente spunta una checkbox in una riga, disattiva le altre della stessa riga.
    """
    chosen_key = f"{key_prefix}__{product}__{chosen_j}"
    if bool(st.session_state.get(chosen_key, False)):
        for j in range(n_levels):
            k = f"{key_prefix}__{product}__{j}"
            if j != chosen_j:
                st.session_state[k] = False

def _seed_knowledge_checkboxes(products: list[str], levels: list[str], knowledge: dict, key_prefix: str):
    """
    Imposta lo stato delle checkbox *prima* che i widget vengano creati.
    Necessario per evitare StreamlitAPIException (modifica session_state dopo instanziazione widget).
    """
    # IMPORTANT: non sovrascrivere lo stato dei widget ad ogni rerun.
    # In Streamlit, se si riassegna session_state per chiavi di widget ad ogni esecuzione,
    # l'interazione dell'utente viene annullata (effetto "non resta flaggato").
    # Quindi inizializziamo solo quando la configurazione (knowledge) cambia oppure
    # quando la key non è ancora presente.
    for p in products:
        sel = knowledge.get(p, None)
        for j, lev in enumerate(levels):
            k = f"{key_prefix}__{p}__{j}"
            if k not in st.session_state:
                st.session_state[k] = (sel == lev)

def _render_knowledge_grid(products: list[str], levels: list[str], key_prefix: str = "ana_k"):
    n_levels = len(levels)

    weights = [3] + [2] * n_levels

    # Header
    hdr = st.columns(weights, gap="small")
    with hdr[0]:
        st.caption("Prodotto")
    for j, lev in enumerate(levels):
        with hdr[j + 1]:
            st.caption(lev)

    # Righe
    for p in products:
        row = st.columns(weights, gap="small")
        with row[0]:
            st.markdown(f"**{p}**")

        for j in range(n_levels):
            cb_key = f"{key_prefix}__{p}__{j}"
            with row[j + 1]:
                st.checkbox(
                    label="",
                    key=cb_key,
                    label_visibility="collapsed",
                    on_change=_knowledge_cb,
                    args=(key_prefix, p, j, n_levels),
                )

        # Aggiorno lo stato "ana_knowledge" in modo coerente con i flag della riga
        selected_j = None
        for j in range(n_levels):
            if st.session_state.get(f"{key_prefix}__{p}__{j}", False):
                selected_j = j
                break

        if "ana_knowledge" not in st.session_state or not isinstance(st.session_state["ana_knowledge"], dict):
            st.session_state["ana_knowledge"] = {}

        if selected_j is None:
            st.session_state["ana_knowledge"].pop(p, None)
        else:
            st.session_state["ana_knowledge"][p] = levels[selected_j]

def render_anagrafica():
    ensure_anagrafica_storage()

    st.markdown(
        '<div class="uw-card"><h2>Anagrafica</h2>'
        '<p>Crea e gestisci le anagrafiche clienti. È possibile creare una nuova anagrafica, modificarne una preesistente oppure cancellarla.</p></div>',
        unsafe_allow_html=True
    )

    mode = st.radio(
        "Operazione",
        ["Crea Anagrafica nuovo Cliente", "Modifica una Anagrafica"],
        horizontal=True,
        key="ana_mode",
    )

    name_key = ""

    if mode == "Crea Anagrafica nuovo Cliente":
        name_key = st.text_input(
            "Nome Anagrafica (identificativo)",
            value=st.session_state.get("ana_name_key", ""),
            key="ana_name_key"
        ).strip()
    else:
        existing = sorted(list(st.session_state["anagrafiche"].keys()))
        if len(existing) == 0:
            st.info("Non esistono ancora anagrafiche salvate. Crei una nuova anagrafica per iniziare.")
            name_key = st.text_input(
                "Nome Anagrafica (identificativo)",
                value=st.session_state.get("ana_name_key", ""),
                key="ana_name_key"
            ).strip()
            mode = "Crea Anagrafica nuovo Cliente"
        else:
            # elenco con Nome, Cognome, # portafogli
            rows = []
            for k in existing:
                payload = st.session_state["anagrafiche"][k]
                d = payload.get("data", {})
                nome_ = d.get("nome", "")
                cognome_ = d.get("cognome", "")
                n_port = len(st.session_state["client_portfolios"].get(k, []))
                rows.append({"Anagrafica": k, "Nome": nome_, "Cognome": cognome_, "Portafogli": n_port})
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

            selected = st.selectbox("Selezioni Anagrafica", existing, key="ana_existing_select")
            name_key = selected

            c1, c2 = st.columns([0.2, 0.2], gap="small")
            with c1:
                if st.button("Carica", key="ana_load_btn"):
                    load_anagrafica_to_state(st.session_state["anagrafiche"][selected])
                    st.success("Anagrafica caricata. Può modificarla e poi salvare.")
            with c2:
                if st.button("Cancella", key="ana_delete_btn"):
                    st.session_state["anagrafiche"].pop(selected, None)
                    st.session_state["client_portfolios"].pop(selected, None)
                    st.success(f'Anagrafica "{selected}" eliminata correttamente.')
                    persist_anagrafiche_from_session()
                    st.rerun()

    # --- A) Dati Anagrafici ---
    st.markdown(
        '<div class="uw-card"><h2>A) Dati Anagrafici</h2>'
        '<p>Inserisca le informazioni principali del cliente.</p></div>',
        unsafe_allow_html=True
    )
    cA1, cA2 = st.columns([0.5, 0.5], gap="small")
    with cA1:
        nome = st.text_input("Nome", value=st.session_state.get("ana_nome", ""), key="ana_nome")
    with cA2:
        cognome = st.text_input("Cognome", value=st.session_state.get("ana_cognome", ""), key="ana_cognome")

    indirizzo = st.text_input("Indirizzo di Residenza", value=st.session_state.get("ana_indirizzo", ""), key="ana_indirizzo")
    prof_opts = ["Lavoratore dipendente","Lavoratore autonomo", "Professionista", "Commerciante", "Pensionato", "Altro"]
    prof_default = st.session_state.get("ana_professione", "Altro")
    professione = st.selectbox(
        "Professione",
        prof_opts,
        index=prof_opts.index(prof_default) if prof_default in prof_opts else len(prof_opts) - 1,
        key="ana_professione"
    )

    # --- B) Bilancio ---
    st.markdown(
        '<div class="uw-card"><h2>B) Bilancio</h2>'
        '<p>Indichi Attività e Passività (in €). In basso: somma Attivi, somma Passivi, Posizione Netta e una sintesi grafica.</p></div>',
        unsafe_allow_html=True
    )
    
    att_keys = ["Liquidità", "Obbligazioni", "Azioni", "Prodotti Assicurativi", "Immobili", "Commodities", "Criptovalute", "Beni di Lusso", "Altro"]
    pas_keys = ["Carte di Credito", "Linee di Credito", "Mutui", "Altri Prestiti", "Altre Passività"]
    
    col_att, col_pas = st.columns(2, gap="large")
    
    with col_att:
        st.markdown('<div class="uw-sec-title-sm">Attività</div>', unsafe_allow_html=True)
        att_vals = {}
        for k in att_keys:
            att_vals[k] = st.number_input(
                f"{k} (€)",
                min_value=0.0,
                value=float(st.session_state.get(f"ana_att_{k}", 0.0)),
                step=1000.0,
                key=f"ana_att_{k}"
            )
    
    with col_pas:
        st.markdown('<div class="uw-sec-title-sm">Passività</div>', unsafe_allow_html=True)
        pas_vals = {}
        for k in pas_keys:
            pas_vals[k] = st.number_input(
                f"{k} (€)",
                min_value=0.0,
                value=float(st.session_state.get(f"ana_pas_{k}", 0.0)),
                step=1000.0,
                key=f"ana_pas_{k}"
            )
    
    tot_att = float(sum(att_vals.values()))
    tot_pas = float(sum(pas_vals.values()))
    net_pos = tot_att - tot_pas
    
    cB1, cB2, cB3 = st.columns(3)
    cB1.metric("Somma Attività (€)", f"{tot_att:,.0f}".replace(",", "."))
    cB2.metric("Somma Passività (€)", f"{tot_pas:,.0f}".replace(",", "."))
    cB3.metric("Posizione Netta (€)", f"{net_pos:,.0f}".replace(",", "."))
    
    
    # --- Sintesi grafica Attivo–Passivo (colonne in pila) ---
    st.markdown(
        '<div class="uw-card"><h3 class="uw-h3-sm">Struttura Attivo–Passivo</h3>'
        '<p>Due colonne in pila: una per l’Attivo e una per il Passivo. Ogni segmento rappresenta una voce.</p></div>',
        unsafe_allow_html=True
    )

    # Prepara dati (solo voci > 0 per evitare legende inutili)
    att_items = [(k, float(att_vals.get(k, 0.0))) for k in att_keys if float(att_vals.get(k, 0.0)) > 0]
    pas_items = [(k, float(pas_vals.get(k, 0.0))) for k in pas_keys if float(pas_vals.get(k, 0.0)) > 0]

    fig_ap = go.Figure()

    # Tracce Attivo (x="Attivo")
    for k, v in att_items:
        fig_ap.add_trace(
            go.Bar(
                name=f"Attivo: {k}",
                x=["Attivo", "Passivo"],
                y=[v, 0.0],
                hovertemplate="<b>%{fullData.name}</b><br>Valore: %{y:,.0f} €<extra></extra>",
            )
        )

    # Tracce Passivo (x="Passivo")
    for k, v in pas_items:
        fig_ap.add_trace(
            go.Bar(
                name=f"Passivo: {k}",
                x=["Attivo", "Passivo"],
                y=[0.0, v],
                hovertemplate="<b>%{fullData.name}</b><br>Valore: %{y:,.0f} €<extra></extra>",
            )
        )

    fig_ap.update_layout(
        barmode="stack",
        height=430,
        margin=dict(l=10, r=10, t=20, b=10),
        xaxis=dict(title="", tickfont=dict(size=12)),
        yaxis=dict(title="€", tickformat=",.0f"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
    )

    # Annotazioni Totali (in cima alle colonne)
    fig_ap.add_annotation(
        x="Attivo",
        y=tot_att,
        text=f"Totale Attivo: {tot_att:,.0f} €".replace(",", "."),
        showarrow=False,
        yshift=12,
        font=dict(size=12),
    )
    fig_ap.add_annotation(
        x="Passivo",
        y=tot_pas,
        text=f"Totale Passivo: {tot_pas:,.0f} €".replace(",", "."),
        showarrow=False,
        yshift=12,
        font=dict(size=12),
    )

    st.plotly_chart(fig_ap, use_container_width=True, config={"displayModeBar": False})
    # --- C) Reddito e Spese ---
    st.markdown(
        '<div class="uw-card"><h2>C) Reddito e Spese</h2>'
        '<p>Inserisca reddito netto mensile, spese mensili e fonti del reddito. In basso: Risparmio Mensile.</p></div>',
        unsafe_allow_html=True
    )
    cC1, cC2 = st.columns(2, gap="small")
    with cC1:
        reddito_m = st.number_input(
            "Reddito Netto Mensile (€)",
            value=float(st.session_state.get("ana_reddito_mensile", 0.0)),
            step=100.0,
            key="ana_reddito_mensile"
        )
    with cC2:
        spese_m = st.number_input(
            "Spese Mensili (€)",
            value=float(st.session_state.get("ana_spese_mensili", 0.0)),
            step=100.0,
            key="ana_spese_mensili"
        )

    fonti_opts = ["Salario", "Pensione", "Investimenti", "Commerciale", "Altro"]
    fonti = st.multiselect("Fonti del reddito", fonti_opts, default=st.session_state.get("ana_fonti_reddito", []), key="ana_fonti_reddito")
    risparmio = reddito_m - spese_m
    st.metric("Risparmio Mensile (€)", f"{risparmio:,.0f}".replace(",", "."))

    # --- D) Conoscenza degli investimenti ---
    st.markdown(
        '<div class="uw-card"><h2>D) Conoscenza degli investimenti</h2>'
        '<p>Per ciascun prodotto selezioni il livello corretto (una sola risposta per riga).</p></div>',
        unsafe_allow_html=True
    )

    products = [
        "Obbligazioni", "Azioni", "Fondi Comuni di Investimento", "ETF", "Prodotti Assicurativi",
        "Commodities", "Criptovalute", "Derivati", "Private Equity", "Fondi Immobiliari",
        "Altri Investimenti Illiquidi"
    ]
    levels = [
        "Nessuna Conoscenza",
        "Conoscenza senza Esperienza",
        "Conoscenza con Esperienza ≤ 15 transazioni (ultimi 3 anni)",
        "Conoscenza con Esperienza > 15 transazioni (ultimi 3 anni)",
        "Elevata Conoscenza ed Esperienza (ultimi 5 anni)",
    ]

    knowledge = st.session_state.get("ana_knowledge", {})
    if not isinstance(knowledge, dict):
        knowledge = {}

    # Se l'anagrafica viene caricata/modificata, la knowledge può cambiare.
    # In quel caso dobbiamo riallineare le checkbox ai nuovi valori.
    sig = tuple(sorted((str(k), str(v)) for k, v in knowledge.items()))
    prev_sig = st.session_state.get("_ana_k_sig", None)
    if prev_sig != sig:
        # rimuovo eventuali chiavi precedenti per evitare stati incoerenti
        for p in products:
            for j in range(len(levels)):
                st.session_state.pop(f"ana_k__{p}__{j}", None)
        st.session_state["_ana_k_sig"] = sig

    _seed_knowledge_checkboxes(products, levels, knowledge, key_prefix="ana_k")
    _render_knowledge_grid(products, levels, key_prefix="ana_k")

    # --- Radar: sintesi della conoscenza per prodotto ---
    try:
        _level_to_score = {lev: i + 1 for i, lev in enumerate(levels)}
        _scores = []
        _selected_levels = {}

        for _p in products:
            _sel = None
            for _j, _lev in enumerate(levels):
                if st.session_state.get(f"ana_k__{_p}__{_j}", False):
                    _sel = _lev
                    break
            _selected_levels[_p] = _sel
            _scores.append(_level_to_score.get(_sel, 0))

        _missing = sum(1 for v in _selected_levels.values() if v is None)
        if _missing > 0:
            st.info("Radar: alcune voci non hanno ancora un livello selezionato; vengono mostrate a 0.", icon="ℹ️")

        _theta = products + [products[0]]
        _r = _scores + [_scores[0]]

        _fig_radar = go.Figure()
        _fig_radar.add_trace(
            go.Scatterpolar(
                r=_r,
                theta=_theta,
                mode="lines+markers",
                fill="toself",
                name="Conoscenza",
                line=dict(width=3),
                marker=dict(size=6),
                opacity=0.9,
            )
        )
        _fig_radar.update_layout(
            title=dict(text="Sintesi grafica della conoscenza per prodotto", x=0.0, xanchor="left"),
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 5],
                    tickmode="array",
                    tickvals=[1, 2, 3, 4, 5],
                    ticktext=["1", "2", "3", "4", "5"],
                ),
                angularaxis=dict(direction="clockwise"),
            ),
            showlegend=False,
            margin=dict(l=10, r=10, t=60, b=10),
            height=420,
        )
        st.plotly_chart(_fig_radar, use_container_width=True, config={"displayModeBar": False})
    except Exception as _radar_exc:
        st.warning(f"Impossibile generare il radar: {_radar_exc}")


    # --- E) Tolleranza al Rischio ---
    st.markdown(
        '<div class="uw-card"><h2>E) Tolleranza al Rischio</h2>'
        '<p>Selezioni il Segmento di Clientela e poi la classe di rischio corrispondente.</p></div>',
        unsafe_allow_html=True
    )

    segmenti = sorted(list(st.session_state.get("client_classes", {}).keys()))
    if len(segmenti) == 0:
        st.warning("Nessun Segmento di Clientela disponibile. Crearlo prima in Tools → Griglie Clientela.")
        segmento_sel = ""
        classe_rischio = ""
    else:
        segmento_default = st.session_state.get("ana_segmento", segmenti[0])
        segmento_sel = st.selectbox(
            "Segmento di Clientela",
            segmenti,
            index=segmenti.index(segmento_default) if segmento_default in segmenti else 0,
            key="ana_segmento"
        )

        payload_seg = st.session_state["client_classes"].get(segmento_sel, {})
        risk_names = payload_seg.get("risk_names", [])
        if len(risk_names) == 0:
            st.warning("Il segmento selezionato non contiene classi di rischio.")
            classe_rischio = ""
        else:
            cr_default = st.session_state.get("ana_classe_rischio", risk_names[0])
            classe_rischio = st.radio(
                "Qual è la classe di rischio?",
                risk_names,
                horizontal=True,
                index=risk_names.index(cr_default) if cr_default in risk_names else 0,
                key="ana_classe_rischio"
            )

    # --- Salva ---
    st.markdown(
        '<div class="uw-card"><h2>Salva Anagrafica</h2>'
        '<p>Salva l’anagrafica anche se non è compilata completamente.</p></div>',
        unsafe_allow_html=True
    )

    if st.button("Salva", type="primary", key="ana_save_btn"):
        if name_key.strip() == "":
            st.error("Inserire un Nome per l’Anagrafica prima di salvare.")
        else:
            data = {
                "nome": nome,
                "cognome": cognome,
                "indirizzo": indirizzo,
                "professione": professione,
                "attivita": att_vals,
                "passivita": pas_vals,
                "reddito_mensile": reddito_m,
                "spese_mensili": spese_m,
                "fonti_reddito": fonti,
                "knowledge": st.session_state.get("ana_knowledge", {}),
                "segmento": segmento_sel,
                "classe_rischio": classe_rischio,
            }
            st.session_state["anagrafiche"][name_key.strip()] = _anagrafica_payload(name_key.strip(), data)
            st.success(f'Anagrafica "{name_key.strip()}" salvata correttamente.')
            persist_anagrafiche_from_session()
st.markdown(CSS, unsafe_allow_html=True)
render_navbar()
ensure_storage()
load_persisted_anagrafiche_into_session()
load_persisted_asset_selections_into_session()
load_persisted_portfolios_into_session()


# =======================
# Sezione → Monitoraggio Portafoglio
# =======================
def render_monitoraggio_portafoglio():
    """
    Sezione dedicata al monitoraggio del portafoglio (placeholder UI).
    Nota: in questa fase non vengono introdotti calcoli nuovi; solo struttura di pagina.
    """
    st.markdown(
        '<div class="uw-card"><h2>Monitoraggio Portafoglio</h2>'
        "<p>Sezione predisposta per le funzionalità di monitoraggio (andamento, scostamenti, alert e reportistica). "
        "Contenuti in sviluppo.</p></div>",
        unsafe_allow_html=True,
    )

# =======================

def render_crea_portafoglio():
    ensure_anagrafica_storage()
    ensure_portfolio_storage()
    ensure_asset_selection_storage()
    ensure_market_database_storage()  # necessario per backtesting/MC anche dopo navigazione via link

    st.markdown(
        '<div class="uw-card"><h2>Crea Soluzione di Investimento</h2>'
        '<p>Creazione di un nuovo portafoglio o modifica di portafogli esistenti.</p></div>',
        unsafe_allow_html=True
    )

    sub = st.radio(
        "Sotto-sezione",
        ["Nuovo Portafoglio", "Modifica Portafoglio"],
        horizontal=True,
        key="pf_subsection"
    )

    if sub == "Modifica Portafoglio":
        pf = st.session_state.get("portfolios", {})
        if not pf:
            st.info("Nessun portafoglio creato finora.")
            return
        rows = []
        for pid, payload in pf.items():
            rows.append({
                "ID": pid,
                "Cliente": payload.get("client_key", ""),
                "Nome Portafoglio": payload.get("portfolio_name", ""),
                "Obiettivo": payload.get("objective", ""),
                "Creato il": payload.get("created_at", ""),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
        return

    # -----------------------
    # Nuovo Portafoglio
    # -----------------------
    anags = st.session_state.get("anagrafiche", {})
    if not anags:
        st.warning("Devi creare l’Anagrafica Cliente prima di procedere.")
        return

    # elenco clienti (nome+cognome) con chiave
    client_keys = list(anags.keys())
    labels = []
    for k in client_keys:
        d = anags[k].get("data", {})
        labels.append(f'{d.get("nome","").strip()} {d.get("cognome","").strip()}  —  ({k})')

    sel_label = st.selectbox("Seleziona Cliente / Investitore", labels, key="pf_client_sel")
    client_key = client_keys[labels.index(sel_label)]
    client_data = anags[client_key].get("data", {})

    st.markdown('<div class="uw-card"><h2>Impostazioni Portafoglio</h2></div>', unsafe_allow_html=True)
    portfolio_name = st.text_input("Nome del Portafoglio", value="", key="pf_name").strip()

    objective = "Massimizzazione del Rendimento Atteso dato un livello di rischio tollerato"

    # Parametri investimento
    c1, c2 = st.columns([0.4, 0.6], gap="small")
    with c1:
        horizon_years = st.number_input("Orizzonte temporale (anni)", min_value=1, max_value=100, value=10, step=1, key="pf_horizon")
        initial_amount = st.number_input("Conferimento iniziale (€)", min_value=0.0, value=0.0, step=1000.0, key="pf_initial")
    with c2:
        periodic_amount = st.number_input("Versamento periodico (€)", min_value=0.0, value=0.0, step=100.0, key="pf_periodic_amt")
        freq = st.selectbox("Frequenza versamento", ["Mensile", "Trimestrale", "Semestrale", "Annuale"], key="pf_freq")
        max_years = int(horizon_years)
        periodic_years = st.number_input("Anni di versamenti periodici", min_value=0, max_value=max_years, value=min(5, max_years), step=1, key="pf_periodic_years")

    
    # Grafico conferimenti (t=0 solo conferimento iniziale; rate periodiche dal periodo successivo)
    mult = {"Mensile": 12, "Trimestrale": 4, "Semestrale": 2, "Annuale": 1}[freq]
    horizon_years_int = int(horizon_years)
    periodic_years_int = int(periodic_years)

    if freq == "Annuale":
        # t=0: solo iniziale; poi anni 1..N: versamenti annuali fino a periodic_years
        labels = ["t=0"] + [f"Anno {y}" for y in range(1, horizon_years_int + 1)]
        amounts = [float(initial_amount)] + [
            float(periodic_amount) if y <= periodic_years_int else 0.0
            for y in range(1, horizon_years_int + 1)
        ]
    else:
        # frequenze infra-annuali: mostro ogni singola rata
        total_periods = horizon_years_int * mult
        periodic_periods = periodic_years_int * mult

        # label compatte Y{anno}-P{periodo}
        labels = ["t=0"]
        amounts = [float(initial_amount)]
        for p in range(1, total_periods + 1):
            year = (p - 1) // mult + 1
            within = (p - 1) % mult + 1
            labels.append(f"Y{year}-P{within}")
            amounts.append(float(periodic_amount) if p <= periodic_periods else 0.0)

    contrib_df = pd.DataFrame({"Periodo": labels, "Conferimenti (€)": amounts})
    fig_contrib = px.bar(contrib_df, x="Periodo", y="Conferimenti (€)")
    fig_contrib.update_traces(marker_color="rgba(120, 200, 120, 0.8)")
    fig_contrib.update_layout(
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis_title="",
        yaxis_title="€"
    )
    st.plotly_chart(fig_contrib, use_container_width=True)

    # -----------------------
    # Griglia consigli Azionario+Opportunità da Segmento + Classe rischio
    # -----------------------
    segmento = client_data.get("segmento", "")
    classe_rischio = client_data.get("classe_rischio", "")

    if not segmento or segmento not in st.session_state.get("client_classes", {}):
        st.warning("Per questo cliente non è stato selezionato un Segmento di Clientela valido (Tools → Griglie Clientela).")
        return

    seg_payload = st.session_state["client_classes"][segmento]
    df_weights = seg_payload.get("weights_df", None)
    horizons = seg_payload.get("horizons", [])
    risk_names = seg_payload.get("risk_names", [])

    if df_weights is None or df_weights.empty:
        st.warning("Il Segmento selezionato non contiene una griglia pesi valida.")
        return

    # costruisco labels coerenti
    def _row_label(hn, y0, y1):
        base = hn.strip() if str(hn).strip() else "Orizzonte"
        if y1 is None:
            return f"{base} (> {int(y0)}y)"
        return f"{base} ({int(y0)}-{int(y1)}y)"

    row_labels = [_row_label(hn, y0, y1) for (hn, y0, y1) in horizons]
    col_labels = [rn.strip() if str(rn).strip() else f"Classe {j+1}" for j, rn in enumerate(risk_names)]

    # riallineo df a labels (difensivo)
    df = df_weights.copy()
    df.index = row_labels[: len(df.index)]
    df.columns = col_labels[: len(df.columns)]

    # identifico riga orizzonte
    y = int(horizon_years)
    chosen_row = None
    for (hn, y0, y1) in horizons:
        if y1 is None:
            if y > int(y0):
                chosen_row = _row_label(hn, y0, y1)
        else:
            if int(y0) <= y <= int(y1):
                chosen_row = _row_label(hn, y0, y1)
                break
    if chosen_row is None and row_labels:
        chosen_row = row_labels[-1]

    chosen_col = classe_rischio if classe_rischio in df.columns else (df.columns[0] if len(df.columns) else None)

    try:
        recommended = float(df.loc[chosen_row, chosen_col])
    except Exception:
        recommended = 0.0

    st.markdown(
        f'<div class="uw-card"><h2>Azionario + Opportunità consigliato</h2>'
        f'<p>Cliente: <b>{client_data.get("nome","")} {client_data.get("cognome","")}</b> · '
        f'Segmento: <b>{segmento}</b> · Classe rischio: <b>{classe_rischio}</b> · Orizzonte: <b>{y} anni</b></p></div>',
        unsafe_allow_html=True
    )

    st.markdown(build_grid_highlight_html(df, chosen_row, chosen_col), unsafe_allow_html=True)

    
    # Valori selezionabili: solo pesi Azionario+Alternativo dei portafogli del Set associato alla Griglia
    selected_set_name = seg_payload.get("selected_set", None)
    eq_options = None
    eq_to_portfolios = {}

    if selected_set_name and selected_set_name in st.session_state.get("asset_selections", {}):
        _as_payload = st.session_state["asset_selections"][selected_set_name]
        _assets_df = _as_payload.get("assets_df", pd.DataFrame(columns=["Asset Class", "Macro-Asset Class"]))
        _alloc_df = _as_payload.get("alloc_df", None)

        if _alloc_df is not None and isinstance(_alloc_df, pd.DataFrame) and not _alloc_df.empty:
            try:
                _macro_map = dict(zip(
                    _assets_df["Asset Class"].astype(str),
                    _assets_df["Macro-Asset Class"].astype(str)
                ))
            except Exception:
                _macro_map = {}

            _risky_cols = [a for a, m in _macro_map.items() if str(m).strip() in {"Azionario", "Alternativo"} and a in _alloc_df.columns.astype(str).tolist()]
            if len(_risky_cols) > 0:
                _agg = (_alloc_df.loc[:, _risky_cols].sum(axis=1).astype(float) * 100.0).round(0).astype(int)
                eq_options = sorted(pd.Series(_agg).unique().tolist())
                # mappa peso -> lista portafogli
                for pf_name, v in _agg.items():
                    eq_to_portfolios.setdefault(int(v), []).append(str(pf_name))
    if not eq_options:
        # fallback: mantengo slider classico se manca il collegamento Set↔Griglia
        eq_w = st.slider(
            "Peso Azionario + Opportunità (%)",
            min_value=0,
            max_value=100,
            value=int(round(recommended)),
            step=1,
            key="pf_eq_slider",
        )
    else:
        # snap del valore consigliato all'opzione più vicina
        rec_int = int(round(recommended))
        nearest = min(eq_options, key=lambda x: abs(int(x) - rec_int))
        eq_w = st.select_slider(
            "Peso Azionario + Opportunità (%)",
            options=eq_options,
            value=nearest,
            key="pf_eq_select_slider"
        )

    
    # -----------------------
    # Selezione Asset Class (dal Set associato alla Griglia)
    # -----------------------
    selections = sorted(list(st.session_state.get("asset_selections", {}).keys()))
    if not selections:
        st.warning("Devi creare un Set di Asset Allocation (Tools → Portafogli in Asset Class) prima di procedere.")
        return

    # Set coerente con la Griglia selezionata (se disponibile)
    sel_as = selected_set_name if (selected_set_name in selections) else st.selectbox(
        "Set di Asset Allocation da utilizzare",
        selections,
        key="pf_asset_sel_fallback"
    )

    as_payload = st.session_state["asset_selections"][sel_as]
    assets_df = as_payload.get("assets_df", pd.DataFrame(columns=["Asset Class", "Macro-Asset Class"]))
    alloc_df = as_payload.get("alloc_df", None)

    if alloc_df is None or (isinstance(alloc_df, pd.DataFrame) and alloc_df.empty):
        st.warning("Il Set selezionato non contiene ancora composizioni (foglio 'Portafogli').")
        return

    # Calcolo peso aggregato Azionario + Alternativo per mappare eq_w → portafoglio del Set
    try:
        macro_map = dict(zip(
            assets_df["Asset Class"].astype(str),
            assets_df["Macro-Asset Class"].astype(str)
        ))
    except Exception:
        macro_map = {}

    risky_cols = [a for a, m in macro_map.items() if str(m).strip() in {"Azionario", "Alternativo"} and a in alloc_df.columns.astype(str).tolist()]
    if len(risky_cols) == 0:
        st.warning('Nel Set selezionato non risultano Asset Class con Macro-Asset Class "Azionario" o "Alternativo".')
        return

    agg = (alloc_df.loc[:, risky_cols].sum(axis=1).astype(float) * 100.0).round(0).astype(int)

    # Portafogli che matchano eq_w (o opzione più vicina)
    target = int(eq_w)
    if target not in agg.values:
        # fallback: prendo il più vicino
        target = int(min(agg.unique().tolist(), key=lambda x: abs(int(x) - int(eq_w))))

    candidate_names = agg[agg == target].index.astype(str).tolist()
    if len(candidate_names) == 0:
        st.warning("Non è stato possibile individuare un portafoglio coerente con il livello selezionato.")
        return
    if len(candidate_names) == 1:
        chosen_pf = candidate_names[0]
    else:
        chosen_pf = st.selectbox(
            "Portafoglio del Set (stesso peso Azionario+Alternativo)",
            candidate_names,
            key="pf_chosen_portfolio_same_weight"
        )

    # Pesi del portafoglio selezionato (non creato ex-novo)
    row = alloc_df.loc[chosen_pf].copy()
    # Normalizzo eventuali percentuali
    s = pd.to_numeric(row, errors="coerce").fillna(0.0).astype(float)
    if s.max() > 1.0001:
        s = s / 100.0

    # tengo solo pesi > 0
    s = s[s > 0].copy()
    if s.sum() <= 0:
        st.warning("Il portafoglio selezionato non contiene pesi positivi.")
        return

    # normalizzo a somma 1 (robustezza)
    s = s / s.sum()

    w = s.to_dict()

    # Dataframe per il grafico a torta (sempre definito)
    pie_df = pd.DataFrame({"Asset Class": list(w.keys()), "Peso": list(w.values())})
    fig_pie = px.pie(pie_df, names="Asset Class", values="Peso")
    fig_pie.update_traces(textposition="inside", textinfo="percent+label")
    fig_pie.update_layout(margin=dict(l=10, r=10, t=20, b=10))

    # --- Calcolo Rendimento atteso / Rischio del portafoglio selezionato ---
    sel_mu = None
    sel_sigma = None

    exp_ret_sel = as_payload.get("exp_ret", None)
    vol_sel = as_payload.get("vol", None)
    corr_sel = as_payload.get("corr", None)

    if exp_ret_sel is not None and vol_sel is not None and corr_sel is not None:
        try:
            asset_names_sel = assets_df["Asset Class"].tolist()
            mu = np.asarray(pd.Series(exp_ret_sel, index=asset_names_sel).astype(float).values)
            sig = np.asarray(pd.Series(vol_sel, index=asset_names_sel).astype(float).values)
            rho = np.asarray(pd.DataFrame(corr_sel, index=asset_names_sel, columns=asset_names_sel).astype(float).values)
            cov = np.outer(sig, sig) * rho

            w_vec = np.asarray([w.get(a, 0.0) for a in asset_names_sel], dtype=float)
            sel_mu = float(w_vec @ mu)
            sel_var = float(w_vec.T @ cov @ w_vec)
            sel_sigma = float(np.sqrt(max(sel_var, 0.0)))
        except Exception:
            sel_mu = None
            sel_sigma = None

    # Layout: Torta a sinistra, scatter a destra
    c_left, c_right = st.columns([0.52, 0.48], gap="large")

    with c_left:
        st.plotly_chart(fig_pie, use_container_width=True)
        if sel_mu is not None and sel_sigma is not None:
            m1, m2 = st.columns(2, gap="small")
            m1.markdown(
                f'<div class="uw-metric-sm"><div class="uw-metric-label">Rendimento Atteso Annuo</div><div class="uw-metric-value-xs">{sel_mu:.2%}</div></div>',
                unsafe_allow_html=True
            )
            m2.markdown(
                f'<div class="uw-metric-sm"><div class="uw-metric-label">Deviazione Standard Annua</div><div class="uw-metric-value-xs">{sel_sigma:.2%}</div></div>',
                unsafe_allow_html=True
            )
        else:
            st.info("Per calcolare rendimento e rischio del portafoglio selezionato, caricare in Tools → Portafogli in Asset Class gli input (rendimenti, volatilità, correlazioni) e salvare la selezione.")

    with c_right:
        alloc_df = as_payload.get("alloc_df", None)
        if alloc_df is None:
            st.info("Per visualizzare le combinazioni rischio-rendimento di tutte le asset allocation, caricare e salvare in Tools → Portafogli in Asset Class il file “Asset Allocation”.")
        elif sel_mu is None or sel_sigma is None:
            st.info("Per visualizzare la frontiera rischio-rendimento, oltre all’Asset Allocation occorrono rendimenti attesi, volatilità e correlazioni (Tools → Portafogli in Asset Class).")
        else:
            try:
                # Allineamento colonne allocazioni alle asset class correnti
                asset_names_sel = assets_df["Asset Class"].tolist()
                alloc = alloc_df.copy()
                alloc = alloc.loc[:, asset_names_sel]

                W = alloc.values.astype(float)
                port_ret = W @ mu
                port_var = np.einsum("ij,jk,ik->i", W, cov, W)
                port_risk = np.sqrt(np.maximum(port_var, 0.0))

                cloud = pd.DataFrame({
                    "Portafoglio": alloc.index.astype(str),
                    "Rischio (σ annuo)": port_risk,
                    "Rendimento atteso annuo": port_ret,
                    "Tipo": "Allocazioni disponibili",
                    "Size": 3,
                })

                sel_point = pd.DataFrame({
                    "Portafoglio": ["Selezionato"],
                    "Rischio (σ annuo)": [sel_sigma],
                    "Rendimento atteso annuo": [sel_mu],
                    "Tipo": ["Portafoglio selezionato"],
                    "Size": [16],
                })

                plot_pf = pd.concat([cloud, sel_point], ignore_index=True)

                fig_pf = px.scatter(
                    plot_pf,
                    x="Rischio (σ annuo)",
                    y="Rendimento atteso annuo",
                    color="Tipo",
                    size="Size",
                    size_max=12,
                    hover_name="Portafoglio",
                    hover_data={"Size": False, "Tipo": False},
                )
                fig_pf.update_layout(
                    title="Rischio vs Rendimento atteso (asset allocation selezionabili)",
                    margin=dict(l=10, r=10, t=40, b=10),
                    xaxis_tickformat=".0%",
                    yaxis_tickformat=".0%",
                    legend_title_text="",
                )
                # Punto selezionato più evidente
                fig_pf.update_traces(marker=dict(opacity=0.9), selector=dict(mode="markers"))
                fig_pf.update_traces(
                    hovertemplate=(
                        "<b>%{hovertext}</b><br>"
                        "Rischio: %{x:.2%}<br>"
                        "Rendimento atteso: %{y:.2%}"
                        "<extra></extra>"
                    )
                )
                st.plotly_chart(fig_pf, use_container_width=True)
            except Exception as e:
                st.error(f"Impossibile calcolare/mostrare il grafico rischio-rendimento: {e}")

    # -----------------------
    # Life Cycle (derisking) + Simulazione Monte Carlo
    # -----------------------
    st.markdown(
        '<div class="uw-card"><h2>Life Cycle</h2>'
        '<p>Definisca se applicare una logica di <b>derisking progressivo</b> verso la Asset Class a minima volatilità. '
        'In ogni caso, in basso viene mostrata l’evoluzione della composizione nel tempo e (opzionale) una simulazione Monte Carlo.</p></div>',
        unsafe_allow_html=True
    )

    # Costruzione vettori base (pesi su tutte le asset class del Set)
    asset_names_sel = assets_df["Asset Class"].astype(str).tolist()
    base_w_vec = np.asarray([w.get(a, 0.0) for a in asset_names_sel], dtype=float)
    if base_w_vec.sum() <= 0:
        st.warning("Impossibile costruire la composizione del portafoglio (somma pesi nulla).")
        return
    base_w_vec = base_w_vec / base_w_vec.sum()

    # Identifico l'asset a minima volatilità (necessario per Life Cycle = Sì)
    min_risk_asset = None
    min_risk_vec = None
    if vol_sel is not None:
        try:
            vol_series = pd.Series(vol_sel, index=asset_names_sel).astype(float)
            min_risk_asset = str(vol_series.idxmin())
            min_risk_vec = np.zeros(len(asset_names_sel), dtype=float)
            min_risk_vec[asset_names_sel.index(min_risk_asset)] = 1.0
        except Exception:
            min_risk_asset = None
            min_risk_vec = None

    lc_choice = st.radio("Vuoi implementare una logica Life Cycle?", ["No", "Sì"], horizontal=True, key="lc_choice")

    # Parametro derisking (anni prima della fine)
    derisk_years = None
    if lc_choice == "Sì":
        if min_risk_asset is None or min_risk_vec is None:
            st.error("Per applicare il Life Cycle servono le volatilità annue delle asset class (Tools → Portafogli in Asset Class).")
            st.stop()

        max_dy = min(10, max(1, horizon_years_int - 1))
        default_dy = 5 if horizon_years_int > 5 else 1
        default_dy = min(default_dy, max_dy)

        derisk_years = st.number_input(
            "Quanti anni prima della fine dell'investimento vuoi iniziare il derisking?",
            min_value=1, max_value=max_dy, value=int(default_dy), step=1, key="lc_derisk_years"
        )

    # Costruzione traiettoria pesi per anno (0..H-1)
    H = int(horizon_years_int)
    year_weights = np.zeros((H, len(asset_names_sel)), dtype=float)

    if lc_choice == "No":
        for y_i in range(H):
            year_weights[y_i, :] = base_w_vec
    else:
        start_year = max(0, H - int(derisk_years))
        for y_i in range(H):
            if y_i < start_year:
                year_weights[y_i, :] = base_w_vec
            else:
                # alpha: 0→1 lungo il periodo di derisking, con 1 nell'ultimo anno
                alpha = (y_i - start_year + 1) / float(derisk_years)
                alpha = float(np.clip(alpha, 0.0, 1.0))
                w_y = (1.0 - alpha) * base_w_vec + alpha * min_risk_vec
                s_y = w_y.sum()
                year_weights[y_i, :] = (w_y / s_y) if s_y > 0 else base_w_vec

    # DataFrame long per area chart (composizione nel tempo)
    lc_df = pd.DataFrame(year_weights, columns=asset_names_sel)
    lc_df.insert(0, "Anno", list(range(1, H + 1)))  # anni 1..H

    lc_long = lc_df.melt(id_vars=["Anno"], var_name="Asset Class", value_name="Peso")
    fig_lc = px.area(
        lc_long,
        x="Anno",
        y="Peso",
        color="Asset Class",
        title="Evoluzione della composizione del portafoglio (Life Cycle)",
    )
    fig_lc.update_layout(
        margin=dict(l=70, r=25, t=70, b=65),
        xaxis_title="Anni",
        yaxis_title="Peso",
    )
    fig_lc.update_yaxes(tickformat=".0%")
    st.plotly_chart(fig_lc, use_container_width=True)

    # -----------------------
    # Backtesting Montante (ultima finestra = orizzonte)
    # -----------------------
    st.markdown(
        '<div class="uw-card"><h2>Backtesting del Montante</h2>'
        '<p>Evoluzione del capitale nell’<b>ultima finestra storica disponibile</b> di ampiezza pari all’orizzonte (anni), '
        'tenendo conto di: conferimento iniziale, versamenti periodici e dinamica dell’asset allocation (Life Cycle).</p></div>',
        unsafe_allow_html=True
    )

    if st.session_state.get("market_database") is None:
        st.warning("Per il backtesting del montante è necessario caricare e salvare prima il Database Mercati (Tools → Database Mercati).")
    else:
        try:
            db_bt = st.session_state["market_database"]["df"].copy()
            # uso rendimenti mensili; richiedo dati completi sulle asset class del Set
            need_cols = [c for c in asset_names_sel if c in db_bt.columns]
            miss_cols = [c for c in asset_names_sel if c not in db_bt.columns]
            if miss_cols:
                st.warning("Nel Database Mercati mancano queste Asset Class (colonne): " + ", ".join(miss_cols))
            else:
                # Pulizia indice date e selezione finestra temporale corretta (ultimi H anni)
                db_bt = db_bt.loc[:, need_cols].copy()

                # 1) Assicuro indice datetime ordinato
                db_bt.index = pd.to_datetime(db_bt.index, errors="coerce")
                db_bt = db_bt[db_bt.index.notna()].sort_index()

                # 2) Se la frequenza sembra infra-mensile (es. giornaliera/settimanale), compongo rendimenti mensili
                if db_bt.shape[0] >= 3:
                    deltas = db_bt.index.to_series().diff().dropna().dt.days
                    if not deltas.empty and deltas.median() < 20:
                        # compounding mensile: (1+r).prod()-1
                        db_bt = (1.0 + db_bt).resample("M").prod() - 1.0

                # 3) Costruisco l'ultima finestra di ampiezza H anni su base mensile
                n_months = int(H) * 12
                end_date = db_bt.index.max()
                start_date = end_date - pd.DateOffset(years=int(H))
                window = db_bt.loc[db_bt.index > start_date].copy()

                # Se ci sono più di n_months osservazioni (es. mesi extra), prendo gli ultimi n_months esatti
                if window.shape[0] > n_months:
                    window = window.iloc[-n_months:].copy()

                # Richiedo una finestra mensile completa: almeno n_months osservazioni e nessun NaN sulle asset class
                window = window.dropna(how="any")

                if window.shape[0] < n_months:
                    st.warning(
                        "Dati storici insufficienti per un backtesting su "
                        + str(H)
                        + " anni: nell'ultima finestra disponibile ci sono "
                        + str(window.shape[0])
                        + " mesi utili (ne servono "
                        + str(n_months)
                        + ")."
                    )
                else:
                    # Garantisco esattamente n_months osservazioni (ultimi n_months mesi)
                    window = window.iloc[-n_months:].copy()


                    # Calendario contributi su base mensile (versamenti a inizio periodo)
                    step_months = int(n_months)
                    contrib_m = np.zeros(step_months, dtype=float)
                    # mappo frequenza versamento in mesi
                    step_map = {"Mensile": 1, "Trimestrale": 3, "Semestrale": 6, "Annuale": 12}
                    step_k = int(step_map.get(freq, 1))

                    max_pay_months = int(periodic_years_int) * 12
                    if periodic_amount > 0 and max_pay_months > 0:
                        for m_i in range(step_k - 1, min(step_months, max_pay_months), step_k):
                            contrib_m[m_i] += float(periodic_amount)

                    # Simulazione deterministica del capitale
                    cap = np.zeros(step_months + 1, dtype=float)
                    cap[0] = float(initial_amount)

                    for t in range(1, step_months + 1):
                        # contributo a inizio mese
                        cap[t-1] += contrib_m[t-1]

                        # peso del Life Cycle: per mese t (1..), anno = floor((t-1)/12)
                        y_i = (t - 1) // 12  # 0..H-1
                        w_t = year_weights[y_i, :]

                        r_vec = window.iloc[t-1].astype(float).values  # rendimenti mensili
                        r_pf = float(np.dot(w_t, r_vec))

                        cap[t] = cap[t-1] * (1.0 + r_pf)

                    # Serie temporale: includo t=0 (data di inizio finestra)
                    dates = pd.DatetimeIndex([window.index[0] - pd.offsets.MonthEnd(1)]).append(window.index)
                    cap_series = pd.Series(cap, index=dates)
                    cap_series = cap_series[cap_series.index.notna()].copy()

                    # Serie dei conferimenti cumulati (per barre verticali)
                    # t=0: capitale iniziale; poi cumulata dei versamenti periodici (rimane costante dopo la fine dei versamenti)
                    contrib_cum = np.zeros(step_months + 1, dtype=float)
                    contrib_cum[0] = float(initial_amount)
                    if step_months > 0:
                        contrib_cum[1:] = float(initial_amount) + np.cumsum(contrib_m[:step_months])
                    contrib_series = pd.Series(contrib_cum, index=dates)
                    contrib_series = contrib_series[contrib_series.index.notna()].copy()

                    st.markdown("#### Andamento storico del montante (backtesting)", unsafe_allow_html=True)

                    # Figura interattiva stile Analisi Portafoglio (montante + drawdown)
                    cap_plot = cap_series.copy()
                    cap_plot = cap_plot[cap_plot > 0]

                    if cap_plot.empty:
                        st.info("Impossibile costruire il grafico del montante (serie vuota).")
                    else:
                        from plotly.subplots import make_subplots

                        running_max = cap_plot.cummax()
                        drawdown_pct = (cap_plot / running_max - 1.0) * 100.0

                        fig_bt = make_subplots(
                            rows=2, cols=1, shared_xaxes=True,
                            vertical_spacing=0.12,
                            row_heights=[0.70, 0.30]
                        )

                        fig_bt.add_trace(
                            go.Bar(
                                x=contrib_series.loc[cap_plot.index].index,
                                y=contrib_series.loc[cap_plot.index].values,
                                name="Conferimenti cumulati (€)",
                                opacity=0.5,
                                marker=dict(color="rgba(120, 200, 120, 0.35)"),
                                hovertemplate="Data: %{x|%d/%m/%Y}<br>Conferimenti cumulati: %{y:,.0f} €<extra></extra>",
                            ),
                            row=1, col=1
                        )

                        fig_bt.add_trace(
                            go.Scatter(
                                x=cap_plot.index,
                                y=cap_plot.values,
                                mode="lines",
                                line=dict(width=2.5),
                                name="Montante (€)",
                                hovertemplate="Data: %{x|%d/%m/%Y}<br>Montante: %{y:,.0f} €<extra></extra>",
                            ),
                            row=1, col=1
                        )

                        fig_bt.add_trace(
                            go.Scatter(
                                x=drawdown_pct.index,
                                y=drawdown_pct.values,
                                mode="lines",
                                fill="tozeroy",
                                line=dict(width=1.5),
                                name="Drawdown (%)",
                                hovertemplate="Data: %{x|%d/%m/%Y}<br>Drawdown: %{y:.2f}%<extra></extra>",
                            ),
                            row=2, col=1
                        )

                        # Bande di stress (solo se ricadono nella finestra)
                        stress_periods = [
                            ("2008-09-15", "2009-06-30", "Crisi finanziaria"),
                            ("2020-02-20", "2020-04-30", "Covid"),
                            ("2022-01-01", "2022-10-31", "Shock tassi / inflazione"),
                        ]
                        x_min = pd.to_datetime(cap_plot.index.min())
                        x_max = pd.to_datetime(cap_plot.index.max())
                        for s_dt, e_dt, label in [(pd.to_datetime(s), pd.to_datetime(e), l) for s, e, l in stress_periods]:
                            if e_dt < x_min or s_dt > x_max:
                                continue
                            s2 = max(s_dt, x_min)
                            e2 = min(e_dt, x_max)
                            fig_bt.add_vrect(
                                x0=s2, x1=e2,
                                fillcolor="rgba(200,200,200,0.18)",
                                line_width=0,
                                annotation_text=label,
                                annotation_position="top left"
                            )

                        # Annotazioni (massimo, minimo, ultimo)
                        idx_max = cap_plot.idxmax()
                        idx_min = cap_plot.idxmin()
                        idx_last = cap_plot.index[-1]

                        fig_bt.add_annotation(
                            x=idx_max, y=float(cap_plot.loc[idx_max]),
                            text=f"Massimo: {float(cap_plot.loc[idx_max]):,.0f}€".replace(",", "."),
                            showarrow=True, arrowhead=2, ax=30, ay=-30
                        )
                        fig_bt.add_annotation(
                            x=idx_min, y=float(cap_plot.loc[idx_min]),
                            text=f"Minimo: {float(cap_plot.loc[idx_min]):,.0f}€".replace(",", "."),
                            showarrow=True, arrowhead=2, ax=30, ay=30
                        )
                        fig_bt.add_annotation(
                            x=idx_last, y=float(cap_plot.loc[idx_last]),
                            text=f"Ultimo: {float(cap_plot.loc[idx_last]):,.0f}€".replace(",", "."),
                            showarrow=True, arrowhead=2, ax=-40, ay=-30
                        )

                        fig_bt.update_layout(
                            margin=dict(l=10, r=10, t=40, b=10),
                            hovermode="x unified",
                            legend_title_text="",
                            barmode="overlay",
                        )
                        fig_bt.update_yaxes(title_text="€", row=1, col=1)
                        fig_bt.update_yaxes(title_text="Drawdown (%)", row=2, col=1)

                        st.plotly_chart(fig_bt, use_container_width=True)

                        # Mini-sintesi
                        cbt1, cbt2, cbt3 = st.columns(3, gap="small")
                        cbt1.metric("Montante finale", f"{float(cap_plot.iloc[-1]):,.0f} €".replace(",", "."))
                        cbt2.metric("Montante massimo", f"{float(cap_plot.max()):,.0f} €".replace(",", "."))
                        cbt3.metric("Max Drawdown", f"{float(drawdown_pct.min()):.2f}%")
        except Exception as e:
            st.error(f"Errore nel backtesting del montante: {e}")


    # -----------------------
    # Monte Carlo – dinamica
    # -----------------------
    st.markdown(
        '<div class="uw-card"><h2>Simulazione Monte Carlo</h2>'
        '<p>Premere <b>Simula</b> per generare 1.000 scenari di evoluzione del capitale (t=0…fine orizzonte). '
        'Vengono tracciati: tutte le traiettorie (grigio chiaro) e i percentili 90/50/10 (verde/blu/rosso).</p></div>',
        unsafe_allow_html=True
    )

    sim_clicked = st.button("Simula", key="mc_simulate_btn")

    # Persisto il trigger in session_state per evitare che l'evento del bottone si perda su rerun
    if sim_clicked:
        st.session_state["mc_trigger"] = True

    if st.session_state.get("mc_trigger", False):
        # Controlli minimi input
        if exp_ret_sel is None or vol_sel is None or corr_sel is None:
            st.error("Per la simulazione Monte Carlo servono: rendimenti attesi, volatilità e correlazioni (Tools → Portafogli in Asset Class).")
            st.session_state["mc_trigger"] = False
            st.stop()

        try:
            mu_ann = np.asarray(pd.Series(exp_ret_sel, index=asset_names_sel).astype(float).values)  # annuo
            sig_ann = np.asarray(pd.Series(vol_sel, index=asset_names_sel).astype(float).values)    # annuo
            rho = np.asarray(pd.DataFrame(corr_sel, index=asset_names_sel, columns=asset_names_sel).astype(float).values)
            cov_ann = np.outer(sig_ann, sig_ann) * rho
        except Exception as e:
            st.error(f"Input di mercato non coerenti per la simulazione: {e}")
            st.session_state["mc_trigger"] = False
            st.stop()
        # Discretizzazione temporale: SEMPRE su base MENSILE (rendimenti concatenati mese per mese)
        months_per_year = 12
        n_steps = int(H * months_per_year)  # numero di mesi simulati

        # Contributi su griglia mensile:
        # - t=0: investimento iniziale
        # - t=1..: versamenti periodici inseriti ai mesi corretti in base alla frequenza scelta,
        #         fino alla durata periodic_years
        contrib = np.zeros(n_steps + 1, dtype=float)
        contrib[0] = float(initial_amount)

        step_map_m = {"Mensile": 1, "Trimestrale": 3, "Semestrale": 6, "Annuale": 12}
        step_k_m = int(step_map_m.get(freq, 1))  # ogni quanti mesi versa
        pay_months = int(periodic_years_int * 12)

        if periodic_amount > 0 and pay_months > 0:
            # Versamento al termine del mese 1,2,... (coerente con logica "t=1..n" nello step)
            for t in range(1, min(n_steps, pay_months) + 1):
                if (t % step_k_m) == 0:
                    contrib[t] = float(periodic_amount)

        # Conversione parametri annuali -> mensili
        # - rendimento atteso: capitalizzazione geometrica
        # - volatilità: regola della radice quadrata del tempo
        mu_m = (1.0 + mu_ann) ** (1.0 / 12.0) - 1.0
        sig_m = sig_ann / np.sqrt(12.0)

        cov_m = np.outer(sig_m, sig_m) * rho

        mu_step = mu_m
        cov_step = cov_m

        # Pesi per mese (costanti all'interno dell'anno y)
        step_weights = np.zeros((n_steps, len(asset_names_sel)), dtype=float)
        for t in range(1, n_steps + 1):
            y_i = (t - 1) // 12  # 0..H-1
            step_weights[t - 1, :] = year_weights[y_i, :]

        # Simulazione vettorizzata
        n_sims = 1000
        rng = np.random.default_rng()

        # Cholesky per generare correlazioni
        try:
            L = np.linalg.cholesky(cov_step)
        except np.linalg.LinAlgError:
            # fallback: jitter (cov non PSD per arrotondamenti)
            eps = 1e-10
            L = np.linalg.cholesky(cov_step + np.eye(cov_step.shape[0]) * eps)

        paths = np.zeros((n_sims, n_steps + 1), dtype=float)
        paths[:, 0] = contrib[0]

        # ============================
        # Simulazione (vettoriale, passo mensile)
        # - calcolo tutte le 1.000 traiettorie prima (più rapido)
        # - poi mostro un'animazione client-side (Plotly frames) che aggiunge progressivamente le linee
        #   senza far scomparire il grafico.
        # ============================
        with st.spinner("Simulazione in corso (1.000 traiettorie, passo mensile)..."):
            wealth = np.full(n_sims, contrib[0], dtype=float)

            for t in range(1, n_steps + 1):
                # shock correlati (n_sims x n_assets)
                Z = rng.standard_normal(size=(n_sims, len(asset_names_sel)))
                r_assets = mu_step + (Z @ L.T)  # (n_sims x n_assets)

                # rendimento portafoglio del mese t
                w_t = step_weights[t - 1, :]  # (n_assets,)
                r_p = (r_assets * w_t).sum(axis=1)  # (n_sims,)

                wealth = (wealth + contrib[t]) * (1.0 + r_p)
                paths[:, t] = wealth

        # ============================
        # Costruzione grafico animato (client-side)
        # ============================
        x_m = np.arange(0, n_steps + 1, dtype=int)
        x = x_m.astype(float) / 12.0  # asse X in anni

        # Per non creare 1.000 trace separate (molto pesante), uso UNA sola trace composta da segmenti
        # separati da None. Le frames aggiungono progressivamente nuovi segmenti.
        def _concat_paths(first_k: int):
            xs, ys = [], []
            for i in range(first_k):
                xs.extend(x.tolist())
                ys.extend(paths[i, :].tolist())
                xs.append(None); ys.append(None)
            return xs, ys

        max_animate = min(250, n_sims)  # animazione fluida lato browser (percentili calcolati su 1.000)

        fig = go.Figure()

        # Scenari (linee grigie): prima vista = 1 traiettoria, poi animazione fino a max_animate
        xs0, ys0 = _concat_paths(1)
        fig.add_trace(go.Scatter(
            x=xs0,
            y=ys0,
            mode="lines",
            line=dict(width=1, color="rgba(120,120,120,0.14)"),
            name="Scenari",
            showlegend=True,
            hoverinfo="skip",
        ))

        # Barre verticali dei conferimenti cumulati (sempre visibili)
        # STRADA ROBUSTA: uso SHAPES (linee verticali) invece di go.Bar, per evitare qualsiasi interazione/bug con le frames.
        # In questo modo il colore RGBA viene rispettato al 100% e le "barre" non possono sparire.
        cum_contrib = np.cumsum(contrib)

        # Legend entry (senza disegnare una seconda volta le barre)
        fig.add_trace(go.Bar(
            x=[x[0]],
            y=[0],
            name="Conferimenti cumulati (€)",
            marker=dict(color="rgba(120, 200, 120, 0.35)"),
            opacity=0.5,
            visible="legendonly",
            hoverinfo="skip",
            showlegend=True,
        ))

        # Disegno delle barre come linee verticali (shapes) sull’asse principale
        contrib_shapes = []
        for xi, yi in zip(x, cum_contrib):
            contrib_shapes.append(dict(
                type="line",
                xref="x",
                yref="y",
                x0=float(xi),
                x1=float(xi),
                y0=0,
                y1=float(yi),
                line=dict(color="rgba(120, 200, 120, 0.35)", width=2.5),
                layer="above",
            ))


        # Percentili (calcolati su TUTTE le 1.000 traiettorie)
        p10 = np.percentile(paths, 10, axis=0)
        p50 = np.percentile(paths, 50, axis=0)
        p90 = np.percentile(paths, 90, axis=0)

        # Range Y fisso per evitare clipping e per rendere SEMPRE visibili le barre dei conferimenti
        y_min = float(np.nanmin([paths[:max_animate, :].min(), p10.min(), cum_contrib.min(), 0.0]))
        y_max = float(np.nanmax([paths[:max_animate, :].max(), p90.max(), cum_contrib.max()]))
        pad = 0.06 * (y_max - y_min) if y_max > y_min else 1.0
        y_range = [y_min - pad, y_max + pad]

        # Banda 10–90 e linee percentili: DEVONO comparire solo dopo avere mostrato tutte le traiettorie grigie.
        # Creo le trace subito (per avere la legenda pronta) ma con dati "vuoti";
        # nell'ultima frame (k=max_animate) le valorizzo.
        empty_y = [None] * len(x)

        # Banda 10–90 (non in legenda) - inizialmente vuota
        fig.add_trace(go.Scatter(
            x=x, y=empty_y,
            mode="lines",
            line=dict(width=0, color="rgba(0,0,0,0)"),
            showlegend=False,
            hoverinfo="skip",
        ))
        fig.add_trace(go.Scatter(
            x=x, y=empty_y,
            mode="lines",
            line=dict(width=0, color="rgba(0,0,0,0)"),
            fill="tonexty",
            fillcolor="rgba(0,0,0,0.06)",
            showlegend=False,
            hoverinfo="skip",
        ))

        # Linee percentili (in legenda) - inizialmente vuote, poi valorizzate nell'ultima frame
        fig.add_trace(go.Scatter(
            x=x, y=empty_y,
            mode="lines",
            line=dict(width=3, color="green"),
            name="Ottimistico (90° percentile)",
            showlegend=True,
        ))
        fig.add_trace(go.Scatter(
            x=x, y=empty_y,
            mode="lines",
            line=dict(width=3, color="blue"),
            name="Atteso (50° percentile)",
            showlegend=True,
        ))
        fig.add_trace(go.Scatter(
            x=x, y=empty_y,
            mode="lines",
            line=dict(width=3, color="red"),
            name="Pessimistico (10° percentile)",
            showlegend=True,
        ))

        # Frames: aggiorno SOLO la trace degli scenari (indice 0).
        # Nell'ultima frame aggiorno ANCHE banda e percentili (indici 2..6).
        # Le barre restano sempre visibili (indice 1) e NON vengono toccate.
        frames = []
        for k in range(1, max_animate + 1):
            xs_k, ys_k = _concat_paths(k)
            if k < max_animate:
                frames.append(go.Frame(
                    name=str(k),
                    data=[go.Scatter(x=xs_k, y=ys_k)],
                    traces=[0],
                ))
            else:
                frames.append(go.Frame(
                    name=str(k),
                    data=[
                        go.Scatter(x=xs_k, y=ys_k),  # scenari
                        go.Scatter(x=x, y=p90),      # banda top
                        go.Scatter(x=x, y=p10),      # banda bottom (fill to next)
                        go.Scatter(x=x, y=p90),      # 90°
                        go.Scatter(x=x, y=p50),      # 50°
                        go.Scatter(x=x, y=p10),      # 10°
                    ],
                    traces=[0, 2, 3, 4, 5, 6],
                ))

        fig.frames = frames

        fig.update_layout(
            title=f"Evoluzione del capitale simulata (animazione: {max_animate} traiettorie su {n_sims}; percentili su 1.000)",
            shapes=contrib_shapes,
            xaxis_title="Anni (t)",
            yaxis_title="Capitale (€)",
            xaxis=dict(
                automargin=True,
                showgrid=True,
                gridcolor="rgba(0,0,0,0.08)",
                zeroline=False,
            ),
            yaxis=dict(
                automargin=True,
                range=y_range,
                showgrid=True,
                gridcolor="rgba(0,0,0,0.08)",
                zeroline=False,
            ),
            hovermode="x unified",
            legend_title_text="",
            legend=dict(
                orientation="v",
                yanchor="top",
                y=1.0,
                xanchor="left",
                x=1.02,
                bgcolor="rgba(255,255,255,0.75)",
                bordercolor="rgba(0,0,0,0.12)",
                borderwidth=1,
                font=dict(size=10),
            ),
            plot_bgcolor="white",
            paper_bgcolor="white",
            margin=dict(l=10, r=240, t=80, b=10),
            barmode="overlay",
            bargap=0.15,
        )
        # ============================
        # Tabella riassuntiva (percentili per anno) – calcolata su 1.000 traiettorie
        # ============================
        year_ends = [(y_i + 1) * 12 for y_i in range(H)]
        tbl = []
        cap0 = float(contrib[0])
        tbl.append({"Anno": 0, "10° percentile (€)": cap0, "50° percentile (€)": cap0, "90° percentile (€)": cap0})
        for y_i, t_end in enumerate(year_ends, start=1):
            tbl.append({
                "Anno": y_i,
                "10° percentile (€)": float(np.percentile(paths[:, t_end], 10)),
                "50° percentile (€)": float(np.percentile(paths[:, t_end], 50)),
                "90° percentile (€)": float(np.percentile(paths[:, t_end], 90)),
            })
        df_tbl = pd.DataFrame(tbl)
        df_tbl_fmt = df_tbl.copy()
        for c in ["10° percentile (€)", "50° percentile (€)", "90° percentile (€)"]:
            df_tbl_fmt[c] = df_tbl_fmt[c].map(lambda v: f"{v:,.0f}".replace(",", "."))

        # Persisto risultati (così non scompaiono al rerun)
        st.session_state["mc_last_fig"] = fig
        st.session_state["mc_last_table"] = df_tbl_fmt
        st.session_state["mc_chart_uid"] = f"mc_chart_{datetime.now().strftime('%H%M%S%f')}"

        # reset trigger e rerun per rendere subito il grafico
        st.session_state["mc_trigger"] = False
        st.rerun()
# -----------------------
    if "mc_last_fig" in st.session_state:
        fig = st.session_state["mc_last_fig"]
        uid = st.session_state.get("mc_chart_uid", "mc_chart")
        plot_html = pio.to_html(fig, include_plotlyjs="cdn", full_html=False, config={"displayModeBar": False})
        components.html(
            f'''
            <div id="{uid}">{plot_html}</div>
            <script>
              (function() {{
                const wrap = document.getElementById("{uid}");
                function playWhenReady() {{
                  if (!wrap) return;
                  const gd = wrap.querySelector(".plotly-graph-div");
                  if (gd && window.Plotly) {{
                    window.Plotly.animate(gd, null, {{
                      frame: {{duration: 25, redraw: false}},
                      transition: {{duration: 0}},
                      mode: "immediate",
                      fromcurrent: true
                    }});
                  }} else {{
                    setTimeout(playWhenReady, 200);
                  }}
                }}
                setTimeout(playWhenReady, 300);
              }})();
            </script>
            ''',
            height=560,
            scrolling=False
        )

    if "mc_last_table" in st.session_state:
        st.markdown('<div class="uw-sec-title-sm">Sintesi per anno (percentili 10/50/90)</div>', unsafe_allow_html=True)
        st.dataframe(st.session_state["mc_last_table"], use_container_width=True, hide_index=True)

    # -----------------------
    # Salvataggio
    # -----------------------

    # Se Life Cycle è attivo, salvo anche la traiettoria dei pesi (per mostrare la dinamica in “Selezione Prodotti”)
    composition_path_records = None
    life_cycle_info = {"enabled": False}
    try:
        if lc_choice == "Sì":
            life_cycle_info = {
                "enabled": True,
                "derisk_years": int(derisk_years),
                "min_risk_asset": str(min_risk_asset) if min_risk_asset is not None else None,
            }
            # lc_df contiene anni 1..H; aggiungo esplicitamente anche t=0
            df_path = lc_df.copy()
            row0 = {"Anno": 0}
            for i_a, a in enumerate(asset_names_sel):
                row0[str(a)] = float(base_w_vec[i_a])
            df_path = pd.concat([pd.DataFrame([row0]), df_path], ignore_index=True)
            # serializzo in list[dict] (JSON-friendly)
            composition_path_records = [
                {k: (float(v) if isinstance(v, (int, float, np.floating)) else v) for k, v in rec.items()}
                for rec in df_path.to_dict(orient="records")
            ]
        else:
            # salvo comunque l'info di disattivazione per trasparenza
            life_cycle_info = {"enabled": False}
    except Exception:
        composition_path_records = None
        life_cycle_info = {"enabled": False}

    if st.button("Salva Portafoglio", type="primary", key="pf_save_btn"):
        # consento salvataggio anche se nome vuoto? (qui richiediamo almeno un nome)
        if portfolio_name == "":
            st.error("Inserire un Nome per il Portafoglio prima di salvare.")
        else:
            base_id = f"{client_key}::{portfolio_name}"
            pid = base_id
            k = 2
            while pid in st.session_state["portfolios"]:
                pid = f"{base_id} ({k})"
                k += 1

            payload = {
                "id": pid,
                "client_key": client_key,
                "portfolio_name": portfolio_name,
                "objective": objective,
                "horizon_years": int(horizon_years),
                "initial_amount": float(initial_amount),
                "periodic_amount": float(periodic_amount),
                "periodic_freq": freq,
                "periodic_years": int(periodic_years),
                "equity_weight_pct": int(eq_w),
                "asset_selection": sel_as,
                "composition": w,
                "composition_path": composition_path_records,
                "life_cycle": life_cycle_info,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            st.session_state["portfolios"][pid] = payload
            st.session_state["client_portfolios"].setdefault(client_key, [])
            st.session_state["client_portfolios"][client_key].append(pid)
            st.success(f'Portafoglio "{portfolio_name}" salvato correttamente per il cliente selezionato.')
    persist_portfolios_from_session()
    persist_client_grids_from_session()

def render_crea_soluzione_gbi():
    """Crea Soluzione di Investimento → Goal-Based Investing (sezione dedicata)."""
    ensure_anagrafica_storage()
    ensure_portfolio_storage()
    ensure_asset_selection_storage()
    ensure_market_database_storage()  # mantiene coerenza con Asset-Only

    st.markdown(
        '<div class="uw-card"><h2>Goal-Based Investing</h2>'
        '<p>Impostazioni di base per la costruzione della soluzione dinamica orientata agli obiettivi.</p></div>',
        unsafe_allow_html=True
    )

    sub = st.radio(
        "Sotto-sezione",
        ["Nuovo Portafoglio", "Modifica Portafoglio"],
        horizontal=True,
        key="gbi_pf_subsection"
    )

    if sub == "Modifica Portafoglio":
        pf = st.session_state.get("portfolios", {})
        if not pf:
            st.info("Nessun portafoglio creato finora.")
            return
        rows = []
        for pid, payload in pf.items():
            rows.append({
                "ID": pid,
                "Cliente": payload.get("client_key", ""),
                "Nome Portafoglio": payload.get("portfolio_name", ""),
                "Obiettivo": payload.get("objective", ""),
                "Creato il": payload.get("created_at", ""),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
        return

    # -----------------------
    # Nuovo Portafoglio
    # -----------------------
    anags = st.session_state.get("anagrafiche", {})
    if not anags:
        st.warning("Devi creare l’Anagrafica Cliente prima di procedere.")
        return

    client_keys = list(anags.keys())
    labels = []
    for k in client_keys:
        d = anags[k].get("data", {})
        labels.append(f'{d.get("nome","").strip()} {d.get("cognome","").strip()}  —  ({k})')

    sel_label = st.selectbox("Seleziona Cliente / Investitore", labels, key="gbi_client_sel")
    client_key = client_keys[labels.index(sel_label)]
    _client_data = anags[client_key].get("data", {})

    st.markdown('<div class="uw-card"><h2>Impostazioni Portafoglio</h2></div>', unsafe_allow_html=True)
    portfolio_name = st.text_input("Nome del Portafoglio", value="", key="gbi_pf_name").strip()

    # Parametri investimento (struttura identica alla modalità Asset-Only)
    c1, c2 = st.columns([0.4, 0.6], gap="small")
    with c1:
        horizon_years = st.number_input(
            "Orizzonte temporale (anni)",
            min_value=1, max_value=100, value=10, step=1,
            key="gbi_horizon"
        )
        initial_amount = st.number_input(
            "Conferimento iniziale (€)",
            min_value=0.0, value=0.0, step=1000.0,
            key="gbi_initial"
        )
    with c2:
        periodic_amount = st.number_input(
            "Versamento periodico (€)",
            min_value=0.0, value=0.0, step=100.0,
            key="gbi_periodic_amt"
        )
        freq = st.selectbox(
            "Frequenza versamento",
            ["Mensile", "Trimestrale", "Semestrale", "Annuale"],
            key="gbi_freq"
        )
        max_years = int(horizon_years)
        periodic_years = st.number_input(
            "Anni di versamenti periodici",
            min_value=0, max_value=max_years, value=min(5, max_years), step=1,
            key="gbi_periodic_years"
        )

    # Grafico conferimenti (t=0 solo conferimento iniziale; rate periodiche dal periodo successivo)
    mult = {"Mensile": 12, "Trimestrale": 4, "Semestrale": 2, "Annuale": 1}[freq]
    horizon_years_int = int(horizon_years)
    periodic_years_int = int(periodic_years)

    if freq == "Annuale":
        labels_p = ["t=0"] + [f"Anno {y}" for y in range(1, horizon_years_int + 1)]
        amounts = [float(initial_amount)] + [
            float(periodic_amount) if y <= periodic_years_int else 0.0
            for y in range(1, horizon_years_int + 1)
        ]
    else:
        total_periods = horizon_years_int * mult
        periodic_periods = periodic_years_int * mult

        labels_p = ["t=0"]
        amounts = [float(initial_amount)]
        for p in range(1, total_periods + 1):
            year = (p - 1) // mult + 1
            within = (p - 1) % mult + 1
            labels_p.append(f"Y{year}-P{within}")
            amounts.append(float(periodic_amount) if p <= periodic_periods else 0.0)

    contrib_df = pd.DataFrame({"Periodo": labels_p, "Conferimenti (€)": amounts})
    fig_contrib = px.bar(contrib_df, x="Periodo", y="Conferimenti (€)")
    fig_contrib.update_layout(
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis_title="",
        yaxis_title="€"
    )
    st.plotly_chart(fig_contrib, use_container_width=True)

    # -----------------------
    # Selezione Portafogli per Strategia Dinamica (dal Set associato alla Griglia)
    # -----------------------
    st.markdown(
        '<div class="uw-card"><h2>Selezione Portafogli per Strategia Dinamica</h2>'
        '<p>Selezioni i portafogli (massimo 12) con cui costruire la soluzione dinamica, pescando dal Set associato alla Griglia del cliente.</p></div>',
        unsafe_allow_html=True
    )

    segmento = (_client_data or {}).get("segmento", "")
    if not segmento or segmento not in st.session_state.get("client_classes", {}):
        st.warning("Per questo cliente non è stato selezionato un Segmento di Clientela valido (Tools → Griglie Clientela).")
        return

    seg_payload = st.session_state["client_classes"][segmento]
    selected_set_name = seg_payload.get("selected_set", None)

    if not selected_set_name or selected_set_name not in st.session_state.get("asset_selections", {}):
        st.warning("Per il segmento selezionato non risulta associato un Set di Portafogli valido (Tools → Portafogli in Asset Class).")
        return

    set_payload = st.session_state["asset_selections"][selected_set_name]
    assets_df = set_payload.get("assets_df", pd.DataFrame(columns=["Asset Class", "Macro-Asset Class"]))
    alloc_df = set_payload.get("alloc_df", None)
    exp_ret = set_payload.get("exp_ret", None)
    vol = set_payload.get("vol", None)
    corr = set_payload.get("corr", None)

    if alloc_df is None or not isinstance(alloc_df, pd.DataFrame) or alloc_df.empty:
        st.error("Il Set associato alla Griglia non contiene composizioni portafogli valide.")
        return

    # Peso aggregato Azionario + Alternativo per ogni portafoglio del Set
    try:
        _macro_map = dict(zip(
            assets_df["Asset Class"].astype(str),
            assets_df["Macro-Asset Class"].astype(str)
        ))
    except Exception:
        _macro_map = {}

    _risky_cols = [
        a for a, m in _macro_map.items()
        if str(m).strip() in {"Azionario", "Alternativo"} and a in alloc_df.columns.astype(str).tolist()
    ]
    if len(_risky_cols) == 0:
        st.warning("Nel Set non risultano Asset Class marcate come 'Azionario' o 'Alternativo'. Impossibile calcolare il peso aggregato Azionario+Alternativo.")
        return

    eq_alt_pct = (alloc_df.loc[:, _risky_cols].sum(axis=1).astype(float) * 100.0).round(0).astype(int)
    pf_meta = pd.DataFrame({
        "Portafoglio": alloc_df.index.astype(str),
        "Peso Azionario+Alternativo (%)": eq_alt_pct.values.astype(int),
    }).sort_values(["Peso Azionario+Alternativo (%)", "Portafoglio"]).reset_index(drop=True)

    total_pf = int(pf_meta.shape[0])
    n_sel_default = min(10, total_pf, 12) if total_pf > 0 else 1
    n_sel = st.number_input(
        "Numero portafogli da utilizzare",
        min_value=1,
        max_value=12,
        value=int(st.session_state.get("gbi_dyn_n", n_sel_default)),
        step=1,
        key="gbi_dyn_n"
    )

    # --- Proposta iniziale: portafogli equispaziati lungo lo spettro del peso Azionario+Alternativo ---
    def _equispaced_portfolios(df_meta: pd.DataFrame, n: int) -> list[str]:
        if df_meta is None or df_meta.empty:
            return []
        n = int(n)
        if n <= 0:
            return []
        if df_meta.shape[0] <= n:
            return df_meta["Portafoglio"].astype(str).tolist()
        idxs = np.linspace(0, df_meta.shape[0] - 1, n).round(0).astype(int)
        return df_meta.loc[idxs, "Portafoglio"].astype(str).tolist()

    proposal = _equispaced_portfolios(pf_meta, int(n_sel))

    # inizializzo una sola volta per combinazione (Set, n_sel)
    init_token = f"{selected_set_name}::{int(n_sel)}"
    if st.session_state.get("gbi_dyn_init_token") != init_token:
        st.session_state["gbi_dyn_init_token"] = init_token
        for i, pf_name in enumerate(proposal):
            st.session_state[f"gbi_dyn_pf_{i}"] = pf_name
        # se n diminuisce, pulisco eventuali chiavi in eccesso
        for j in range(len(proposal), 12):
            st.session_state.pop(f"gbi_dyn_pf_{j}", None)

    # --- Selezione (sostituzione guidata) ---
    st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)
    st.markdown('<div class="uw-sec-title-sm">Portafogli selezionati</div>', unsafe_allow_html=True)
    st.caption("Può modificare liberamente i portafogli proposti. Per ogni portafoglio è mostrato il peso aggregato Azionario+Alternativo.")

    all_pf_names = pf_meta["Portafoglio"].astype(str).tolist()
    pf_to_eq = dict(zip(pf_meta["Portafoglio"].astype(str), pf_meta["Peso Azionario+Alternativo (%)"].astype(int)))

    selected_pf = []
    for i in range(int(n_sel)):
        default_pf = st.session_state.get(f"gbi_dyn_pf_{i}", proposal[i] if i < len(proposal) else all_pf_names[min(i, len(all_pf_names)-1)])
        cols = st.columns([0.55, 0.25, 0.20], gap="small")
        with cols[0]:
            pf_i = st.selectbox(
                f"Portafoglio {i+1}",
                options=all_pf_names,
                index=all_pf_names.index(default_pf) if default_pf in all_pf_names else 0,
                key=f"gbi_dyn_pf_{i}"
            )
        with cols[1]:
            st.markdown(f'<div class="uw-metric-sm"><div class="uw-metric-label">Az.+Alt.</div><div class="uw-metric-value">{pf_to_eq.get(pf_i, 0)}%</div></div>', unsafe_allow_html=True)
        with cols[2]:
            # indicazione rapida distanza dalla proposta
            prop_pf = proposal[i] if i < len(proposal) else pf_i
            delta = int(pf_to_eq.get(pf_i, 0) - pf_to_eq.get(prop_pf, 0))
            st.markdown(
                f'<div class="uw-metric-sm"><div class="uw-metric-label">Δ vs proposta</div><div class="uw-metric-value">{delta:+d}%</div></div>',
                unsafe_allow_html=True
            )
        selected_pf.append(pf_i)

    # validazione duplicati
    dup = [p for p in set(selected_pf) if selected_pf.count(p) > 1]
    if dup:
        st.warning("Attenzione: sono presenti portafogli duplicati nella selezione. Per i grafici verrà usato l’elenco unico (ordine preservato).")
        # preservo ordine
        seen = set()
        selected_pf = [p for p in selected_pf if (p not in seen and not seen.add(p))]

    # -----------------------
    # Sintesi grafica: area chart (composizioni) e scatter rischio-rendimento atteso
    # -----------------------
    st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)
    st.markdown('<div class="uw-sec-title-sm">Sintesi grafica dei portafogli selezionati</div>', unsafe_allow_html=True)

    # Area chart delle composizioni (solo portafogli selezionati)
    try:
        alloc_sub = alloc_df.loc[selected_pf, :].copy()
        long_alloc = alloc_sub.reset_index().melt(id_vars=alloc_sub.index.name or "index", var_name="Asset Class", value_name="Peso")
        if "index" not in long_alloc.columns:
            long_alloc.rename(columns={alloc_sub.index.name: "index"}, inplace=True)
        long_alloc.rename(columns={"index": "Portafoglio"}, inplace=True)

        area_fig = px.area(
            long_alloc,
            x="Portafoglio",
            y="Peso",
            color="Asset Class",
        )
        area_fig.update_layout(
            margin=dict(l=10, r=10, t=20, b=10),
            xaxis_title="Portafogli",
            yaxis_title="Peso",
            yaxis_tickformat=".0%",
        )
        st.plotly_chart(area_fig, use_container_width=True)
    except Exception:
        st.info("Impossibile costruire l’area chart delle composizioni per i portafogli selezionati.")

    # Scatter rischio-rendimento atteso (se presenti input di mercato)
    if exp_ret is None or vol is None or corr is None:
        st.info("Scatter rischio-rendimento atteso non disponibile: mancano rendimenti attesi / volatilità / correlazioni nel Set.")
    else:
        try:
            asset_names = assets_df["Asset Class"].astype(str).tolist()
            mu = np.asarray(pd.Series(exp_ret, index=asset_names).astype(float).values)
            sig = np.asarray(pd.Series(vol, index=asset_names).astype(float).values)
            rho = np.asarray(pd.DataFrame(corr, index=asset_names, columns=asset_names).astype(float).values)
            cov = np.outer(sig, sig) * rho

            W = alloc_df.loc[selected_pf, asset_names].values.astype(float)
            port_ret = W @ mu
            port_var = np.einsum("ij,jk,ik->i", W, cov, W)
            port_risk = np.sqrt(np.maximum(port_var, 0.0))

            pf_sc = pd.DataFrame({
                "Portafoglio": selected_pf,
                "Rischio (σ annuo)": port_risk,
                "Rendimento atteso annuo": port_ret,
                "Peso Azionario+Alternativo (%)": [pf_to_eq.get(p, 0) for p in selected_pf]
            })

            fig_pf = px.scatter(
                pf_sc,
                x="Rischio (σ annuo)",
                y="Rendimento atteso annuo",
                hover_name="Portafoglio",
                color="Peso Azionario+Alternativo (%)",
            )
            fig_pf.update_traces(
                marker=dict(size=14),
                hovertemplate=(
                    "<b>%{hovertext}</b><br>"
                    "Rischio: %{x:.2%}<br>"
                    "Rendimento atteso: %{y:.2%}<br>"
                    "Az.+Alt.: %{marker.color:.0f}%"
                    "<extra></extra>"
                ),
            )
            fig_pf.update_layout(
                title="Portafogli selezionati: rischio vs rendimento atteso",
                xaxis_tickformat=".0%",
                yaxis_tickformat=".0%",
                margin=dict(l=10, r=10, t=40, b=10),
            )
            st.plotly_chart(fig_pf, use_container_width=True)
        except Exception:
            st.info("Impossibile costruire lo scatter rischio-rendimento atteso per i portafogli selezionati.")

    # -----------------------
    # Definizione degli Obiettivi
    # -----------------------
    st.markdown(
        '<div class="uw-card"><h2>Definizione degli Obiettivi</h2>'
        '<p>Identifichi gli obiettivi futuri di spesa da perseguire. Gli obiettivi vanno inseriti in ordine <b>decrescente</b> di priorità (prima i più importanti).</p>'
        '</div>',
        unsafe_allow_html=True
    )

    n_goals = st.number_input(
        "Numero di obiettivi da perseguire",
        min_value=1,
        max_value=10,
        value=int(st.session_state.get("gbi_goals_n", 1)),
        step=1,
        key="gbi_goals_n"
    )

    base_dir = os.path.dirname(__file__) if "__file__" in globals() else os.getcwd()
    goal_icons = {
        "Accumulazione Capitale": os.path.join(base_dir, "Ob Accumulazione Capitale.png"),
        "Acquisto Casa": os.path.join(base_dir, "Ob Acquisto Casa.png"),
        "Istruzione Figli": os.path.join(base_dir, "Ob Istruzione Figli.png"),
        "Rendita Pensionistica": os.path.join(base_dir, "Ob Rendita Pensionistica.png"),
        "Beneficenza": os.path.join(base_dir, "Ob Beneficenza.png"),
        "Riduzione Debito": os.path.join(base_dir, "Ob Riduzione Debito.png"),
        "Altro Obiettivo": os.path.join(base_dir, "Ob Altro Obiettivo.png"),
    }
    goal_types = list(goal_icons.keys())

    def _img_to_b64(path: str) -> str | None:
        try:
            if not path or (not os.path.exists(path)):
                return None
            with open(path, "rb") as f:
                return base64.b64encode(f.read()).decode("ascii")
        except Exception:
            return None

    horizon_max = int(horizon_years_int)
    year_options = list(range(1, horizon_max + 1))

    # palette fissa per distinguere visivamente gli obiettivi
    goal_palette = [
        "#F59E0B",  # giallo
        "#3B82F6",  # blu
        "#10B981",  # verde
        "#EF4444",  # rosso
        "#8B5CF6",  # viola
        "#06B6D4",  # ciano
        "#F97316",  # arancio
        "#22C55E",  # verde 2
        "#E11D48",  # rosa
        "#64748B",  # grigio
    ]

    objectives = []
    for i in range(int(n_goals)):
        with st.expander(f"Obiettivo {i+1} (priorità {i+1})", expanded=(i == 0)):
            cL, cR = st.columns([0.22, 0.78], gap="medium")
            with cL:
                goal_type = st.selectbox(
                    "Obiettivo perseguito",
                    options=goal_types,
                    index=0,
                    key=f"gbi_goal_type_{i}"
                )
                b64 = _img_to_b64(goal_icons.get(goal_type, ""))
                if b64:
                    st.markdown(
                        f"""
                        <div style="display:flex; justify-content:center; padding:6px 0 0 0;">
                          <img src="data:image/png;base64,{b64}" style="width:120px; height:auto;" />
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                else:
                    st.info("Immagine non disponibile.")

            with cR:
                goal_name = st.text_input(
                    "Nome dell’Obiettivo",
                    value=st.session_state.get(f"gbi_goal_name_{i}", ""),
                    key=f"gbi_goal_name_{i}"
                ).strip()

                n_years = st.number_input(
                    "In quanti anni futuri sostenere la spesa",
                    min_value=1,
                    max_value=max(1, horizon_max),
                    value=int(st.session_state.get(f"gbi_goal_nyears_{i}", 1)),
                    step=1,
                    key=f"gbi_goal_nyears_{i}"
                )

                year_amounts = []
                st.caption("Per ciascun anno selezioni l’orizzonte (menu a tendina) e l’importo necessario.")
                for j in range(int(n_years)):
                    yc1, yc2 = st.columns([0.35, 0.65], gap="small")
                    with yc1:
                        y = st.selectbox(
                            f"Anno futuro {j+1}",
                            options=year_options,
                            index=min(j, len(year_options) - 1),
                            key=f"gbi_goal_{i}_year_{j}"
                        )
                    with yc2:
                        amt = st.number_input(
                            f"Spesa in anno {y} (€)",
                            min_value=0.0,
                            value=float(st.session_state.get(f"gbi_goal_{i}_amt_{j}", 0.0)),
                            step=1000.0,
                            format="%.0f",
                            key=f"gbi_goal_{i}_amt_{j}"
                        )
                    year_amounts.append({"year": int(y), "amount": float(amt)})

                # warning duplicati anni nello stesso obiettivo
                years_only = [x["year"] for x in year_amounts]
                if len(set(years_only)) != len(years_only):
                    st.warning("All’interno dello stesso obiettivo sono stati selezionati anni duplicati. Verifichi la coerenza.")

            objectives.append({
                "priority": i + 1,
                "type": goal_type,
                "name": goal_name if goal_name else f"Obiettivo {i+1}",
                "icon_path": goal_icons.get(goal_type, ""),
                "icon_b64": _img_to_b64(goal_icons.get(goal_type, "")),
                "color": goal_palette[i % len(goal_palette)],
                "schedule": year_amounts,
            })

    st.session_state["gbi_objectives"] = objectives

    # --- Invalidation (anti-cache incoerenze) ---
    # Se cambiano obiettivi o parametri di cashflow/orizzonte, i risultati salvati (MC/GA) diventano obsoleti.
    try:
        _fp_now = _gbi_fingerprint(objectives, int(max(1, far_year if 'far_year' in locals() else 1)),
                                   float(st.session_state.get("gbi_initial_amount", 0.0) if "gbi_initial_amount" in st.session_state else 0.0),
                                   str(st.session_state.get("gbi_contrib_freq", "Annuale")),
                                   float(st.session_state.get("gbi_periodic_amount", 0.0)),
                                   int(st.session_state.get("gbi_periodic_years", 0)))
        st.session_state["gbi_fp"] = _fp_now

        # Invalida scenari MC se non coerenti
        mc_meta = st.session_state.get("gbi_mc_assets_meta", {}) or {}
        if mc_meta.get("fingerprint") and mc_meta.get("fingerprint") != _fp_now:
            st.session_state.pop("gbi_mc_assets", None)
            st.session_state.pop("gbi_mc_assets_meta", None)

        # Invalida risultato GA se non coerente
        ga_best = st.session_state.get("gbi_ga_best", {}) or {}
        if ga_best.get("fingerprint") and ga_best.get("fingerprint") != _fp_now:
            st.session_state.pop("gbi_ga_best", None)
    except Exception:
        pass

    # -----------------------
    # Mappa degli Obiettivi (anni futuri ed importi)
    # -----------------------
    # Costruzione struttura year -> obiettivi
    rows = []
    for ob in objectives:
        for s in ob.get("schedule", []):
            if float(s.get("amount", 0.0)) <= 0:
                continue
            rows.append({
                "year": int(s.get("year")),
                "priority": int(ob.get("priority")),
                "goal": ob.get("name"),
                "type": ob.get("type"),
                "amount": float(s.get("amount")),
                "color": ob.get("color"),
                "icon_b64": ob.get("icon_b64"),
            })

    st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)
    st.markdown('<div class="uw-sec-title-sm">Mappa degli Obiettivi (anni futuri ed importi)</div>', unsafe_allow_html=True)

    if not rows:
        st.info("Per visualizzare la mappa, inserisca almeno una spesa (importo > 0) per uno o più obiettivi.")
        return

    df_map = pd.DataFrame(rows)
    max_amt = float(df_map["amount"].max()) if not df_map.empty else 0.0
    max_amt = max(max_amt, 1.0)
    # Grafico compatto: barre verticali in pila (stacked) + icone in alto per obiettivo
    # - Asse X: anni futuri
    # - Barre: importi per obiettivo (colori diversi), impilate se più obiettivi nello stesso anno
    # - Icone: posizionate in corrispondenza dell'anno medio delle spese di ciascun obiettivo
        # -----------------------
    # Conferimenti (iniziale + periodici) da rappresentare come barre negative
    # -----------------------
    # Costruisco un profilo annuo dei conferimenti coerente con:
    # - conferimento iniziale a t=0
    # - versamenti periodici per i primi "Anni di versamenti periodici"
    step_per_year = {"Mensile": 12, "Trimestrale": 4, "Semestrale": 2, "Annuale": 1}.get(str(freq), 12)
    horizon_years_int = int(horizon_years_int)
    periodic_years_int = int(periodic_years_int)

    contrib_by_year: dict[int, float] = {}
    if float(initial_amount) > 0:
        contrib_by_year[0] = float(initial_amount)

    # Aggregazione annua: in assenza di un calendario mensile, assumo versamenti equispaziati nell'anno
    if float(periodic_amount) > 0 and periodic_years_int > 0:
        annualized = float(periodic_amount) * float(step_per_year)
        for y in range(1, min(periodic_years_int, horizon_years_int) + 1):
            contrib_by_year[y] = contrib_by_year.get(y, 0.0) + annualized

    years_from_expenses = df_map["year"].unique().tolist()
    years_from_contrib = list(contrib_by_year.keys())
    years_sorted = sorted(set([int(y) for y in years_from_expenses] + [int(y) for y in years_from_contrib]))

    min_year = int(min(years_sorted))
    max_year = int(max(years_sorted))

    # Totali annui per dimensionare correttamente icone e margini
    df_tot = df_map.groupby("year", as_index=False)["amount"].sum().rename(columns={"amount": "total"})
    max_total = float(df_tot["total"].max()) if not df_tot.empty else 1.0
    max_total = max(max_total, 1.0)
    y_icon = max_total * 1.12  # altezza unica per tutte le icone (sopra le barre)

    # Ordinamento obiettivi: priorità crescente (1 = più importante) e poi nome
    goals_order = (
        df_map[["goal", "priority", "color", "icon_b64"]]
        .drop_duplicates()
        .sort_values(["priority", "goal"])
        .reset_index(drop=True)
    )

    fig = go.Figure()

    # Barre in pila: un trace per obiettivo
    for _, g in goals_order.iterrows():
        g_name = str(g["goal"])
        g_color = str(g["color"])
        sub = df_map[df_map["goal"] == g_name].groupby("year", as_index=False)["amount"].sum()
        amounts_by_year = {int(r["year"]): float(r["amount"]) for _, r in sub.iterrows()}
        y_vals = [amounts_by_year.get(int(y), 0.0) for y in years_sorted]

        fig.add_trace(
            go.Bar(
                x=years_sorted,
                y=y_vals,
                name=g_name,
                marker=dict(color=g_color),
                opacity=0.5,
                width=0.8,
                hovertemplate="<b>%{fullData.name}</b><br>Anno %{x}<br>€ %{y:,.0f}<extra></extra>",
            )
        )

    # Conferimenti: barre negative sotto l'asse X (opacità 0.5)
    # NOTA: per rendere le barre dei conferimenti completamente indipendenti dalle barre delle spese
    # (ed evitare qualsiasi "cancellazione" in anni dove coesistono spese e conferimenti),
    # plottiamo i conferimenti su un asse Y secondario (y2) sovrapposto al principale.
    y_contrib = []
    if contrib_by_year:
        y_contrib = [-float(contrib_by_year.get(int(y), 0.0)) for y in years_sorted]
        if any(abs(v) > 0 for v in y_contrib):
            fig.add_trace(
                go.Bar(
                    x=years_sorted,
                    y=y_contrib,
                    name="Conferimenti (iniziale + periodici)",
                    marker=dict(color="rgba(0, 120, 200, 0.50)"),
                    opacity=0.5,
                    yaxis="y2",
                    width=0.8,
                    hovertemplate="<b>%{fullData.name}</b><br>Anno %{x}<br>€ %{y:,.0f}<extra></extra>",
                )
            )

    # Range asse Y: include spese (positive) e conferimenti (negativi)
    max_contrib_abs = max([abs(v) for v in y_contrib], default=0.0) if y_contrib else 0.0
    y_min = -max_contrib_abs * 1.15 if max_contrib_abs > 0 else 0.0



    fig.update_layout(
        barmode="stack",
        height=480,
        margin=dict(l=20, r=20, t=90, b=40),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
        xaxis=dict(
            title="Anni futuri",
            tickmode="linear",
            dtick=1,
            range=[min_year - 0.5, max_year + 0.5],
            showgrid=True,
            zeroline=False,
        ),
        yaxis=dict(title="Importo (€)", showgrid=True, zeroline=True),
        yaxis2=dict(
            overlaying="y",
            matches="y",
            side="right",
            showgrid=False,
            zeroline=False,
            showticklabels=False,
        ),
    )

        # Icone lungo una diagonale: una per obiettivo
    # - Le icone sono posizionate in corrispondenza dell'anno medio delle sue spese (x_mean)
    # - L'altezza (y) segue una diagonale/curva crescente dall'origine verso l'angolo alto del grafico,
    #   così da rimanere compatta anche con molti obiettivi.
    # - La diagonale è resa come freccia convessa a bassa opacità.
    x_span = max(max_year - min_year, 1)
    y0 = max_total * 0.06
    y1 = max_total * 1.18
    bulge = max_total * 0.14  # convessità della "freccia"

    # Curva convessa (tipo freccia) su cui appoggiare le icone
    x_curve = np.linspace(min_year, max_year, 80)
    t_curve = (x_curve - float(min_year)) / float(x_span)
    y_curve = y0 + (y1 - y0) * t_curve + bulge * np.sin(np.pi * t_curve)

    # Linea curva
    fig.add_trace(
        go.Scatter(
            x=x_curve,
            y=y_curve,
            mode="lines",
            line=dict(width=7, color="rgba(30, 90, 160, 0.18)"),
            hoverinfo="skip",
            showlegend=False,
        )
    )
    # Punta freccia (annotazione) per dare l'effetto "arrow"
    fig.add_annotation(
        x=max_year,
        y=float(y_curve[-1]),
        xref="x",
        yref="y",
        ax=max_year - 0.35,
        ay=float(y_curve[-1]) - max_total * 0.02,
        axref="x",
        ayref="y",
        showarrow=True,
        arrowhead=3,
        arrowsize=1.2,
        arrowwidth=6,
        arrowcolor="rgba(30, 90, 160, 0.18)",
        text="",
    )

    def _y_on_curve(x_val: float) -> float:
        t = (float(x_val) - float(min_year)) / float(x_span)
        t = min(max(t, 0.0), 1.0)
        return float(y0 + (y1 - y0) * t + bulge * np.sin(np.pi * t))

    # Icone: posizionate lungo la curva, in corrispondenza dell'anno medio delle spese dell'obiettivo.
    # Richieste:
    # (1) immagini leggermente più grandi;
    # (2) evitare sovrapposizioni se più obiettivi ricadono nella stessa posizione temporale:
    #     - raggruppiamo per "bucket" temporale e impiliamo verticalmente le icone.
    icon_items = []
    for _, g in goals_order.iterrows():
        g_name = str(g["goal"])
        b64 = g.get("icon_b64")
        if not isinstance(b64, str) or not b64.strip():
            continue

        years_g = df_map[(df_map["goal"] == g_name) & (df_map["amount"] > 0)]["year"].tolist()
        if not years_g:
            continue

        x_mean = float(sum(years_g)) / float(len(years_g))
        y_base = _y_on_curve(x_mean)

        icon_items.append(
            {
                "goal": g_name,
                "priority": int(g.get("priority", 9999)),
                "x_mean": x_mean,
                "y_base": y_base,
                "b64": b64,
            }
        )
    # Bucket temporale per evitare collisioni:
    # Le immagini in Plotly occupano spazio in "unità asse x" (anni). Se due icone hanno x molto vicine,
    # possono sovrapporsi anche se non identiche. Usiamo quindi un bucket basato su una distanza minima.
    # Regola: se due icone cadono nella stessa "finestra temporale" (entro ~1 anno), le impiliamo verticalmente.
    def _bucket_x(xv: float, step: float) -> int:
        """Assegna xv a un bucket temporale stabile (intero) per evitare collisioni tra icone.
        Usiamo floor division per evitare che valori vicini al bordo finiscano in bucket diversi.
        """
        return int(math.floor(float(xv) / float(step)))

    # Parametri icone (più grandi e più leggibili)
    # NB: sizex è espresso in "anni" (unità dell'asse x).
    # Per impedire sovrapposizioni anche quando gli anni medi sono ravvicinati,
    # imponiamo una soglia orizzontale più ampia del sizex effettivo.
    icon_sizex = 1.90
    icon_sizey = max_total * 0.30
    min_dx = icon_sizex * 1.30  # soglia collisione orizzontale (anni) - più severa
    icon_stack_gap = max_total * 0.16  # distanza verticale tra icone impilate nello stesso bucket (più ampia)

    buckets: dict[int, list[dict]] = {}
    for it in icon_items:
        k = _bucket_x(it["x_mean"], step=min_dx)
        buckets.setdefault(k, []).append(it)

    ymax_icons = 0.0

    for k, items in buckets.items():
        # Ordine: priorità (1 = più importante) poi nome
        items_sorted = sorted(items, key=lambda d: (d["priority"], d["goal"]))
        for j, it in enumerate(items_sorted):
            x_mean = float(it["x_mean"])
            # stessa base su curva, ma con impilamento verticale per evitare sovrapposizione
            y_pos = float(it["y_base"]) + float(j) * icon_stack_gap

            fig.add_layout_image(
                dict(
                    source=f"data:image/png;base64,{it['b64']}",
                    xref="x",
                    yref="y",
                    x=x_mean,
                    y=y_pos,
                    xanchor="center",
                    yanchor="bottom",
                    sizex=icon_sizex,
                    sizey=icon_sizey,
                    sizing="contain",
                    opacity=1.0,
                    layer="above",
                )
            )
            ymax_icons = max(ymax_icons, y_pos + icon_sizey)
    # Estende l'asse Y per includere le icone
    fig.update_yaxes(range=[float(y_min), max(float(max(y_curve)) + max_total * 0.12, float(ymax_icons) + max_total * 0.06)])

    st.plotly_chart(fig, use_container_width=True)


    # ------------------------------
    # IRR (Tasso interno di rendimento) per raggiungere gli obiettivi
    # Conferimenti (iniziale + periodici) = flussi in uscita (negativi)
    # Spese obiettivi = flussi in entrata (positivi)  [come da specifica]
    # ------------------------------
    try:
        import numpy as _np
        try:
            import numpy_financial as _npf
            _irr = _npf.irr
        except Exception:
            # Fallback robusto (bisezione su NPV)
            def _irr(cashflows):
                cashflows = _np.asarray(cashflows, dtype=float)
                if not ((cashflows > 0).any() and (cashflows < 0).any()):
                    return _np.nan

                def _npv(r):
                    return _np.sum(cashflows / ((1.0 + r) ** _np.arange(len(cashflows))))

                lo, hi = -0.9999, 10.0
                f_lo, f_hi = _npv(lo), _npv(hi)
                if _np.isnan(f_lo) or _np.isnan(f_hi) or f_lo * f_hi > 0:
                    hi = 100.0
                    f_hi = _npv(hi)
                    if _np.isnan(f_hi) or f_lo * f_hi > 0:
                        return _np.nan

                for _ in range(200):
                    mid = (lo + hi) / 2
                    f_mid = _npv(mid)
                    if _np.isnan(f_mid):
                        return _np.nan
                    if abs(f_mid) < 1e-10:
                        return mid
                    if f_lo * f_mid <= 0:
                        hi, f_hi = mid, f_mid
                    else:
                        lo, f_lo = mid, f_mid
                return (lo + hi) / 2

        # Flussi annuali t=0..H (anni futuri 1..H)
        _H = int(horizon_years_int) if 'horizon_years_int' in locals() else int(horizon_years)
        _cf = [0.0] * (_H + 1)

        # Conferimenti: uscite (negative)
        _cf[0] -= float(initial_amount)
        _vp_annuo = float(periodic_amount) * float(mult)
        for _t in range(1, min(int(periodic_years_int), _H) + 1):
            _cf[_t] -= _vp_annuo

        # Spese obiettivi: entrate (positive) come da specifica
        for _ob in objectives:
            for _s in _ob.get("schedule", []):
                try:
                    _y = int(_s.get("year"))
                    _a = float(_s.get("amount", 0.0))
                    if 0 <= _y <= _H and _a > 0:
                        _cf[_y] += _a
                except Exception:
                    pass

        _irr_val = _irr(_cf)
        if _irr_val is None or _np.isnan(_irr_val):
            st.info("Il Tasso di Rendimento necessario per raggiungere tutti gli obiettivi non è calcolabile con i dati correnti (servono flussi sia negativi sia positivi).")
        elif _irr_val < 0:
            st.markdown("**Il Tasso di Rendimento necessario per raggiungere tutti gli obiettivi è:** Negativo")
        else:
            st.markdown(f"**Il Tasso di Rendimento necessario per raggiungere tutti gli obiettivi è:** {(_irr_val * 100):.2f}%")
    except Exception:
        st.info("Il Tasso di Rendimento necessario per raggiungere tutti gli obiettivi non è calcolabile con i dati correnti.")
    
    # ============================================================
    # La soluzione di investimento dinamica
    # (Metodo GA su strategie annuali; scenari Monte Carlo su Asset Class
    #  utilizzando rendimento atteso, rischio e correlazioni delle Asset Class)
    # ============================================================
    st.markdown(
        '<div class="uw-card"><h2>La soluzione di investimento dinamica</h2>'
        '<p>La strategia è costruita con un <b>Algoritmo Genetico</b> che seleziona, anno per anno, il portafoglio da detenere '
        'tra quelli scelti nella sezione <i>Portafogli selezionati</i>, imponendo che il rischio non aumenti nel tempo. '
        'La valutazione avviene su <b>1.000</b> scenari Monte Carlo di rendimenti <b>mensili</b> delle Asset Class.</p></div>',
        unsafe_allow_html=True
    )

    # --- Input indispensabili (Asset Class + Composizioni portafogli selezionati) ---
    if exp_ret is None or vol is None or corr is None:
        st.info(
            "Per eseguire il modello dinamico sono necessari rendimenti attesi, volatilità e correlazioni delle Asset Class "
            "nel Set (Tools → Portafogli in Asset Class)."
        )
        return

    try:
        asset_names = assets_df["Asset Class"].astype(str).tolist()
        mu_ann_assets = np.asarray(pd.Series(exp_ret, index=asset_names).astype(float).values)  # rendimento atteso annuo (aritmetico)
        sig_ann_assets = np.asarray(pd.Series(vol, index=asset_names).astype(float).values)     # volatilità annua
        rho_assets = np.asarray(pd.DataFrame(corr, index=asset_names, columns=asset_names).astype(float).values)

        # Matrice pesi dei portafogli selezionati (righe = portafogli; colonne = asset class)
        W_sel_raw = alloc_df.loc[selected_pf, asset_names].values.astype(float)

        # Ordinamento dei portafogli per rischio (σ annua crescente): indice 1 = meno rischioso; indice H = più rischioso
        cov_ann_assets = np.outer(sig_ann_assets, sig_ann_assets) * rho_assets
        port_ret_sel = W_sel_raw @ mu_ann_assets
        port_var_sel = np.einsum("ij,jk,ik->i", W_sel_raw, cov_ann_assets, W_sel_raw)
        port_sig_sel = np.sqrt(np.maximum(port_var_sel, 0.0))

        order = np.argsort(port_sig_sel)  # crescente
        ports_ordered = [selected_pf[i] for i in order.tolist()]
        W_ports = W_sel_raw[order, :]
        port_sig_ord = port_sig_sel[order]
        port_ret_ord = port_ret_sel[order]
        H = int(len(ports_ordered))

        # --- (GBI) Persisto in sessione la frontiera di portafogli e la lista Asset Class
        #     (necessari per salvare/ricostruire la composizione dinamica della strategia GA)
        try:
            st.session_state["gbi_asset_names"] = list(asset_names)
            st.session_state["gbi_W_ports"] = np.asarray(W_ports, dtype=float)
            st.session_state["gbi_ports_ordered"] = list(ports_ordered)
        except Exception:
            pass


        st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)
        st.markdown('<div class="uw-sec-title-sm">Input del modello dinamico</div>', unsafe_allow_html=True)

        df_in = pd.DataFrame({
            "Indice (1=meno rischioso)": np.arange(1, H + 1),
            "Portafoglio": ports_ordered,
            "Rendimento atteso annuo": port_ret_ord.astype(float),
            "Rischio (σ annuo)": port_sig_ord.astype(float),
        })
        st.dataframe(
            df_in.style.format({"Rendimento atteso annuo": "{:.2%}", "Rischio (σ annuo)": "{:.2%}"}),
            use_container_width=True
        )
    except Exception:
        st.info("Impossibile preparare gli input del modello dinamico con le informazioni disponibili.")
        return

    # --- Orizzonte = anno dell’obiettivo più lontano ---
    try:
        obj_rows = st.session_state.get("gbi_objectives", [])
        far_year = 0
        for ob in (obj_rows or []):
            for s in ob.get("schedule", []):
                try:
                    far_year = max(far_year, int(s.get("year", 0)))
                except Exception:
                    pass
        T_years = int(max(1, far_year))
    except Exception:
        T_years = int(max(1, int(st.session_state.get("gbi_horizon", 10))))

    M_months = int(T_years * 12)

    c1, c2, c3, c4 = st.columns([0.25, 0.25, 0.25, 0.25], gap="small")
    with c1:
        n_scen = st.number_input("Numero scenari", min_value=200, max_value=20000, value=1000, step=100, key="gbi_ga_n_scen")
    with c2:
        seed = st.number_input("Seed (opzionale)", min_value=0, max_value=999999, value=12345, step=1, key="gbi_ga_seed")
    with c3:
        pop_size = st.number_input("Popolazione", min_value=50, max_value=1000, value=50, step=50, key="gbi_ga_pop")
    with c4:
        st.metric("Orizzonte (anni)", f"{T_years}")

    st.caption(
        "Conversioni mensili: rendimento atteso mensile = (1+μ_annuo)^(1/12) − 1; "
        "volatilità mensile = σ_annuo / √12. I rendimenti mensili delle Asset Class sono simulati come Normale multivariata."
    )

    def _build_monthly_contributions(T_years_: int, freq_: str, periodic_amt_: float, periodic_years_: int) -> np.ndarray:
        """Contributi mensili (solo rate periodiche). Il conferimento iniziale è gestito separatamente."""
        M_ = int(T_years_ * 12)
        cash_in = np.zeros(M_, dtype=float)
        step = {"Mensile": 1, "Trimestrale": 3, "Semestrale": 6, "Annuale": 12}.get(freq_, 12)
        max_m = int(periodic_years_ * 12)
        if periodic_amt_ <= 0 or max_m <= 0:
            return cash_in
        for m in range(step, min(M_, max_m) + 1, step):
            cash_in[m - 1] += float(periodic_amt_)
        return cash_in

    def _build_monthly_outflows_from_objectives(objectives_: list[dict], max_years_: int, upto_priority: int | None = None) -> np.ndarray:
        """Flussi di spesa mensili. Ogni spesa al 'Year y' è applicata al mese 12*y."""
        M_ = int(max_years_ * 12)
        cash_out = np.zeros(M_, dtype=float)
        for ob in (objectives_ or []):
            pr = int(ob.get("priority", 999999))
            if upto_priority is not None and pr > int(upto_priority):
                continue
            for s in ob.get("schedule", []):
                try:
                    y = int(s.get("year", 0))
                    amt = float(s.get("amount", 0.0))
                except Exception:
                    continue
                if y <= 0 or amt <= 0:
                    continue
                m = int(y * 12) - 1
                if 0 <= m < M_:
                    cash_out[m] += amt
        return cash_out


    def _gbi_fingerprint(objectives_: list[dict], T_years_: int, initial_amount_: float,
                         freq_: str, periodic_amount_: float, periodic_years_: int) -> str:
        """Fingerprint deterministico dello stato GBI (obiettivi + parametri cashflow/orizzonte).
        Serve a invalidare risultati GA/MC salvati in sessione quando cambiano i dati.
        """
        # Normalizzo per evitare differenze spurie (es. float vs int)
        obj_norm = []
        for ob in (objectives_ or []):
            try:
                pr = int(ob.get("priority"))
            except Exception:
                pr = None
            sched = []
            for s in (ob.get("schedule", []) or []):
                try:
                    y = int(s.get("year", 0))
                    a = float(s.get("amount", 0.0))
                except Exception:
                    continue
                if y > 0 and a != 0:
                    sched.append({"year": y, "amount": a})
            sched.sort(key=lambda x: (x["year"], x["amount"]))
            obj_norm.append({"priority": pr, "schedule": sched})
        obj_norm.sort(key=lambda x: (x["priority"] if x["priority"] is not None else 10**9))

        payload = {
            "T_years": int(T_years_),
            "initial_amount": float(initial_amount_),
            "freq": str(freq_),
            "periodic_amount": float(periodic_amount_),
            "periodic_years": int(periodic_years_),
            "objectives": obj_norm,
        }
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


    def _simulate_assets_mc(mu_ann: np.ndarray, sig_ann: np.ndarray, rho: np.ndarray, months: int, scen: int, seed_: int) -> np.ndarray:
        """Rende array (scen, n_assets, months) di rendimenti mensili simulati."""
        mu_ann = np.asarray(mu_ann, dtype=float).reshape(-1)
        sig_ann = np.asarray(sig_ann, dtype=float).reshape(-1)
        rho = np.asarray(rho, dtype=float)

        mu_m = np.power(1.0 + mu_ann, 1.0 / 12.0) - 1.0
        sig_m = sig_ann / np.sqrt(12.0)
        cov_m = np.outer(sig_m, sig_m) * rho

        rng = np.random.default_rng(int(seed_))
        try:
            L = np.linalg.cholesky(cov_m)
        except np.linalg.LinAlgError:
            L = np.linalg.cholesky(cov_m + np.eye(cov_m.shape[0]) * 1e-10)

        Z = rng.standard_normal(size=(int(scen) * int(months), mu_m.shape[0]))
        X = Z @ L.T
        R = X + mu_m
        R = R.reshape(int(scen), int(months), mu_m.shape[0]).transpose(0, 2, 1)  # (scen, assets, months)
        R = np.maximum(R, -0.9999)
        return R

    def _repair_nonincreasing(row: np.ndarray) -> np.ndarray:
        """Impone non-crescenza: row[t+1] <= row[t]."""
        r = row.astype(int).copy()
        for t in range(0, r.shape[0] - 1):
            if r[t + 1] > r[t]:
                r[t + 1] = r[t]
        return r

    def _init_population(pop: int, years: int, H_: int, rng: np.random.Generator) -> np.ndarray:
        P = rng.integers(1, H_ + 1, size=(int(pop), int(years)), endpoint=False)
        # endpoint=False -> max H_ incluso? in numpy endpoint=False esclude high; quindi high=H_+1.
        P = np.sort(P, axis=1)[:, ::-1]  # ordino decrescente (non crescente nel tempo)
        return P

    def _roulette_select_idx(fitness: np.ndarray, rng: np.random.Generator) -> int:
        f = np.asarray(fitness, dtype=float)
        f = np.maximum(f, 0.0)
        s = float(f.sum())
        if s <= 0:
            return int(rng.integers(0, f.shape[0]))
        p = f / s
        return int(rng.choice(np.arange(f.shape[0]), p=p))

    def _evaluate_population(population: np.ndarray, R_assets: np.ndarray, W_ports_: np.ndarray,
                             initial_: float, cash_in: np.ndarray, cash_out: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """
        Ritorna:
        - fitness = probabilità di successo (wealth sempre >=0)
        - std_final = volatilità del capitale finale (dev. std. sui 1.000 scenari)
        """
        S, A, M = R_assets.shape
        Pn, Y = population.shape
        # R_pf: (S, H, M)
        R_pf = np.einsum("sam,ha->shm", R_assets, W_ports_)
        R_pf_smH = R_pf.transpose(0, 2, 1)  # (S, M, H)
        idx_month = np.repeat(population - 1, 12, axis=1)  # (Pn, M)
        if idx_month.shape[1] != M:
            # in caso di arrotondamenti (non dovrebbe), adattamento
            idx_month = idx_month[:, :M] if idx_month.shape[1] > M else np.pad(idx_month, ((0,0),(0, M-idx_month.shape[1])), mode="edge")

        # Selezione rendimenti: (S, Pn, M)
        R_stack = R_pf_smH[:, None, :, :]  # (S,1,M,H)
        idx = idx_month[None, :, :, None]  # (1,Pn,M,1)
        sel = np.take_along_axis(R_stack, idx, axis=3).squeeze(3)  # (S,Pn,M)

        wealth = np.full((S, Pn), float(initial_), dtype=float)
        min_w = wealth.copy()

        for m in range(M):
            if cash_in is not None:
                wealth += float(cash_in[m])
            wealth *= (1.0 + sel[:, :, m])
            if cash_out is not None:
                wealth -= float(cash_out[m])
            min_w = np.minimum(min_w, wealth)

        success = (min_w >= 0.0) & (wealth >= 0.0)
        fitness = success.mean(axis=0)  # (Pn,)
        std_final = wealth.std(axis=0, ddof=1)
        return fitness, std_final

    # --- Costruzione cashflow mensili ---
    objectives_all = st.session_state.get("gbi_objectives", [])
    cash_in = _build_monthly_contributions(T_years, freq, float(periodic_amount), int(periodic_years_int))
    cash_out_all = _build_monthly_outflows_from_objectives(objectives_all, T_years, upto_priority=None)
    initial_cap = float(initial_amount)

    # --- Pulsanti azione ---
    colA, colB = st.columns([0.5, 0.5], gap="small")
    with colA:
        gen_ok = st.button("Step 1: Genera scenari Monte Carlo", type="secondary", use_container_width=True)
    with colB:
        run_ok = st.button("Step 2: Esegui Algoritmo Genetico", type="secondary", use_container_width=True)

    if gen_ok:
        with st.spinner("Simulazione Monte Carlo in corso..."):
            R_assets = _simulate_assets_mc(mu_ann_assets, sig_ann_assets, rho_assets, M_months, int(n_scen), int(seed))
        st.session_state["gbi_mc_assets"] = R_assets
        st.session_state["gbi_mc_assets_meta"] = {"n_scen": int(n_scen), "seed": int(seed), "months": int(M_months), "T_years": int(T_years), "fingerprint": st.session_state.get("gbi_fp")}
        st.success("Scenari Monte Carlo (Asset Class) generati e salvati in sessione.")

    # --- GA (accelerato + UX) ---
    # NOTE: Streamlit non consente di "cliccare" bottoni mentre un singolo run è in esecuzione.
    # Per offrire progress, grafici live e la possibilità di interrompere, eseguiamo il GA "a chunk":
    # ogni run calcola un numero limitato di generazioni e poi fa rerun automatico.
    if run_ok:
        if "gbi_mc_assets" not in st.session_state:
            st.warning("Prima generi gli scenari Monte Carlo (pulsante 1).")
        else:
            R_assets = np.asarray(st.session_state["gbi_mc_assets"], dtype=float)
            if R_assets.ndim != 3 or R_assets.shape[2] != M_months:
                st.warning("Gli scenari presenti in sessione non sono coerenti con l’orizzonte corrente. Rigeneri gli scenari.")
            else:
                # Parametri performance / stop
                stall_limit = 300
                hard_max_gen = 800
                screening_scen = 300          # come da decisione
                full_scen = int(n_scen)       # tipicamente 1000
                early_stop_check = 200        # come da specifica
                keep_frac_full = 0.40         # % popolazione valutata su full_scen

                # Popolazione adattiva
                base_pop = int(pop_size) if int(pop_size) > 0 else 200
                pop_small = min(150, base_pop)

                # Probabilità GA (come da specifica)
                pc_threshold = 0.55  # se u < 0.55 -> NO crossover
                pm_threshold = 0.70  # se u < 0.70 -> NO mutation

                # RNG
                rng = np.random.default_rng(int(seed))

                # Pre-calcolo rendimenti dei portafogli per scenario (evita einsum ripetuti)
                # R_pf: (S, H, M)
                R_pf = np.einsum("sam,ha->shm", R_assets, W_ports)
                R_pf_smH = R_pf.transpose(0, 2, 1)  # (S, M, H)

                def _eval_population_on_scenarios(population: np.ndarray,
                                                  scen_idx: np.ndarray,
                                                  best_fit_bound: float | None,
                                                  batch_size: int = 50) -> tuple[np.ndarray, np.ndarray]:
                    """
                    Valuta fitness su un sottoinsieme di scenari (scen_idx).
                    Implementa early stopping: dopo 'early_stop_check' scenari, se la probabilità massima
                    raggiungibile è < best_fit_bound, interrompe e ritorna un lower bound conservativo.
                    Ritorna:
                      - fitness (0..1) su len(scen_idx)
                      - std_final (dev std del capitale finale) su len(scen_idx) se completato; altrimenti inf
                    """
                    scen_idx = np.asarray(scen_idx, dtype=int)
                    S_total = int(scen_idx.size)
                    Pn, Y = population.shape

                    # Preparazione indici mensili per selezione H
                    idx_month = np.repeat(population - 1, 12, axis=1)  # (Pn, M)
                    if idx_month.shape[1] != M_months:
                        idx_month = idx_month[:, :M_months] if idx_month.shape[1] > M_months else np.pad(idx_month, ((0,0),(0, M_months-idx_month.shape[1])), mode="edge")
                    idx_month = idx_month[None, :, :, None]  # (1,Pn,M,1)

                    # Accumulatori
                    succ = np.zeros((Pn,), dtype=int)
                    seen = 0

                    # Per std_final (solo se completiamo)
                    final_wealth_all = []

                    # Scorri scenari a batch
                    for b0 in range(0, S_total, batch_size):
                        b1 = min(S_total, b0 + batch_size)
                        batch = scen_idx[b0:b1]
                        Sb = int(batch.size)

                        # Selezione rendimenti: (Sb, Pn, M)
                        R_stack = R_pf_smH[batch][:, None, :, :]          # (Sb,1,M,H)
                        sel = np.take_along_axis(R_stack, idx_month, axis=3).squeeze(3)  # (Sb,Pn,M)

                        wealth = np.full((Sb, Pn), float(initial_cap), dtype=float)
                        min_w = wealth.copy()

                        for m_ in range(M_months):
                            if cash_in is not None:
                                wealth += float(cash_in[m_])
                            wealth *= (1.0 + sel[:, :, m_])
                            if cash_out_all is not None:
                                wealth -= float(cash_out_all[m_])
                            min_w = np.minimum(min_w, wealth)

                        success = (min_w >= 0.0) & (wealth >= 0.0)  # (Sb,Pn)
                        succ += success.sum(axis=0).astype(int)
                        seen += Sb

                        # memorizzo wealth finali per std (solo se non useremo early stop)
                        final_wealth_all.append(wealth.copy())

                        # early stop check (dopo 200 scenari visti)
                        if best_fit_bound is not None and best_fit_bound >= 0 and seen >= int(early_stop_check):
                            # upper bound: succ + (S_total-seen) successi massimi
                            ub = (succ + (S_total - seen)) / float(S_total)
                            if np.all(ub < float(best_fit_bound) - 1e-12):
                                # impossibile battere best: ritorno lower bound conservativo (assumo fallimento sui rimanenti)
                                fit_lb = succ / float(S_total)
                                std_inf = np.full((Pn,), np.inf, dtype=float)
                                return fit_lb.astype(float), std_inf

                    # completato: fitness esatta su S_total e std_final
                    fit = succ / float(S_total)

                    wealth_all = np.concatenate(final_wealth_all, axis=0)  # (S_total, Pn)
                    std_final = wealth_all.std(axis=0, ddof=1) if S_total > 1 else np.zeros((Pn,), dtype=float)
                    return fit.astype(float), std_final.astype(float)

                # ---------- GA (premium progress UI, no Plotly during run) ----------
                # Mostriamo un pannello di avanzamento *leggero* (testo + progress bar + KPI),
                # evitando grafici Plotly live per prevenire duplicazioni di ID/Key.
                _ga_ui = st.container()
                with _ga_ui:
                    try:
                        _ga_status = st.status("Algoritmo Genetico in esecuzione…", expanded=True)
                    except Exception:
                        _ga_status = None

                    st.markdown(
                        """<div class='uw-card'>
                          <div style='display:flex;align-items:center;justify-content:space-between;gap:12px;'>
                            <div>
                              <div style='font-size:0.98rem;font-weight:700;'>Ottimizzazione dinamica in corso</div>
                              <div style='font-size:0.86rem;opacity:0.78;'>Valutazione popolazioni → ricerca della migliore strategia (vincolo di rischio non crescente).</div>
                            </div>
                            <div style='font-size:0.82rem;opacity:0.75;text-align:right;'>
                              <div><b>Stop</b>: {stall_limit} gen. senza miglioramento</div>
                              <div><b>Hard cap</b>: {hard_max_gen} generazioni</div>
                            </div>
                          </div>
                        </div>""".format(stall_limit=int(stall_limit), hard_max_gen=int(hard_max_gen)),
                        unsafe_allow_html=True,
                    )

                    _ga_prog = st.progress(0.0, text="Preparazione…")
                    _k1, _k2, _k3, _k4 = st.columns(4)
                    _ph_best = _k1.empty()
                    _ph_stall = _k2.empty()
                    _ph_elapsed = _k3.empty()
                    _ph_eta = _k4.empty()

                    _ui_last_update = 0.0
                    _ui_every = 3  # aggiorna UI ogni N generazioni (riduce overhead)
                    _t0 = time.time()

                # Durante l’elaborazione non viene mostrato alcun output; al termine vengono salvati i risultati in sessione.
                
                # Popolazione iniziale (ridotta) + valutazione screening
                pop = _init_population(pop_small, int(T_years), int(H), rng)
                S_avail = int(R_pf_smH.shape[0])
                scen_screen = np.arange(min(screening_scen, S_avail))
                fit, stdf = _eval_population_on_scenarios(pop, scen_screen, best_fit_bound=None)
                

                # baseline: best success prob in the FIRST evaluated population (used only for UI 'incremento')
                try:
                    baseline_fit = float(np.max(fit)) if fit is not None and len(fit) else 0.0
                except Exception:
                    baseline_fit = 0.0
                best_fit = -1.0
                best_std = float('inf')
                best_row = None
                stall = 0
                gen = 0
                
                while True:
                    gen += 1
                    # stop conditions
                    if stall >= int(stall_limit):
                        break
                    if gen > int(hard_max_gen):
                        break

                    # --- UI update (leggero) ---
                    if '_ga_prog' in locals():
                        try:
                            # progresso "soft": rispetto al hard cap (orientativo)
                            _p = min(0.99, max(0.0, float(gen) / float(max(1, int(hard_max_gen)))))
                            _elapsed = time.time() - _t0
                            _rate = _elapsed / float(max(1, gen))
                            _eta_sec = max(0.0, (float(max(1, int(hard_max_gen) - gen)) * _rate))
                            # aggiorna solo ogni _ui_every generazioni (o all'inizio)
                            if gen == 1 or (gen % int(_ui_every) == 0):
                                _ga_prog.progress(_p, text=f"Generazione {gen}/{int(hard_max_gen)} – valutazione in corso…")
                                _cur_best = float(best_fit) if (best_fit is not None and best_fit >= 0) else float(baseline_fit)
                                _inc = _cur_best - float(baseline_fit)
                                _ph_best.metric("Incremento Prob. successo", f"{_inc:+.1%}")
                                _ph_stall.metric("Stallo", f"{int(stall)}/{int(stall_limit)}")
                                _ph_elapsed.metric("Tempo trascorso", f"{int(_elapsed//60)}m {int(_elapsed%60)}s")
                                _ph_eta.metric("Tempo stimato residuo", f"{int(_eta_sec//60)}m {int(_eta_sec%60)}s")
                        except Exception:
                            pass
                
                    # best of current population (tie-break: min std finale)
                    fmax = float(fit.max()) if fit.size else -1.0
                    cand_idx = np.where(fit == fmax)[0] if fit.size else np.array([], dtype=int)
                    if cand_idx.size > 1:
                        j = int(cand_idx[np.nanargmin(stdf[cand_idx])])
                    elif cand_idx.size == 1:
                        j = int(cand_idx[0])
                    else:
                        j = 0
                
                    improved = False
                    if best_row is None:
                        improved = True
                    else:
                        if (fmax > float(best_fit) + 1e-12) or (abs(fmax - float(best_fit)) < 1e-12 and float(stdf[j]) < float(best_std) - 1e-12):
                            improved = True
                
                    if improved:
                        best_fit = fmax
                        best_std = float(stdf[j])
                        best_row = pop[j].copy()
                        stall = 0
                    else:
                        stall += 1
                
                    # Popolazione adattiva: gen 1-2 (pop_small), >=3 (base_pop)
                    target_pop = pop_small if gen <= 2 else base_pop
                    if pop.shape[0] != int(target_pop):
                        if pop.shape[0] < int(target_pop):
                            extra = _init_population(int(target_pop) - pop.shape[0], int(T_years), int(H), rng)
                            pop = np.vstack([pop, extra])
                            extra_fit, extra_std = _eval_population_on_scenarios(extra, scen_screen, best_fit_bound=float(best_fit))
                            fit = np.concatenate([fit, extra_fit])
                            stdf = np.concatenate([stdf, extra_std])
                        else:
                            pop = pop[:int(target_pop)]
                            fit = fit[:int(target_pop)]
                            stdf = stdf[:int(target_pop)]
                
                    # Nuova popolazione con elitismo
                    elite = (best_row.copy() if best_row is not None else pop[j].copy())
                    new_pop = [elite.copy()]
                    toggle = True
                    while len(new_pop) < int(target_pop):
                        if toggle:
                            # CROSSOVER
                            i1 = _roulette_select_idx(fit, rng)
                            i2 = _roulette_select_idx(fit, rng)
                            p1 = pop[i1].copy()
                            p2 = pop[i2].copy()
                            u = float(rng.random())
                            if u < pc_threshold or int(T_years) <= 1:
                                new_pop.append(p1)
                                if len(new_pop) < int(target_pop):
                                    new_pop.append(p2)
                            else:
                                cut = int(rng.integers(1, int(T_years)))
                                c1 = np.concatenate([p1[:cut], p2[cut:]])
                                c2 = np.concatenate([p2[:cut], p1[cut:]])
                                ok1 = np.all(c1[1:] <= c1[:-1])
                                ok2 = np.all(c2[1:] <= c2[:-1])
                                if ok1:
                                    new_pop.append(c1.astype(int))
                                if len(new_pop) < int(target_pop) and ok2:
                                    new_pop.append(c2.astype(int))
                                if (not ok1) and (not ok2):
                                    new_pop.append(_repair_nonincreasing(c1))
                        else:
                            # MUTATION
                            i = _roulette_select_idx(fit, rng)
                            p = pop[i].copy()
                            u = float(rng.random())
                            if u < pm_threshold or int(T_years) <= 0:
                                new_pop.append(p)
                            else:
                                pos = int(rng.integers(0, int(T_years)))
                                delta = int(rng.integers(-2, 3))
                                if delta == 0:
                                    delta = 1
                                p[pos] = int(np.clip(p[pos] + delta, 1, int(H)))
                                p = _repair_nonincreasing(p)
                                new_pop.append(p)
                        toggle = not toggle
                
                    pop = np.vstack(new_pop[:int(target_pop)])
                
                    # ---------- Fitness a due stadi ----------
                    fit_screen, std_screen = _eval_population_on_scenarios(pop, scen_screen, best_fit_bound=float(best_fit))
                    k_full = max(1, int(math.ceil(float(target_pop) * float(keep_frac_full))))
                    top_idx = np.argsort(-fit_screen)[:k_full]
                    scen_full = np.arange(min(full_scen, S_avail))
                    fit_full, std_full = _eval_population_on_scenarios(pop[top_idx], scen_full, best_fit_bound=float(best_fit))
                    fit = fit_screen.copy()
                    stdf = std_screen.copy()
                    fit[top_idx] = fit_full
                    stdf[top_idx] = std_full
                
                # Salvataggio risultato (se esiste)
                if best_row is not None:
                    # --- Ricalcolo esatto della probabilità sul BEST (coerenza con sezioni per priorità) ---
                    try:
                        fit_exact, _ = _evaluate_population(
                            np.asarray(best_row, dtype=int)[:int(T_years)][None, :],
                            R_assets,
                            W_ports,
                            float(initial_cap),
                            cash_in,
                            cash_out_all
                        )
                        best_fit = float(fit_exact[0])
                    except Exception:
                        pass

                    st.session_state['gbi_ga_run_id'] = int(st.session_state.get('gbi_ga_run_id', 0)) + 1
                    st.session_state['gbi_ga_best'] = {
                        'best_row': np.asarray(best_row, dtype=int),
                        'best_fit': float(best_fit),
                        'best_std_final': float(best_std),
                        'ports_ordered': ports_ordered,
                        'T_years': int(T_years),
                        'run_id': int(st.session_state['gbi_ga_run_id']),
                        'fingerprint': st.session_state.get('gbi_fp'),
                    }
                    try:
                        if '_ga_prog' in locals():
                            _ga_prog.progress(1.0, text="Completato.")
                        if _ga_status is not None:
                            _ga_status.update(label="Algoritmo Genetico completato", state="complete", expanded=False)
                    except Exception:
                        pass
                    st.success(f"Ottimizzazione completata. Probabilità di successo (tutti gli obiettivi): {float(best_fit):.1%}")
    # --- Visualizzazione risultati se presenti ---
    if "gbi_ga_best" in st.session_state and (st.session_state["gbi_ga_best"].get("fingerprint") in (None, st.session_state.get("gbi_fp"))):
        res = st.session_state["gbi_ga_best"]
        best_row = np.asarray(res.get("best_row"), dtype=int).reshape(-1)
        best_fit = float(res.get("best_fit", 0.0))
        ports_ordered = list(res.get("ports_ordered", []))
        T_years_res = int(res.get("T_years", T_years))

        st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
        st.markdown('<div class="uw-sec-title-sm">Risultato: strategia dinamica ottimale</div>', unsafe_allow_html=True)

        # (1) Line chart: indice del portafoglio nel tempo
        df_line = pd.DataFrame({"Anno": np.arange(1, T_years_res + 1), "Indice Portafoglio": best_row[:T_years_res]})
        fig_line = px.line(df_line, x="Anno", y="Indice Portafoglio", markers=True)
        fig_line.update_traces(
            line=dict(color="rgba(243,156,18,0.8)", width=3),
            marker=dict(size=20, color="rgba(243,156,18,0.8)")
        )
        fig_line.update_layout(margin=dict(l=10, r=10, t=30, b=10), yaxis=dict(dtick=1))
        st.plotly_chart(fig_line, use_container_width=True, key=f"gbi_ga_result_line_{int(res.get('run_id',0))}")

        # (2) Area chart: composizione per Asset Class nel tempo (annuale)
        try:
            idx0 = np.clip(best_row[:T_years_res] - 1, 0, H - 1)
            W_year = W_ports[idx0, :]  # (T_years, assets)
            df_area = pd.DataFrame(W_year, columns=asset_names)
            df_area["Anno"] = np.arange(1, T_years_res + 1)
            longA = df_area.melt(id_vars=["Anno"], var_name="Asset Class", value_name="Peso")
            fig_area = px.area(longA, x="Anno", y="Peso", color="Asset Class")
            fig_area.update_layout(
                margin=dict(l=10, r=10, t=30, b=10),
                yaxis_tickformat=".0%",
                xaxis=dict(dtick=1),
                title="Evoluzione della composizione per Asset Class (annuale)"
            )
            st.plotly_chart(fig_area, use_container_width=True, key=f"gbi_ga_result_area_{int(res.get('run_id',0))}")
        except Exception:
            st.info("Impossibile costruire il grafico ad area della composizione per Asset Class.")

        # (3) Probabilità di successo + icona meteo (PNG reali)
        def _resolve_local_png(filename: str) -> str:
            """Ritorna un path assoluto robusto per immagini locali."""
            try:
                base_dir = os.path.dirname(__file__)
            except Exception:
                base_dir = os.getcwd()
            return os.path.join(base_dir, filename)

        def _meteo_icon_from_probability(p: float):
            """p: probabilità di successo (0–1). Ritorna (path_png, label)."""
            if p > 0.90:
                return _resolve_local_png("Prob Sole Pieno.png"), "Probabilità di successo molto elevata"
            if p > 0.80:
                return _resolve_local_png("Prob Poco Nuvoloso.png"), "Probabilità di successo elevata"
            if p > 0.65:
                return _resolve_local_png("Prob Nuvoloso.png"), "Probabilità di successo buona"
            if p > 0.50:
                return _resolve_local_png("Prob Molto Nuvoloso.png"), "Probabilità di successo discreta"
            if p > 0.40:
                return _resolve_local_png("Prob Pioggia.png"), "Probabilità di successo bassa"
            return _resolve_local_png("Prob Fulmini.png"), "Probabilità di successo molto bassa"

        # --- Coerenza: ricalcolo la probabilità "tutti gli obiettivi" con la stessa identica logica dei cumulati ---
        best_fit_display = best_fit
        try:
            if "gbi_mc_assets" in st.session_state:
                R_assets = np.asarray(st.session_state["gbi_mc_assets"], dtype=float)
                if R_assets.ndim == 3:
                    pr_list_all = sorted({int(ob.get("priority", 999999)) for ob in (objectives_all or [])})
                    pr_list_all = [p for p in pr_list_all if p < 999999]
                    # Se esistono priorità, "tutti gli obiettivi" equivale a "fino alla priorità massima"
                    upto_p = max(pr_list_all) if pr_list_all else None
                    cash_out_all = _build_monthly_outflows_from_objectives(objectives_all, T_years_res, upto_priority=upto_p)
                    fit_all, std_all = _evaluate_population(
                        best_row[:T_years_res][None, :],
                        R_assets,
                        W_ports,
                        initial_cap,
                        cash_in,
                        cash_out_all
                    )
                    best_fit_display = float(fit_all[0])
                    # sincronizzo anche il valore salvato (solo coerenza dati; la grafica resta identica)
                    try:
                        st.session_state["gbi_ga_best"]["best_fit"] = best_fit_display
                    except Exception:
                        pass
        except Exception:
            best_fit_display = best_fit

        icon_file, icon_label = _meteo_icon_from_probability(best_fit_display)
        c1, c2 = st.columns([1, 4])
        with c1:
            if os.path.exists(icon_file):
                st.image(icon_file, width=110)
            else:
                st.write("⚠️ Icona meteo non trovata")
        with c2:
            st.markdown(
                f'<div class="uw-card">'
                f'<div style="font-size:18px; font-weight:800; margin:0 0 6px 0;">Probabilità di successo (tutti gli obiettivi)</div>'
                f'<p style="font-size:22px;"><b>{best_fit_display*100:.1f}%</b></p>'
                f'<p style="margin-top:-8px; color:#6b7280;">{icon_label}</p>'
                f'</div>',
                unsafe_allow_html=True
            )

        # Probabilità di successo cumulata per priorità (1, 1+2, 1+2+3, ...)
        if "gbi_mc_assets" in st.session_state:
            R_assets = np.asarray(st.session_state["gbi_mc_assets"], dtype=float)
            if R_assets.ndim == 3:
                try:
                    # recupero set di priorità in ordine
                    pr_list = sorted({int(ob.get("priority", 999999)) for ob in (objectives_all or [])})
                    pr_list = [p for p in pr_list if p < 999999]
                    if pr_list:
                        rows_pr = []
                        st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)
                        st.markdown('<div class="uw-sec-title-sm">Probabilità di successo per obiettivi cumulati (per priorità)</div>', unsafe_allow_html=True)

                        for pmax in pr_list:
                            cash_out_p = _build_monthly_outflows_from_objectives(objectives_all, T_years_res, upto_priority=pmax)
                            # Valuto solo la strategia migliore
                            fit1, std1 = _evaluate_population(best_row[:T_years_res][None, :], R_assets, W_ports, initial_cap, cash_in, cash_out_p)
                            pr_success = float(fit1[0])
                            icon_p, label_p = _meteo_icon_from_probability(pr_success)

                            cc1, cc2 = st.columns([1, 4])
                            with cc1:
                                if os.path.exists(icon_p):
                                    st.image(icon_p, width=90)
                                else:
                                    st.write("⚠️")
                            with cc2:
                                st.markdown(
                                    f"**Obiettivi fino alla priorità {pmax}:** {pr_success*100:.1f}%  ",
                                )
                                st.caption(label_p)

                            rows_pr.append({"Obiettivi fino a priorità": pmax, "Probabilità di successo": pr_success})

                        # Tabella di riepilogo (senza immagini)
                        df_pr = pd.DataFrame(rows_pr)
                        st.dataframe(df_pr.style.format({"Probabilità di successo": "{:.1%}"}), use_container_width=True)
                        # -----------------------
                        # Traiettorie del montante (strategia ottima) – 250 scenari + percentili 10/50/90
                        # -----------------------
                        try:
                            # Ricostruisco i rendimenti del portafoglio per scenario e per scelta annuale (H)
                            H = int(W_ports.shape[0])  # numero portafogli disponibili (azioni GA)
                            M_months = int(T_years_res) * 12
                            # cash-out per *tutti* gli obiettivi (ultima priorità) per costruire il montante netto
                            cash_out_all = _build_monthly_outflows_from_objectives(objectives_all, T_years_res, upto_priority=max(pr_list))

                            R_pf = np.einsum("sam,ha->shm", R_assets, W_ports)  # (S, H, M)
                            R_pf_smH = R_pf.transpose(0, 2, 1)                 # (S, M, H)
                            idx_month_best = np.repeat(best_row[:T_years_res] - 1, 12)[:M_months]  # (M,)
                            idx_month_best = np.clip(idx_month_best.astype(int), 0, H - 1)
                            S_total = int(R_assets.shape[0])
                            m_idx = np.arange(M_months, dtype=int)[None, :]
                            s_idx = np.arange(S_total, dtype=int)[:, None]
                            sel_r = R_pf_smH[s_idx, m_idx, idx_month_best[None, :]]  # (S, M)
                            # Simulazione wealth mensile (t=0..M)
                            wealth = np.full(S_total, float(initial_cap), dtype=float)
                            paths_w = np.zeros((S_total, M_months + 1), dtype=float)
                            paths_w[:, 0] = wealth
                            for m_ in range(M_months):
                                if cash_in is not None:
                                    wealth += float(cash_in[m_])
                                wealth *= (1.0 + sel_r[:, m_])
                                if cash_out_all is not None:
                                    wealth -= float(cash_out_all[m_])
                                paths_w[:, m_ + 1] = wealth
                        
                            x = (np.arange(M_months + 1, dtype=float) / 12.0)  # anni
                        
                            # Percentili calcolati su TUTTI gli scenari (tipicamente 1.000)
                            p10 = np.percentile(paths_w, 10, axis=0)
                            p50 = np.percentile(paths_w, 50, axis=0)
                            p90 = np.percentile(paths_w, 90, axis=0)
                        
                            # Seleziono 250 traiettorie per visualizzazione
                            n_show = min(250, S_total)
                            rng_show = np.random.default_rng(12345)
                            show_idx = rng_show.choice(np.arange(S_total), size=n_show, replace=False) if S_total > n_show else np.arange(S_total)
                        
                            def _concat_paths_idx(idxs: np.ndarray):
                                xs, ys = [], []
                                for i in idxs:
                                    xs.extend(x.tolist())
                                    ys.extend(paths_w[int(i), :].tolist())
                                    xs.append(None); ys.append(None)
                                return xs, ys
                        
                            xs_g, ys_g = _concat_paths_idx(show_idx)
                            fig_dyn = go.Figure()
                            fig_dyn.add_trace(go.Scatter(
                                x=xs_g, y=ys_g,
                                mode="lines",
                                line=dict(width=1, color="rgba(120,120,120,0.14)"),
                                name="Scenari (250)",
                                hoverinfo="skip",
                            ))
                            fig_dyn.add_trace(go.Scatter(
                                x=x, y=p90, mode="lines",
                                line=dict(width=3, color="green"),
                                name="Ottimistico (90° percentile)",
                            ))
                            fig_dyn.add_trace(go.Scatter(
                                x=x, y=p50, mode="lines",
                                line=dict(width=3, color="blue"),
                                name="Atteso (50° percentile)",
                            ))
                            fig_dyn.add_trace(go.Scatter(
                                x=x, y=p10, mode="lines",
                                line=dict(width=3, color="red"),
                                name="Pessimistico (10° percentile)",
                            ))
                        
                            # Nota: ys_g contiene separatori None (per spezzare le traiettorie). Per evitare errori
                            # nei min/max, uso direttamente i valori numerici di paths_w sulle traiettorie mostrate.
                            _show_vals = paths_w[show_idx, :]
                            y_min = float(np.nanmin([np.nanmin(p10), np.nanmin(_show_vals), 0.0]))
                            y_max = float(np.nanmax([np.nanmax(p90), np.nanmax(_show_vals)]))
                            pad = 0.06 * (y_max - y_min) if y_max > y_min else 1.0
                        
                            fig_dyn.update_layout(
                                title="Evoluzione del montante (strategia ottima) – scenari e percentili",
                                xaxis_title="Tempo (anni)",
                                yaxis_title="Montante (€)",
                                margin=dict(l=10, r=10, t=60, b=10),
                                yaxis=dict(range=[y_min - pad, y_max + pad], automargin=True, showgrid=True, gridcolor="rgba(0,0,0,0.08)", zeroline=False),
                                xaxis=dict(automargin=True, showgrid=True, gridcolor="rgba(0,0,0,0.08)", zeroline=False),
                                hovermode="x unified",
                                plot_bgcolor="white",
                                paper_bgcolor="white",
                                legend_title_text="",
                                legend=dict(orientation="v", yanchor="top", y=1.0, xanchor="left", x=1.02, bgcolor="rgba(255,255,255,0.75)", bordercolor="rgba(0,0,0,0.12)", borderwidth=1, font=dict(size=10)),
                            )
                        
                            st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
                            st.plotly_chart(fig_dyn, use_container_width=True)
                        
                            # Tabella percentili per anno
                            year_ends = [(y_i + 1) * 12 for y_i in range(T_years_res)]
                            tbl = [{"Anno": 0, "10° percentile (€)": float(p10[0]), "50° percentile (€)": float(p50[0]), "90° percentile (€)": float(p90[0])}]
                            for y_i, t_end in enumerate(year_ends, start=1):
                                tbl.append({
                                    "Anno": y_i,
                                    "10° percentile (€)": float(np.percentile(paths_w[:, t_end], 10)),
                                    "50° percentile (€)": float(np.percentile(paths_w[:, t_end], 50)),
                                    "90° percentile (€)": float(np.percentile(paths_w[:, t_end], 90)),
                                })
                            df_tbl = pd.DataFrame(tbl)
                            df_tbl_fmt = df_tbl.copy()
                            for c in ["10° percentile (€)", "50° percentile (€)", "90° percentile (€)"]:
                                df_tbl_fmt[c] = df_tbl_fmt[c].map(lambda v: f"{v:,.0f}".replace(",", "."))
                        
                            st.markdown('<div class="uw-sec-title-sm">Sintesi per anno (percentili 10/50/90)</div>', unsafe_allow_html=True)
                            st.dataframe(df_tbl_fmt, use_container_width=True, hide_index=True)
                        
                            # Persisto per evitare scomparsa al rerun
                            st.session_state["gbi_dyn_last_fig"] = fig_dyn
                            st.session_state["gbi_dyn_last_table"] = df_tbl_fmt
                        except Exception as e:
                            st.info("Impossibile costruire le traiettorie del montante per la strategia ottima.")
                            st.caption(f"Dettaglio tecnico: {type(e).__name__}: {e}")

                except Exception:
                    st.info("Impossibile calcolare la probabilità di successo per obiettivi cumulati.")




    # -----------------------
    # Salvataggio portafoglio dinamico (Goal-Based Investing)
    # -----------------------
    st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)
    if st.button("Salva", type="primary", key="gbi_save_dynamic_btn"):
        if portfolio_name.strip() == "":
            st.error("Inserire un Nome per il Portafoglio prima di salvare.")
        else:
            # Richiedo che esista una soluzione GA valida
            best_ga = st.session_state.get("gbi_ga_best", None)
            if (best_ga is None) or (best_ga.get("best_row") is None) or (best_ga.get("best_fit") is None):
                st.error("Eseguire prima l’Algoritmo Genetico per generare una soluzione dinamica.")
            else:
                best_row_to_save = best_ga.get("best_row")
                best_fit_to_save = best_ga.get("best_fit")

                # --- Costruisco e salvo anche la composizione (t=0) e la traiettoria dei pesi (dinamica) ---
                comp_w0 = {}
                comp_path_records = None
                try:
                    _asset_names = list(st.session_state.get("gbi_asset_names", []))
                    _W_ports = st.session_state.get("gbi_W_ports", None)
                    _T_years = int(best_ga.get("T_years", 0) or 0)
                    _best_row = np.asarray(best_row_to_save, dtype=int).reshape(-1)
                    if _W_ports is not None and isinstance(_asset_names, list) and len(_asset_names) > 0 and _T_years > 0 and _best_row.size > 0:
                        _H = int(_W_ports.shape[0])
                        _idx = np.clip(_best_row[:_T_years] - 1, 0, _H - 1)
                        _W_year = np.asarray(_W_ports[_idx, :], dtype=float)  # (T_years, assets)
                        # t=0: uso la prima allocazione annuale come composizione iniziale
                        comp_w0 = {str(a): float(max(w, 0.0)) for a, w in zip(_asset_names, _W_year[0].tolist())}
                        # normalizzazione
                        _s0 = float(sum(comp_w0.values()))
                        if _s0 > 0:
                            comp_w0 = {k: v/_s0 for k, v in comp_w0.items()}
                        # traiettoria: includo anche Anno=0
                        comp_path_records = []
                        rec0 = {"Anno": 0}
                        rec0.update({str(a): float(max(w, 0.0)) for a, w in zip(_asset_names, _W_year[0].tolist())})
                        comp_path_records.append(rec0)
                        for t in range(_T_years):
                            rec = {"Anno": int(t+1)}
                            rec.update({str(a): float(max(w, 0.0)) for a, w in zip(_asset_names, _W_year[t].tolist())})
                            comp_path_records.append(rec)
                except Exception:
                    comp_w0 = {}
                    comp_path_records = None

                base_id = f"{client_key}::{portfolio_name}"
                pid = base_id
                k = 2
                while pid in st.session_state.get("portfolios", {}):
                    pid = f"{base_id} ({k})"
                    k += 1

                payload = {
                    "id": pid,
                    "client_key": client_key,
                    "portfolio_name": portfolio_name,
                    "objective": "Goal-Based Investing",
                    "horizon_years": int(horizon_years),
                    "initial_amount": float(initial_amount),
                    "periodic_amount": float(periodic_amount),
                    "periodic_freq": freq,
                    "periodic_years": int(periodic_years),
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    # elementi GBI (dinamica)
                    "gbi": True,
                    "gbi_objectives": objectives_all,
                    "gbi_strategy_best_row": list(map(int, best_row_to_save)),
                    "gbi_best_success_prob": float(best_fit_to_save),
                    "gbi_asset_selection": selected_set_name,
                    "composition": comp_w0,
                    "composition_path": comp_path_records,
                }

                st.session_state.setdefault("portfolios", {})
                st.session_state["portfolios"][pid] = payload
                st.session_state.setdefault("client_portfolios", {})
                st.session_state["client_portfolios"].setdefault(client_key, [])
                st.session_state["client_portfolios"][client_key].append(pid)

                persist_portfolios_from_session()
                st.success(f'Portafoglio dinamico "{portfolio_name}" salvato correttamente per il cliente selezionato.')
# Sezione principale (navigazione reale)
# =======================
ensure_anagrafica_storage()
main_section, tools_sub, crea_sub = top_nav_controls()

# =======================
# Header (sempre definito)
# =======================
_SECTION_TITLES = {
    "Clienti/Investitori": "Clienti/Investitori",
    "Crea Soluzione di Investimento": "Crea Soluzione di Investimento",
    "Selezione Prodotti": "Selezione Prodotti",
    "Monitoraggio Portafoglio": "Monitoraggio Portafoglio",
    "Analisi Asset Allocation": "Analisi Asset Allocation",
    "Tools": "Tools",
}

header_title = _SECTION_TITLES.get(main_section, str(main_section))
header_desc = ""

if main_section == "Tools":
    _tools_desc = {
        "Griglie Clientela": (
            "Creazione e gestione di diverse tipologie di segmenti di clientela. Ogni classe è identificata da un <b>Nome</b>. "
            "L’utente può creare una nuova classe, modificarne una preesistente, eliminarla e poi salvarla."
        ),
        "Portafogli in Asset Class": (
            "Creazione e gestione di set di Asset Allocation in termini di asset class, input di mercato (rendimenti, volatilità, correlazioni) "
            "e composizioni dei portafogli."
        ),
        "Database Mercati": "Caricamento e salvataggio del Database Mercati (serie storiche dei rendimenti) utilizzabile nelle analisi.",
        "Database Prodotti": "Caricamento e salvataggio del Database Prodotti (universo ETF/fondi e metriche) utilizzabile nella selezione AI dei prodotti.",
    }
    header_title = f"Tools → {tools_sub}"
    header_desc = _tools_desc.get(tools_sub, "Strumenti operativi dell’applicazione.")
elif main_section == "Crea Soluzione di Investimento":
    header_title = f"Crea Soluzione di Investimento → {crea_sub}"
    header_desc = (
        "Costruzione di una soluzione di investimento in modalità <b>Asset-Only</b>."
        if crea_sub == "Asset-Only"
        else
        "Costruzione di una soluzione dinamica <b>Goal-Based Investing</b> (Monte Carlo + Algoritmo Genetico)."
    )
elif main_section == "Selezione Prodotti":
    header_title = "Selezione Prodotti"
    header_desc = (
        "Selezione e trasformazione di un portafoglio in asset class in un portafoglio di prodotti (ETF/fondi), "
        "con selezione guidata e componente AI percepibile."
    )
elif main_section == "Monitoraggio Portafoglio":
    header_title = "Monitoraggio Portafoglio"
    header_desc = "Monitoraggio del portafoglio: andamento, scostamenti, alert e reportistica di controllo."
elif main_section == "Analisi Asset Allocation":
    header_title = "Analisi Asset Allocation"
    header_desc = "Analisi dell’asset allocation: metriche, backtesting, rischio/rendimento e indicatori."
else:
    # Clienti/Investitori
    header_title = "Clienti/Investitori"
    header_desc = "Gestione dell’anagrafica clienti/investitori e delle informazioni utili alla profilazione."


# =======================
# Breadcrumb (dinamico)
# =======================
if main_section == "Tools":
    breadcrumb_html = f'<span>Tools</span><div class="uw-dot"></div><span>{tools_sub}</span>'
elif main_section == "Crea Soluzione di Investimento":
    breadcrumb_html = f'<span>Crea Soluzione di Investimento</span><div class="uw-dot"></div><span>{crea_sub}</span>'
elif main_section == "Selezione Prodotti":
    breadcrumb_html = '<span>Selezione Prodotti</span>'
elif main_section == "Analisi Asset Allocation":
    breadcrumb_html = '<span>Analisi Asset Allocation</span>'
else:
    breadcrumb_html = '<span>Clienti/Investitori</span>'

st.markdown(
    f"""
    <div class="uw-content">
      <div class="uw-breadcrumb">
        {breadcrumb_html}
      </div>
      <div class="uw-shell">
        <div class="uw-shell-header">
          <div class="uw-title">
            <h1>{header_title} <span class="uw-badge">UI</span></h1>
            <p>{header_desc}</p>
          </div>
        </div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="uw-content">', unsafe_allow_html=True)

# =======================
# Routing (render) per sezione principale
# =======================
if main_section == "Clienti/Investitori":
    render_anagrafica()
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

elif main_section == "Crea Soluzione di Investimento":
    if crea_sub == "Asset-Only":
        render_crea_portafoglio()
    else:
        render_crea_soluzione_gbi()
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

elif main_section == "Selezione Prodotti":
    render_selezione_prodotti()
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

elif main_section == "Monitoraggio Portafoglio":
    render_monitoraggio_portafoglio()
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

elif main_section == "Analisi Asset Allocation":
    render_analisi_portafoglio()
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()
# Sezione Tools: routing sottosezioni che hanno una pagina dedicata
if main_section == "Tools":
    if tools_sub == "Portafogli in Asset Class":
        render_selezione_asset_class()
        st.markdown("</div>", unsafe_allow_html=True)
        st.stop()

    if tools_sub == "Database Mercati":
        render_database_mercati()
        st.markdown("</div>", unsafe_allow_html=True)
        st.stop()

    if tools_sub == "Database Prodotti":
        render_database_prodotti()
        st.markdown("</div>", unsafe_allow_html=True)
        st.stop()

# =======================
# Scelta: crea nuova / modifica esistente
# =======================
st.markdown(
    '<div class="uw-card"><h2>Selezione operazione</h2>'
    '<p>Scelga se creare una nuova Griglia oppure modificare/cancellare una Griglia preesistente.</p></div>',
    unsafe_allow_html=True
)

mode = st.radio(
    "Operazione",
    ["Crea una nuova Griglia", "Modifica/Cancella una Griglia preesitente"],
    horizontal=True,
    key="mode_radio"
)

class_name = ""
selected_existing = None

if mode == "Crea una nuova Griglia":
    class_name = st.text_input("Nome della nuova Griglia", value="", key="new_class_name")
else:
    existing_names = sorted(list(st.session_state["client_classes"].keys()))
    if len(existing_names) == 0:
        st.info("Non esistono ancora Griglie salvate. Crei una nuova Griglia per iniziare.")
        # Forzo a creare nuova (solo UI)
        class_name = st.text_input("Nome della nuova Griglia", value="", key="new_class_name_fallback")
        mode = "Crea una nuova Griglia"
    else:
        selected_existing = st.selectbox("Selezioni la Griglia da modificare", existing_names, key="existing_select")
        class_name = selected_existing

        if st.button("Carica griglia selezionata", key="load_btn"):
            load_to_form(st.session_state["client_classes"][selected_existing])
            st.success("Griglia caricata. Può modificarla e poi salvare.")

# Pulsante ELIMINA (solo in modalità modifica)
del_cols = st.columns([0.25, 0.75])
with del_cols[0]:
    delete_clicked = st.button("Elimina griglia selezionata", type="secondary", key="delete_btn")
with del_cols[1]:
    st.caption("Attenzione: l’eliminazione rimuove la Griglia dall’elenco delle Griglie salvate (demo: sessione corrente).")

if delete_clicked and selected_existing:
    st.session_state["client_classes"].pop(selected_existing, None)
    st.success(f'Griglia "{selected_existing}" eliminata correttamente.')

    # Pulizia minima dello stato UI (per evitare riferimenti a una classe eliminata)
    st.session_state.pop("existing_select", None)
    st.rerun()

st.markdown('<div style="height:6px;"></div>', unsafe_allow_html=True)

# =======================
# Default standard per nuova Griglia: 3 classi di orizzonte temporale
# =======================
# Requisito: in creazione di una nuova Griglia, la soluzione standard deve prevedere:
#   - Breve: 0-5 anni
#   - Medio: 5-10 anni
#   - Lungo: >10 anni
if mode == "Crea una nuova Griglia":
    # Inizializzo solo se non già impostato (per non sovrascrivere scelte dell’utente su rerun)
    if "hor_n" not in st.session_state:
        st.session_state["hor_n"] = 3

    # Se non ci sono nomi/interval già in session_state, imposto lo standard
    if all(k not in st.session_state for k in ["hor_name_0", "hor_name_1", "hor_name_2"]):
        st.session_state["hor_name_0"] = "Breve"
        st.session_state["hor_from_0"] = 0
        st.session_state["hor_to_0"] = 5

        st.session_state["hor_name_1"] = "Medio"
        st.session_state["hor_from_1"] = 5
        st.session_state["hor_to_1"] = 10

        st.session_state["hor_name_2"] = "Lungo"
        st.session_state["hor_from_2"] = 10

# =======================
# 1) Classi di Rischio
# =======================
st.markdown(
    '<div class="uw-card"><h2>1) Classi di Rischio</h2>'
    '<p>Scelga quante classi (2–10) e assegni un nome a ciascuna.</p></div>',
    unsafe_allow_html=True
)

risk_n = st.number_input(
    "Numero classi di rischio",
    min_value=2, max_value=10, value=int(st.session_state.get("risk_n", 4)),
    step=1, key="risk_n"
)

risk_defaults = default_risk_names(int(risk_n))
risk_names = []
for i in range(int(risk_n)):
    # se già presente in session_state (es. da load), lo userà come default
    default_val = st.session_state.get(f"risk_name_{i}", risk_defaults[i] if i < len(risk_defaults) else f"Classe {i+1}")
    risk_names.append(
        st.text_input(f"Nome classe di rischio {i+1}", value=default_val, key=f"risk_name_{i}")
    )

# =======================
# 2) Classi di Orizzonte Temporale
# =======================
st.markdown(
    '<div class="uw-card"><h2>2) Classi di Orizzonte Temporale</h2>'
    '<p>Scelga quante classi temporali (1–10) e definisca l’intervallo (anni) per ciascuna.</p></div>',
    unsafe_allow_html=True
)

hor_n = st.number_input(
    "Numero classi di orizzonte temporale",
    min_value=1, max_value=10, value=int(st.session_state.get("hor_n", 3)),
    step=1, key="hor_n"
)

hor_defaults = default_horizon_names(int(hor_n))
horizons = []
for i in range(int(hor_n)):
    is_last = (i == int(hor_n) - 1)

    # ultima riga: niente "A (anni)", ma "> X"
    if not is_last:
        c1, c2, c3 = st.columns([0.46, 0.27, 0.27], gap="small")
        with c1:
            default_hn = st.session_state.get(
                f"hor_name_{i}",
                hor_defaults[i] if i < len(hor_defaults) else f"Orizzonte {i+1}"
            )
            hn = st.text_input(f"Nome orizzonte {i+1}", value=default_hn, key=f"hor_name_{i}")
        with c2:
            default_y0 = int(st.session_state.get(f"hor_from_{i}", 0 if i == 0 else i * 3))
            y0 = st.number_input(f"Da (anni) {i+1}", min_value=0, max_value=200, value=default_y0, step=1, key=f"hor_from_{i}")
        with c3:
            default_y1 = int(st.session_state.get(f"hor_to_{i}", (3 if i == 0 else i * 3 + 3)))
            y1 = st.number_input(f"A (anni) {i+1}", min_value=0, max_value=200, value=default_y1, step=1, key=f"hor_to_{i}")
        horizons.append((hn, int(y0), int(y1)))

    else:
        c1, c2 = st.columns([0.58, 0.42], gap="small")
        with c1:
            default_hn = st.session_state.get(
                f"hor_name_{i}",
                hor_defaults[i] if i < len(hor_defaults) else f"Orizzonte {i+1}"
            )
            hn = st.text_input(f"Nome orizzonte {i+1}", value=default_hn, key=f"hor_name_{i}")
        with c2:
            default_y0 = int(st.session_state.get(f"hor_from_{i}", 5))
            y0 = st.number_input(f"Soglia (anni) {i+1}", min_value=0, max_value=200, value=default_y0, step=1, key=f"hor_from_{i}")

        # Per l'ultima classe, y1 è None (non usato)
        horizons.append((hn, int(y0), None))

# Labels righe/colonne
col_labels = [rn.strip() if rn.strip() else f"Classe {j+1}" for j, rn in enumerate(risk_names)]
row_labels = []
for (hn, y0, y1) in horizons:
    base = hn.strip() if hn.strip() else "Orizzonte"
    if y1 is None:
        row_labels.append(f"{base} (> {y0}y)")
    else:
        row_labels.append(f"{base} ({y0}-{y1}y)")

# DataFrame pesi in session_state (per mantenere i valori)
key_df = "weights_df"
if key_df not in st.session_state:
    st.session_state[key_df] = pd.DataFrame(0.0, index=row_labels, columns=col_labels)

df = st.session_state[key_df].reindex(index=row_labels, columns=col_labels).fillna(0.0)

# =======================
# 3) Pesi (menu a tendina per cella) – basati sui portafogli disponibili in un Set
# =======================
st.markdown(
    '<div class="uw-card"><h2>3) Pesi “Azionario+Alternativo” (%)</h2>'
    '<p>Selezioni il <b>Set di Portafogli</b> (Tools → Portafogli in Asset Class) da utilizzare per popolare la griglia. '
    'Nei menu a tendina compariranno <b>solo</b> i pesi aggregati di <b>Azionario + Alternativo</b> dei portafogli presenti nel Set selezionato.</p></div>',
    unsafe_allow_html=True
)

# Selezione Set di Portafogli (Asset Allocation) da cui derivare i pesi ammessi
asset_sets = sorted(list(st.session_state.get("asset_selections", {}).keys()))
if len(asset_sets) == 0:
    st.warning("Nessun Set disponibile. Creare prima un Set in Tools → Portafogli in Asset Class.")
    options = [0]
    selected_set_for_grid = None
else:
    selected_set_for_grid = st.selectbox(
        "Selezioni il Set di Portafogli da utilizzare",
        asset_sets,
        key="grid_asset_set_select"
    )

    as_payload = st.session_state["asset_selections"].get(selected_set_for_grid, {})
    assets_df_sel = as_payload.get("assets_df", pd.DataFrame(columns=["Asset Class", "Macro-Asset Class"]))
    alloc_df_sel = as_payload.get("alloc_df", None)

    if alloc_df_sel is None or (isinstance(alloc_df_sel, pd.DataFrame) and alloc_df_sel.empty):
        st.warning("Il Set selezionato non contiene ancora composizioni (foglio “Portafogli”). Caricare e salvare il Set in Tools → Portafogli in Asset Class.")
        options = [0]
    else:
        # Calcolo pesi aggregati Azionario + Alternativo per ciascun portafoglio
        try:
            macro_map = dict(zip(
                assets_df_sel["Asset Class"].astype(str),
                assets_df_sel["Macro-Asset Class"].astype(str)
            ))
        except Exception:
            macro_map = {}

        risky_assets = [a for a, m in macro_map.items() if str(m).strip() in {"Azionario", "Alternativo"}]

        if len(risky_assets) == 0:
            st.warning('Nel Set selezionato non risultano Asset Class con Macro-Asset Class "Azionario" o "Alternativo".')
            options = [0]
        else:
            cols_present = [c for c in risky_assets if c in alloc_df_sel.columns.astype(str).tolist()]
            if len(cols_present) == 0:
                st.warning("Nel foglio “Portafogli” del Set selezionato non risultano colonne per le asset class Azionario/Alternativo.")
                options = [0]
            else:
                agg = alloc_df_sel.loc[:, cols_present].sum(axis=1).astype(float)
                options = sorted(pd.Series((agg * 100).round(0).astype(int)).unique().tolist())
                if len(options) == 0:
                    options = [0]

# --- st.markdown("**Inserimento pesi (%):**")

# --- LARGHEZZE COLONNE (stabili) ---
left_w = 3
col_w = 2
col_weights = [left_w] + [col_w] * len(col_labels)

st.markdown("**Inserimento pesi (%):**")

# Header: widget disabilitati (altezza uniforme)
hdr_cols = st.columns(col_weights, gap="small")
with hdr_cols[0]:
    st.text_input(
        label="",
        value="Orizzonte / Rischio",
        disabled=True,
        label_visibility="collapsed",
        key="hdr_left_static"
    )

for c in col_labels:
    with hdr_cols[col_labels.index(c) + 1]:
        st.text_input(
            label="",
            value=c,
            disabled=True,
            label_visibility="collapsed",
            key=f"hdr_col_{c}"   # chiave basata sul nome colonna
        )

# Griglia: chiavi basate su (riga, colonna) -> stabili anche se cambia l'ordine o i nomi
for r in row_labels:
    row_cols = st.columns(col_weights, gap="small")

    # Etichetta riga: key basata sul testo riga
    with row_cols[0]:
        st.text_input(
            label="",
            value=r,
            disabled=True,
            label_visibility="collapsed",
            key=f"rowlbl_{r}"
        )

    for j, c in enumerate(col_labels):
        # chiave cella basata su (riga, colonna)
        cell_key = f"w__{r}__{c}"

        # valore corrente dal df
        cur = df.loc[r, c]
        try:
            cur_int = int(cur)
        except Exception:
            cur_int = 0

        # se già presente in session_state, lo uso (coerente per quella specifica cella)
        if cell_key in st.session_state:
            try:
                cur_int = int(st.session_state[cell_key])
            except Exception:
                cur_int = 0

        val = row_cols[j + 1].selectbox(
            label="",
            options=options,
            index=options.index(cur_int) if cur_int in options else 0,
            key=cell_key,
            label_visibility="collapsed",
        )
        df.loc[r, c] = float(val)

st.session_state[key_df] = df

# =======================
# 4) Risultato finale: griglia
# =======================
st.markdown(
    '<div class="uw-card"><h2>Risultato finale: Griglia</h2>'
    '<p>Anteprima della griglia con il livello di Azionario+Opportunità per ciascuna combinazione.</p></div>',
    unsafe_allow_html=True
)

st.markdown(build_grid_preview_html(df), unsafe_allow_html=True)

# =======================
# Salvataggio classe
# =======================
st.markdown(
    '<div class="uw-card"><h2>Salvataggio</h2>'
    '<p>Assegni un nome alla Griglia e salvi. La griglia sarà poi disponibile in “Modifica/Cancella”.</p></div>',
    unsafe_allow_html=True
)

# Se in modalità "modifica", il nome è quello selezionato; se "nuova" viene dal campo
if mode == "Crea una nuova Griglia":
    save_name = st.session_state.get("new_class_name", "").strip()
else:
    save_name = (selected_existing or "").strip()

actions = st.columns([0.18, 0.82])
with actions[0]:
    save_clicked = st.button("Salva", type="primary", key="save_btn")
with actions[1]:
    # Mostro una “pill” informativa
    if len(st.session_state["client_classes"]) > 0:
        st.caption(f"Griglie salvate: {len(st.session_state['client_classes'])}")

if save_clicked:
    if save_name == "":
        st.error("Inserire un Nome per la Griglia prima di salvare.")
    else:
        payload = build_payload(
            class_name=save_name,
            risk_n=int(risk_n),
            risk_names=risk_names,
            hor_n=int(hor_n),
            horizons=horizons,
            df=df
        )
        # Set di Portafogli associato alla Griglia (Tools → Portafogli in Asset Class)
        payload["selected_set"] = selected_set_for_grid
        st.session_state["client_classes"][save_name] = payload
        st.success(f'Griglia "{save_name}" salvata correttamente.')
        persist_client_grids_from_session()

st.markdown("</div>", unsafe_allow_html=True)


# ================= FINAL GA RENDERING (NO LIVE UPDATES) =================
if st.session_state.get("ga_completed", False):

    st.subheader("Risultato finale – Soluzione di investimento dinamica")

    if "fig_dyn_final" in st.session_state:
        st.plotly_chart(
            st.session_state.fig_dyn_final,
            use_container_width=True
        )

    if "fig_fit_final" in st.session_state:
        st.plotly_chart(
            st.session_state.fig_fit_final,
            use_container_width=True
        )
# =======================================================================



# ================= FINAL GA RENDERING (AFTER COMPLETION) =================
if st.session_state.get("ga_completed", False):

    st.subheader("Risultato finale – Soluzione di investimento dinamica")

    if "best_results" in st.session_state:
        st.write(st.session_state["best_results"])

    if "fig_dyn_final" in st.session_state:
        st.plotly_chart(st.session_state["fig_dyn_final"], use_container_width=True)

    if "fig_fit_final" in st.session_state:
        st.plotly_chart(st.session_state["fig_fit_final"], use_container_width=True)
# =======================================================================