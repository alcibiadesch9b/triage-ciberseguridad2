import os
import json
import base64
import secrets
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlencode

from flask import (
    Flask, render_template, redirect, url_for, session, abort, request, flash
)
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt

from db import (
    init_db, listar_incidentes, obtener_incidente, crear_incidente,
    actualizar_estado, actualizar_incidente, eliminar_incidente,
    registrar_auditoria, listar_auditoria,
    listar_comentarios, obtener_comentario, crear_comentario,
    actualizar_comentario, eliminar_comentario,
)

load_dotenv()

# Para cuando llegue la CA corregida (déjalo comentado en .env mientras tanto)
ca_bundle = os.getenv("KEYCLOAK_CA_BUNDLE")
if ca_bundle:
    os.environ["REQUESTS_CA_BUNDLE"] = ca_bundle

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("Falta FLASK_SECRET_KEY en el archivo .env")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True, 
)

KEYCLOAK_SERVER = os.getenv("KEYCLOAK_SERVER", "").rstrip("/")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET") or None
TRIAGE_URL = os.getenv("TRIAGE_URL", "http://127.0.0.1:5000").rstrip("/")
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"

oauth = OAuth(app)
keycloak = oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=(
        f"{KEYCLOAK_SERVER}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid profile email",
        "code_challenge_method": "S256",  # PKCE
        "token_endpoint_auth_method": "client_secret_post" if CLIENT_SECRET else "none",
    },
)

# Crea las tablas si no existen
init_db()


# ---------------------------------------------------------------
# Autorización
# ---------------------------------------------------------------

# Matriz de permisos (sección 8.1 del documento del proyecto)
# C = crear, R = leer, U = actualizar, D = eliminar
PERMISOS = {
    "incidentes": {
        "ROL_ADMIN": "CRUD",
        "ROL_ANALISTA": "CRU",
        "ROL_AUDITOR": "R",
        "ROL_USUARIO": "CR",  # solo sus propios incidentes
    },
    "comentarios": {
        "ROL_ADMIN": "CRUD",
        "ROL_ANALISTA": "CRU",
        "ROL_AUDITOR": "R",
        "ROL_USUARIO": "CR",
    },
    "auditoria": {"ROL_ADMIN": "R", "ROL_AUDITOR": "R"},
    "usuarios": {"ROL_ADMIN": "CRUD"},
    "configuracion": {"ROL_ADMIN": "RU"},
}

# Roles que pueden ver los incidentes de todos
ROLES_VEN_TODO = {"ROL_ADMIN", "ROL_ANALISTA", "ROL_AUDITOR"}

SEVERIDADES = ("Alta", "Media", "Baja")
ESTADOS = ("Abierto", "En investigación", "Resuelto")


def login_required(vista):
    @wraps(vista)
    def envoltura(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("inicio"))
        return vista(*args, **kwargs)
    return envoltura


def puede(recurso, accion):
    roles = session.get("user", {}).get("roles", [])
    return any(accion in PERMISOS.get(recurso, {}).get(r, "") for r in roles)


def permiso_requerido(recurso, accion):
    def decorador(vista):
        @wraps(vista)
        def envoltura(*args, **kwargs):
            if not puede(recurso, accion):
                abort(403)
            return vista(*args, **kwargs)
        return envoltura
    return decorador


def ve_todos():
    roles = set(session.get("user", {}).get("roles", []))
    return bool(ROLES_VEN_TODO & roles)


def calcular_stats(filas):
    return {
        "total": len(filas),
        "abiertos": sum(1 for f in filas if f["estado"] == "Abierto"),
        "investigacion": sum(1 for f in filas if f["estado"] == "En investigación"),
        "resueltos": sum(1 for f in filas if f["estado"] == "Resuelto"),
    }


def incidentes_visibles():
    # Admin, analista y auditor ven todo; el usuario general solo lo suyo
    if ve_todos():
        return listar_incidentes()
    return listar_incidentes(creado_por=session["user"]["sub"])


def auditar(accion, detalle=""):
    """Registra un evento. Nunca pases tokens, contraseñas ni secretos en 'detalle'."""
    registrar_auditoria(session.get("user", {}).get("username"), accion, detalle)


# ---------------------------------------------------------------
# Protección CSRF para formularios
# ---------------------------------------------------------------

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def verificar_csrf():
    enviado = request.form.get("_csrf", "")
    esperado = session.get("_csrf", "")
    if not esperado or not secrets.compare_digest(enviado, esperado):
        abort(400)


@app.context_processor
def exponer_utilidades():
    return {"puede": puede, "csrf_token": csrf_token}


# ---------------------------------------------------------------
# Utilidades para la evidencia del ID token
# ---------------------------------------------------------------

def _cabecera_jwt(jwt_str):
    """Lee la cabecera (alg, kid) de un JWT. Solo informativo: la firma ya la verificó Authlib."""
    parte = jwt_str.split(".")[0]
    parte += "=" * (-len(parte) % 4)
    return json.loads(base64.urlsafe_b64decode(parte))


def _fecha(ts):
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------
# Rutas de autenticación
# ---------------------------------------------------------------

@app.route("/")
def inicio():
    return render_template("login.html")


@app.route("/login")
def login():
    if DEMO_MODE:
        # Solo desarrollo: sesión ficticia, NO es autenticación real
        session["user"] = {
            "sub": "demo",
            "username": "usuario_demo",
            "name": "Usuario de prueba",
            "email": "usuario@proyecto.test",
            "roles": ["demo"],
        }
        return redirect(url_for("dashboard"))

    redirect_uri = url_for("callback", _external=True)
    return keycloak.authorize_redirect(redirect_uri)  # Authlib genera state y nonce


@app.route("/callback")
def callback():
    # Authlib valida state, firma, iss, aud, exp y nonce del ID token (aud = cli-triage-dev)
    token = keycloak.authorize_access_token()
    claims = token.get("userinfo") or {}

    # Los roles vienen en el access token, cuyo aud es api-triage
    issuer = keycloak.load_server_metadata()["issuer"]
    jwks = keycloak.fetch_jwk_set()
    access_claims = jwt.decode(
        token["access_token"],
        jwks,
        claims_options={
            "iss": {"essential": True, "value": issuer},
            "aud": {"essential": True, "values": ["api-triage"]},
        },
    )
    access_claims.validate(leeway=60)  # tolera hasta 60 s de desfase de reloj

    session["user"] = {
        "sub": claims.get("sub"),
        "username": claims.get("preferred_username"),
        "name": claims.get("name"),
        "email": claims.get("email"),
        "roles": access_claims.get("realm_access", {}).get("roles", []),
    }
    session["id_token"] = token.get("id_token")

    # Evidencia para el informe (solo datos no sensibles; NO se guarda ningún token aquí)
    cabecera = _cabecera_jwt(token["id_token"])
    aud = claims.get("aud")
    aud = aud if isinstance(aud, list) else [aud]
    session["evidencia_id_token"] = {
        "iss": claims.get("iss"),
        "iss_esperado": issuer,
        "aud": aud,
        "aud_esperada": CLIENT_ID,
        "azp": claims.get("azp"),
        "sub": claims.get("sub"),
        "nonce": claims.get("nonce"),
        "iat": _fecha(claims.get("iat")),
        "exp": _fecha(claims.get("exp")),
        "auth_time": _fecha(claims.get("auth_time")),
        "alg": cabecera.get("alg"),
        "kid": cabecera.get("kid"),
        "iss_ok": claims.get("iss") == issuer,
        "aud_ok": CLIENT_ID in aud,
    }

    auditar("LOGIN", "Inicio de sesión correcto")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    if "user" in session:
        auditar("LOGOUT", "Cierre de sesión")

    id_token = session.pop("id_token", None)
    session.clear()

    if DEMO_MODE:
        return redirect(url_for("inicio"))

    metadata = keycloak.load_server_metadata()
    end_session = metadata.get("end_session_endpoint")
    if not end_session:
        return redirect(url_for("inicio"))

    params = {"post_logout_redirect_uri": TRIAGE_URL + "/", "client_id": CLIENT_ID}
    if id_token:
        params["id_token_hint"] = id_token
    return redirect(f"{end_session}?{urlencode(params)}")


# ---------------------------------------------------------------
# Rutas protegidas
# ---------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    stats = None
    publico = False
    if puede("incidentes", "R"):
        stats = calcular_stats(incidentes_visibles())
    elif "ROL_INVITADO" in session["user"].get("roles", []):
        # Estadísticas públicas: solo totales globales, sin ningún dato de incidentes
        stats = calcular_stats(listar_incidentes())
        publico = True
    return render_template("dashboard.html", stats=stats, publico=publico)


@app.route("/perfil")
@login_required
def perfil():
    return render_template("perfil.html", user=session["user"])


@app.route("/incidentes")
@login_required
@permiso_requerido("incidentes", "R")
def incidentes():
    filas = incidentes_visibles()
    return render_template(
        "incidentes.html",
        incidentes=filas,
        stats=calcular_stats(filas),
        estados=ESTADOS,
        comentarios_por_incidente={
            i["id"]: listar_comentarios(i["id"]) for i in filas
        },
    )


@app.route("/incidentes/nuevo", methods=["GET", "POST"])
@login_required
@permiso_requerido("incidentes", "C")
def nuevo_incidente():
    error = None
    if request.method == "POST":
        verificar_csrf()
        titulo = request.form.get("titulo", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        severidad = request.form.get("severidad", "")

        if not titulo or len(titulo) > 120:
            error = "El título es obligatorio y debe tener máximo 120 caracteres."
        elif not descripcion or len(descripcion) > 2000:
            error = "La descripción es obligatoria y debe tener máximo 2000 caracteres."
        elif severidad not in SEVERIDADES:
            error = "Selecciona una severidad válida."
        else:
            user = session["user"]
            nuevo_id = crear_incidente(
                titulo,
                descripcion,
                severidad,
                user["sub"],
                user.get("name") or user.get("username"),
            )
            auditar("INCIDENTE_CREADO", f"INC-{nuevo_id:03d} (severidad {severidad})")
            flash("Incidente registrado correctamente.")
            return redirect(url_for("incidentes"))

    return render_template("nuevo_incidente.html", error=error, severidades=SEVERIDADES)


@app.route("/incidentes/<int:incidente_id>/editar", methods=["POST"])
@login_required
@permiso_requerido("incidentes", "U")
def editar_incidente(incidente_id):
    verificar_csrf()
    incidente = incidente_accesible(incidente_id)

    titulo = request.form.get("titulo", "").strip()
    descripcion = request.form.get("descripcion", "").strip()
    severidad = request.form.get("severidad", "")

    if not titulo or len(titulo) > 120:
        flash("El título es obligatorio y debe tener máximo 120 caracteres.")
        return redirect(url_for("incidentes"))
    if not descripcion or len(descripcion) > 2000:
        flash("La descripción es obligatoria y debe tener máximo 2000 caracteres.")
        return redirect(url_for("incidentes"))
    if severidad not in SEVERIDADES:
        abort(400)

    if not actualizar_incidente(incidente_id, titulo, descripcion, severidad):
        abort(404)

    auditar("INCIDENTE_EDITADO", f"INC-{incidente_id:03d}: datos generales actualizados")
    flash(f"INC-{incidente_id:03d} actualizado correctamente.")
    return redirect(url_for("incidentes"))


@app.route("/incidentes/<int:incidente_id>/eliminar", methods=["POST"])
@login_required
@permiso_requerido("incidentes", "D")
def borrar_incidente(incidente_id):
    verificar_csrf()
    incidente = incidente_accesible(incidente_id)
    titulo = incidente["titulo"]

    if not eliminar_incidente(incidente_id):
        abort(404)

    auditar("INCIDENTE_ELIMINADO", f"INC-{incidente_id:03d}: {titulo[:120]}")
    flash(f"INC-{incidente_id:03d} eliminado correctamente.")
    return redirect(url_for("incidentes"))


@app.route("/incidentes/<int:incidente_id>/estado", methods=["POST"])
@login_required
@permiso_requerido("incidentes", "U")
def cambiar_estado(incidente_id):
    verificar_csrf()
    nuevo_estado = request.form.get("estado", "")
    if nuevo_estado not in ESTADOS:
        abort(400)

    incidente = obtener_incidente(incidente_id)
    if incidente is None:
        abort(404)

    anterior = incidente["estado"]
    actualizar_estado(incidente_id, nuevo_estado)
    auditar(
        "INCIDENTE_ESTADO",
        f"INC-{incidente_id:03d}: {anterior} -> {nuevo_estado}",
    )
    flash(f"Estado de INC-{incidente_id:03d} actualizado a «{nuevo_estado}».")
    return redirect(url_for("incidentes"))


def incidente_accesible(incidente_id):
    """Obtiene un incidente y comprueba que el usuario pueda acceder a él."""
    incidente = obtener_incidente(incidente_id)
    if incidente is None:
        abort(404)
    if not ve_todos() and incidente["creado_por"] != session["user"].get("sub"):
        abort(404)
    return incidente


@app.route("/incidentes/<int:incidente_id>/comentarios", methods=["POST"])
@login_required
@permiso_requerido("comentarios", "C")
def nuevo_comentario(incidente_id):
    verificar_csrf()
    incidente_accesible(incidente_id)
    contenido = request.form.get("contenido", "").strip()

    if not contenido or len(contenido) > 2000:
        flash("El comentario es obligatorio y debe tener máximo 2000 caracteres.")
        return redirect(url_for("incidentes"))

    user = session["user"]
    comentario_id = crear_comentario(
        incidente_id,
        contenido,
        user["sub"],
        user.get("name") or user.get("username"),
    )
    auditar("COMENTARIO_CREADO", f"Comentario #{comentario_id} en INC-{incidente_id:03d}")
    flash("Comentario agregado correctamente.")
    return redirect(url_for("incidentes"))


@app.route("/comentarios/<int:comentario_id>/editar", methods=["POST"])
@login_required
@permiso_requerido("comentarios", "U")
def editar_comentario(comentario_id):
    verificar_csrf()
    comentario = obtener_comentario(comentario_id)
    if comentario is None:
        abort(404)
    incidente_accesible(comentario["incidente_id"])
    contenido = request.form.get("contenido", "").strip()

    if not contenido or len(contenido) > 2000:
        flash("El comentario es obligatorio y debe tener máximo 2000 caracteres.")
        return redirect(url_for("incidentes"))

    actualizar_comentario(comentario_id, contenido)
    auditar(
        "COMENTARIO_EDITADO",
        f"Comentario #{comentario_id} en INC-{comentario['incidente_id']:03d}",
    )
    flash("Comentario actualizado correctamente.")
    return redirect(url_for("incidentes"))


@app.route("/comentarios/<int:comentario_id>/eliminar", methods=["POST"])
@login_required
@permiso_requerido("comentarios", "D")
def borrar_comentario(comentario_id):
    verificar_csrf()
    comentario = obtener_comentario(comentario_id)
    if comentario is None:
        abort(404)
    incidente_accesible(comentario["incidente_id"])
    eliminar_comentario(comentario_id)
    auditar(
        "COMENTARIO_ELIMINADO",
        f"Comentario #{comentario_id} en INC-{comentario['incidente_id']:03d}",
    )
    flash("Comentario eliminado correctamente.")
    return redirect(url_for("incidentes"))


@app.route("/auditoria")
@login_required
@permiso_requerido("auditoria", "R")
def auditoria():
    return render_template("auditoria.html", registros=listar_auditoria())


@app.route("/admin")
@login_required
@permiso_requerido("usuarios", "R")
def admin():
    filas = listar_incidentes()
    por_severidad = {s: sum(1 for f in filas if f["severidad"] == s) for s in SEVERIDADES}

    # Configuración visible: NUNCA incluir el Client Secret, tokens ni la clave de sesión
    config = {
        "Servidor de identidad": KEYCLOAK_SERVER,
        "Realm": KEYCLOAK_REALM,
        "Client ID": CLIENT_ID,
        "Tipo de cliente": "Confidencial" if CLIENT_SECRET else "Público",
        "PKCE": "S256",
        "URL de la aplicación": TRIAGE_URL,
        "Cookie de sesión Secure": (
            "Sí" if app.config["SESSION_COOKIE_SECURE"] else "No (HTTP de desarrollo)"
        ),
        "Cookie HttpOnly": "Sí" if app.config["SESSION_COOKIE_HTTPONLY"] else "No",
        "Cookie SameSite": app.config["SESSION_COOKIE_SAMESITE"],
        "Modo demostración": "Activado" if DEMO_MODE else "Desactivado",
    }

    return render_template(
        "admin.html",
        stats=calcular_stats(filas),
        por_severidad=por_severidad,
        permisos=PERMISOS,
        config=config,
        recientes=listar_auditoria(10),
    )


@app.route("/evidencia-token")
@login_required
def evidencia_token():
    # TEMPORAL: solo para capturas del informe. Quitar antes de la entrega final.
    return render_template("evidencia_token.html", e=session.get("evidencia_id_token"))


@app.errorhandler(403)
def prohibido(e):
    if "user" in session:
        auditar("ACCESO_DENEGADO", request.path)
    return render_template("403.html"), 403


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5443,
        ssl_context=(
            r"C:\certs\triage\triage.crt",
            r"C:\certs\triage\triage.key"
        ),
        debug=False
    )