"""
TRIAGE - Verificacion automatizada del control de acceso
Responsable: Jennifer Yau (Integrante 4 - Autorizacion)

QUE HACE
--------
Ejecuta la aplicacion real de TRIAGE (app.py) y comprueba, rol por rol y ruta
por ruta, que el comportamiento observado coincide con la matriz de control de
acceso documentada. Tambien verifica el aislamiento por propietario, la
proteccion CSRF y el registro de las denegaciones en la bitacora.

No reimplementa nada: importa la aplicacion tal cual esta en el repositorio.
Si una prueba falla, el defecto esta en la aplicacion, no en este archivo.

COMO SE EJECUTA
---------------
Este archivo vive en la carpeta verificacion/ del repositorio y se ejecuta
desde ahi:

    pip install -r requirements.txt
    cd verificacion
    python pruebas_autorizacion.py

No requiere Keycloak ni conexion de red: la sesion se inyecta directamente,
que es justo lo que permite aislar la AUTORIZACION de la AUTENTICACION.

POR QUE SE PUEDE INYECTAR LA SESION
-----------------------------------
La aplicacion decide los permisos leyendo session["user"]["roles"]. En
produccion ese valor lo escribe unicamente el callback de OIDC, despues de
validar la firma del token contra el JWKS de Keycloak y comprobar iss, aud y
exp. Aqui se escribe desde el banco de pruebas para poder ejercitar cada rol
sin levantar el proveedor de identidad. La inyeccion ocurre SOLO en este
archivo y no altera la aplicacion.
"""

import os
import sys
import re
import tempfile
from pathlib import Path

# La aplicacion vive en la raiz del repositorio, un nivel por encima.
RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

# ---------------------------------------------------------------------------
# Entorno minimo. No se usan secretos reales: la aplicacion exige que estas
# variables existan, pero ninguna prueba contacta con Keycloak.
# ---------------------------------------------------------------------------
os.environ.setdefault("FLASK_SECRET_KEY", "clave-solo-para-pruebas")
os.environ.setdefault("KEYCLOAK_SERVER", "https://idp.proyecto.test:8443")
os.environ.setdefault("KEYCLOAK_REALM", "triage")
os.environ.setdefault("KEYCLOAK_CLIENT_ID", "cli-triage-dev")
os.environ["DEMO_MODE"] = "false"

# Base de datos temporal: las pruebas no tocan la base real del proyecto.
import db
_tmp = tempfile.mkdtemp(prefix="triage-pruebas-")
db.DB_PATH = Path(_tmp) / "pruebas.db"

import app as A

A.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

CSRF = "token-de-prueba"


def sesion(roles, sub, usuario):
    """Devuelve un cliente HTTP con una sesion ya establecida para ese rol."""
    c = A.app.test_client()
    with c.session_transaction() as s:
        s["user"] = {
            "sub": sub,
            "username": usuario,
            "name": usuario,
            "email": usuario + "@proyecto.test",
            "roles": roles,
        }
        s["_csrf"] = CSRF
    return c


resultados = []


def comprobar(n, descripcion, obtenido, esperado, nota=""):
    ok = obtenido == esperado
    resultados.append((n, descripcion, ok))
    print("  %-5s %2d. %-46s esperado %-18s obtenido %s%s"
          % ("OK" if ok else "FALLA", n, descripcion,
             esperado, obtenido, ("  <- " + nota) if nota else ""))
    return ok


# ---------------------------------------------------------------------------
# BLOQUE 1 - Matriz de acceso por rol y por ruta
# ---------------------------------------------------------------------------
# 200 = permitido   403 = denegado por falta de permiso   302 = redirigido a login

MATRIZ_ESPERADA = {
    #                     /dashboard /incidentes /incidentes/nuevo /auditoria /admin
    "ROL_ADMIN":          (200,      200,        200,              200,       200),
    "ROL_ANALISTA":       (200,      200,        200,              403,       403),
    "ROL_AUDITOR":        (200,      200,        403,              200,       403),
    "ROL_USUARIO":        (200,      200,        200,              403,       403),
    "ROL_INVITADO":       (200,      403,        403,              403,       403),
}

RUTAS = ["/dashboard", "/incidentes", "/incidentes/nuevo", "/auditoria", "/admin"]


def bloque_matriz():
    print()
    print("BLOQUE 1 - Matriz de control de acceso")
    print("-" * 100)
    n = 0
    for rol, esperados in MATRIZ_ESPERADA.items():
        c = sesion([rol], "sub-" + rol.lower(), rol.lower())
        for ruta, esperado in zip(RUTAS, esperados):
            n += 1
            obtenido = c.get(ruta).status_code
            comprobar(n, "%-14s %s" % (rol.replace("ROL_", ""), ruta),
                      obtenido, esperado)
    return n


# ---------------------------------------------------------------------------
# BLOQUE 2 - Aislamiento por propietario
# ---------------------------------------------------------------------------
# Dos usuarios finales distintos. Ninguno debe alcanzar el incidente del otro.
# La respuesta correcta a un recurso ajeno es 404, no 403: un 403 confirmaria
# que el recurso existe (OWASP A01:2021 - Broken Access Control).

def bloque_propiedad(n):
    print()
    print("BLOQUE 2 - Aislamiento por propietario")
    print("-" * 100)

    ana = sesion(["ROL_USUARIO"], "sub-ana", "ana")
    beto = sesion(["ROL_USUARIO"], "sub-beto", "beto")

    ana.post("/incidentes/nuevo", data={
        "_csrf": CSRF, "titulo": "Incidente de Ana",
        "descripcion": "Contenido reservado", "severidad": "Alta"})

    incidentes = db.listar_incidentes()
    if not incidentes:
        print("  FALLA: no se pudo crear el incidente de partida")
        return n + 4
    iid = incidentes[0]["id"]

    n += 1
    r = beto.get("/incidentes")
    comprobar(n, "Beto no ve el incidente de Ana en el listado",
              b"Incidente de Ana" in r.data, False,
              "el filtrado ocurre en la consulta")

    n += 1
    r = beto.post("/incidentes/%d/comentarios" % iid,
                  data={"_csrf": CSRF, "contenido": "intrusion"})
    comprobar(n, "Beto comenta en el incidente de Ana", r.status_code, 404,
              "404 y no 403: no se revela que existe")

    n += 1
    r = beto.post("/incidentes/%d/estado" % iid,
                  data={"_csrf": CSRF, "estado": "Resuelto"})
    comprobar(n, "Beto cambia el estado del incidente de Ana",
              r.status_code, 403, "le falta el permiso U")

    n += 1
    r = ana.get("/incidentes")
    comprobar(n, "Ana si ve su propio incidente",
              b"Incidente de Ana" in r.data, True)

    return n


# ---------------------------------------------------------------------------
# BLOQUE 3 - Controles complementarios
# ---------------------------------------------------------------------------

def bloque_controles(n):
    print()
    print("BLOQUE 3 - Controles complementarios")
    print("-" * 100)

    n += 1
    anonimo = A.app.test_client()
    comprobar(n, "Peticion sin sesion a /incidentes",
              anonimo.get("/incidentes").status_code, 302,
              "redirige al login")

    n += 1
    ana = sesion(["ROL_USUARIO"], "sub-ana", "ana")
    r = ana.post("/incidentes/nuevo", data={
        "titulo": "Sin token", "descripcion": "x", "severidad": "Alta"})
    comprobar(n, "Formulario enviado sin token CSRF", r.status_code, 400)

    n += 1
    beto = sesion(["ROL_USUARIO"], "sub-beto", "beto")
    antes = len(db.listar_auditoria())
    beto.post("/incidentes/1/estado", data={"_csrf": CSRF, "estado": "Resuelto"})
    despues = db.listar_auditoria()
    registrado = any(a["accion"] == "ACCESO_DENEGADO" for a in despues)
    comprobar(n, "La denegacion por permiso queda en la bitacora",
              registrado, True)

    return n


# ---------------------------------------------------------------------------
# BLOQUE 4 - Hallazgos de la revision
# ---------------------------------------------------------------------------
# Estas comprobaciones NO describen el comportamiento deseado: documentan
# desviaciones detectadas respecto de la matriz. Se marcan como FALLA a
# proposito, para que queden visibles hasta que se corrijan.

def bloque_hallazgos(n):
    print()
    print("BLOQUE 4 - Hallazgos de la revision")
    print("-" * 100)

    n += 1
    inv = sesion(["ROL_INVITADO"], "sub-inv", "invitado")
    comprobar(n, "H1 /evidencia-token exige permiso",
              inv.get("/evidencia-token").status_code, 403,
              "hoy responde 200 a cualquier rol")

    n += 1
    ana = sesion(["ROL_USUARIO"], "sub-ana2", "ana2")
    ana.post("/incidentes/nuevo", data={
        "_csrf": CSRF, "titulo": "Caso reservado",
        "descripcion": "x", "severidad": "Media"})
    iid = db.listar_incidentes()[0]["id"]

    beto = sesion(["ROL_USUARIO"], "sub-beto2", "beto2")
    antes = len(db.listar_auditoria())
    beto.post("/incidentes/%d/comentarios" % iid,
              data={"_csrf": CSRF, "contenido": "x"})
    nuevos = db.listar_auditoria()[:len(db.listar_auditoria()) - antes]
    registrado = any(a["accion"] == "ACCESO_DENEGADO" for a in nuevos)
    comprobar(n, "H2 La denegacion por propiedad queda en la bitacora",
              registrado, True,
              "el 404 por propiedad no se registra")

    n += 1
    inv = sesion(["ROL_INVITADO"], "sub-inv2", "invitado2")
    cuerpo = inv.get("/dashboard").data.decode("utf-8", "ignore")
    numeros = [int(x) for x in re.findall(r">\s*(\d+)\s*<", cuerpo)]
    total_real = len(db.listar_incidentes())
    expone = total_real in numeros and total_real > 0
    comprobar(n, "H3 El invitado no ve conteos de incidentes ajenos",
              expone, False,
              "ve el total global de la organizacion")

    return n


# ---------------------------------------------------------------------------

def main():
    print()
    print("=" * 100)
    print("  TRIAGE - Verificacion del control de acceso")
    print("  Jennifer Yau - Integrante 4 (Autorizacion)")
    print("=" * 100)

    n = bloque_matriz()
    n = bloque_propiedad(n)
    n = bloque_controles(n)
    total_sin_hallazgos = n
    n = bloque_hallazgos(n)

    base = [r for r in resultados if r[0] <= total_sin_hallazgos]
    hallazgos = [r for r in resultados if r[0] > total_sin_hallazgos]
    ok_base = sum(1 for r in base if r[2])
    abiertos = [r for r in hallazgos if not r[2]]

    print()
    print("=" * 100)
    print("  Conformidad con la matriz : %d de %d comprobaciones superadas"
          % (ok_base, len(base)))
    print("  Hallazgos abiertos        : %d de %d"
          % (len(abiertos), len(hallazgos)))
    for num, desc, _ in abiertos:
        print("      - %s" % desc)
    print("=" * 100)
    print()

    # El codigo de salida refleja solo la conformidad con la matriz; los
    # hallazgos se reportan pero no hacen fallar la verificacion base.
    return 0 if ok_base == len(base) else 1


if __name__ == "__main__":
    sys.exit(main())
