"""Carga incidentes de ejemplo en instance/triage.db.

Uso (con (venv) activo, dentro de la carpeta triage):
    python seed.py            -> añade los incidentes de ejemplo
    python seed.py --borrar   -> elimina solo los incidentes de ejemplo
"""
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone

from db import get_conn, init_db

MARCA = "seed-demo"  # identifica los datos de ejemplo para poder borrarlos

# (título, descripción, severidad, estado, creado por, hace cuántos días)
INCIDENTES = [
    ("Intentos de acceso fallidos desde IP externa",
     "Se detectaron más de 40 intentos fallidos de inicio de sesión sobre una misma cuenta en 10 minutos, desde una dirección fuera de la red del laboratorio.",
     "Alta", "En investigación", "Eva Pinzón", 1),
    ("Correo de phishing reportado por un usuario",
     "Un usuario recibió un correo que suplanta al área de TI y solicita restablecer la contraseña mediante un enlace sospechoso.",
     "Media", "Abierto", "Caro Villalba", 2),
    ("Servicio SSH expuesto con autenticación por contraseña",
     "Durante una revisión de configuración se encontró que el servidor acepta autenticación por contraseña en SSH. Se recomienda usar solo llaves.",
     "Alta", "Abierto", "Eva Pinzón", 3),
    ("Archivo con extensión sospechosa en carpeta compartida",
     "Se encontró un archivo ejecutable dentro de una carpeta de documentos. Se aisló y se envió a análisis.",
     "Media", "En investigación", "Caro Villalba", 5),
    ("Actualización de seguridad aplicada al servidor",
     "Se instalaron los parches pendientes del sistema operativo y se reinició el servicio sin incidencias.",
     "Baja", "Resuelto", "Eva Pinzón", 8),
]


def borrar():
    with closing(get_conn()) as conn:
        with conn:
            cur = conn.execute("DELETE FROM incidentes WHERE creado_por = ?", (MARCA,))
            print(f"Se eliminaron {cur.rowcount} incidentes de ejemplo.")


def cargar():
    init_db()
    with closing(get_conn()) as conn:
        existentes = conn.execute(
            "SELECT COUNT(*) FROM incidentes WHERE creado_por = ?", (MARCA,)
        ).fetchone()[0]
        if existentes:
            print(f"Ya hay {existentes} incidentes de ejemplo. Usa 'python seed.py --borrar' primero.")
            return

        ahora = datetime.now(timezone.utc)
        with conn:
            for titulo, desc, sev, estado, nombre, dias in INCIDENTES:
                fecha = (ahora - timedelta(days=dias)).strftime("%Y-%m-%d %H:%M:%S")
                conn.execute(
                    """INSERT INTO incidentes
                       (titulo, descripcion, severidad, estado, creado_por, creado_por_nombre, creado_en)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (titulo, desc, sev, estado, MARCA, nombre, fecha),
                )
        print(f"Se añadieron {len(INCIDENTES)} incidentes de ejemplo.")


if __name__ == "__main__":
    if "--borrar" in sys.argv:
        borrar()
    else:
        cargar()