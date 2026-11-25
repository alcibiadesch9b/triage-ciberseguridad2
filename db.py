import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = Path(__file__).parent / "instance" / "triage.db"


def get_conn():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with closing(get_conn()) as conn:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidentes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    titulo TEXT NOT NULL,
                    descripcion TEXT NOT NULL,
                    severidad TEXT NOT NULL,
                    estado TEXT NOT NULL DEFAULT 'Abierto',
                    creado_por TEXT NOT NULL,
                    creado_por_nombre TEXT,
                    creado_en TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS auditoria (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario TEXT NOT NULL,
                    accion TEXT NOT NULL,
                    detalle TEXT,
                    creado_en TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS comentarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incidente_id INTEGER NOT NULL,
                    contenido TEXT NOT NULL,
                    creado_por TEXT NOT NULL,
                    creado_por_nombre TEXT,
                    creado_en TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (incidente_id) REFERENCES incidentes(id)
                        ON DELETE CASCADE
                )
            """)


# ---------------- Incidentes ----------------

def listar_incidentes(creado_por=None):
    with closing(get_conn()) as conn:
        if creado_por:
            cur = conn.execute(
                "SELECT * FROM incidentes WHERE creado_por = ? ORDER BY id DESC",
                (creado_por,),
            )
        else:
            cur = conn.execute("SELECT * FROM incidentes ORDER BY id DESC")
        return cur.fetchall()


def obtener_incidente(incidente_id):
    with closing(get_conn()) as conn:
        return conn.execute(
            "SELECT * FROM incidentes WHERE id = ?", (incidente_id,)
        ).fetchone()


def crear_incidente(titulo, descripcion, severidad, creado_por, creado_por_nombre):
    with closing(get_conn()) as conn:
        with conn:
            cur = conn.execute(
                """INSERT INTO incidentes
                   (titulo, descripcion, severidad, creado_por, creado_por_nombre)
                   VALUES (?, ?, ?, ?, ?)""",
                (titulo, descripcion, severidad, creado_por, creado_por_nombre),
            )
            return cur.lastrowid


def actualizar_incidente(incidente_id, titulo, descripcion, severidad):
    """Actualiza los datos editables de un incidente, sin alterar su estado."""
    with closing(get_conn()) as conn:
        with conn:
            cur = conn.execute(
                """UPDATE incidentes
                   SET titulo = ?, descripcion = ?, severidad = ?
                   WHERE id = ?""",
                (titulo, descripcion, severidad, incidente_id),
            )
            return cur.rowcount > 0


def eliminar_incidente(incidente_id):
    """Elimina un incidente y sus comentarios asociados (ON DELETE CASCADE)."""
    with closing(get_conn()) as conn:
        with conn:
            cur = conn.execute(
                "DELETE FROM incidentes WHERE id = ?",
                (incidente_id,),
            )
            return cur.rowcount > 0


def actualizar_estado(incidente_id, estado):
    with closing(get_conn()) as conn:
        with conn:
            cur = conn.execute(
                "UPDATE incidentes SET estado = ? WHERE id = ?",
                (estado, incidente_id),
            )
            return cur.rowcount > 0


# ---------------- Auditoría ----------------

def registrar_auditoria(usuario, accion, detalle=""):
    with closing(get_conn()) as conn:
        with conn:
            conn.execute(
                "INSERT INTO auditoria (usuario, accion, detalle) VALUES (?, ?, ?)",
                (usuario or "anónimo", accion, detalle),
            )


def listar_auditoria(limite=200):
    with closing(get_conn()) as conn:
        return conn.execute(
            "SELECT * FROM auditoria ORDER BY id DESC LIMIT ?", (limite,)
        ).fetchall()

# ---------------- Comentarios ----------------

def listar_comentarios(incidente_id):
    with closing(get_conn()) as conn:
        return conn.execute(
            """SELECT * FROM comentarios
               WHERE incidente_id = ?
               ORDER BY id ASC""",
            (incidente_id,)
        ).fetchall()


def obtener_comentario(comentario_id):
    with closing(get_conn()) as conn:
        return conn.execute(
            "SELECT * FROM comentarios WHERE id = ?",
            (comentario_id,)
        ).fetchone()


def crear_comentario(incidente_id, contenido, creado_por, creado_por_nombre):
    with closing(get_conn()) as conn:
        with conn:
            cur = conn.execute(
                """INSERT INTO comentarios
                   (incidente_id, contenido, creado_por, creado_por_nombre)
                   VALUES (?, ?, ?, ?)""",
                (incidente_id, contenido, creado_por, creado_por_nombre)
            )
            return cur.lastrowid


def actualizar_comentario(comentario_id, contenido):
    with closing(get_conn()) as conn:
        with conn:
            cur = conn.execute(
                "UPDATE comentarios SET contenido = ? WHERE id = ?",
                (contenido, comentario_id)
            )
            return cur.rowcount > 0


def eliminar_comentario(comentario_id):
    with closing(get_conn()) as conn:
        with conn:
            cur = conn.execute(
                "DELETE FROM comentarios WHERE id = ?",
                (comentario_id,)
            )
            return cur.rowcount > 0
