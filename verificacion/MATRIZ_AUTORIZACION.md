# Matriz de control de acceso — TRIAGE

**Responsable:** Jennifer Yau — Integrante 4 (Autorización)
**Asignatura:** Ciberseguridad II — Universidad Tecnológica de Panamá

Este documento especifica la matriz de control de acceso de TRIAGE y la
contrasta con lo que la aplicación hace realmente. La verificación está
automatizada en `verificacion/pruebas_autorizacion.py`; los desvíos
detectados están en `verificacion/HALLAZGOS.md`.

---

## 1. Alcance

La **autenticación** responde *quién eres* y la resuelve Keycloak mediante
OpenID Connect con PKCE (Fase 3). La **autorización** responde *qué se te
permite* y es lo que aquí se especifica.

Son controles distintos y se verifican por separado. Un token válido no
concede, por sí solo, ningún permiso.

## 2. Origen de los roles

Los roles no se definen dentro de la aplicación. Recorren esta cadena:

```
Samba AD (grupo GRP_<ÁREA>_<ROL>)
    ↓  federación LDAPS + group-ldap-mapper
Keycloak (rol de realm ROL_<ROL>)
    ↓  claim realm_access.roles del access token
TRIAGE (matriz de este documento)
```

Consecuencia práctica: para cambiar los permisos de una persona se mueve su
cuenta de grupo en el directorio. No se toca la base de datos de la aplicación
ni se modifica código. Eso es lo que hace que el control sea centralizado y
auditable.

## 3. Notación

Operaciones sobre cada recurso: **C** crear · **R** leer · **U** actualizar ·
**D** eliminar.

## 4. Matriz

| Recurso | ADMIN | ANALISTA | AUDITOR | USUARIO | INVITADO |
|---|:---:|:---:|:---:|:---:|:---:|
| Incidentes | CRUD | CRU | R | CR (solo propios) | — |
| Comentarios | CRUD | CRU | R | CR (en sus incidentes) | — |
| Auditoría | R | — | R | — | — |
| Usuarios | CRUD | — | — | — | — |
| Configuración | RU | — | — | — | — |
| Estadísticas públicas | — | — | — | — | R |

### Alcance de visibilidad

| Rol | Incidentes que puede ver |
|---|---|
| ADMIN, ANALISTA, AUDITOR | Todos |
| USUARIO | Únicamente los que creó |
| INVITADO | Ninguno |

La restricción del rol USUARIO se aplica **en la consulta**, no en la
interfaz: el listado se construye filtrando por el identificador del usuario
antes de que los datos salgan del servidor.

## 5. Justificación de mínimo privilegio

**ADMIN.** Único rol con acceso a usuarios y configuración. Se concentra en
una sola figura porque un cambio de configuración afecta a todo el sistema y
debe ser rastreable a una persona.

**ANALISTA.** Es quien trabaja los incidentes: crea, lee y actualiza. **No
recibe D.** La decisión es deliberada: eliminar un incidente destruye la
evidencia y la cronología de una investigación. Si un incidente se abrió por
error, se cierra con una justificación; no se borra. Esto preserva la
trazabilidad, que es el propósito de la herramienta.

**AUDITOR.** Solo lectura, pero es el único rol fuera de ADMIN que accede a la
bitácora. Encarna la **separación de deberes**: quien revisa la actuación del
sistema no debe poder alterar lo que revisa. Si el auditor pudiera modificar
incidentes, su propio informe dejaría de ser independiente.

**USUARIO.** Puede reportar un incidente y seguir el suyo. Un empleado que
reporta un correo de phishing no tiene por qué ver los incidentes de otras
áreas: esa información revela la postura de seguridad de la organización.

**INVITADO.** El mínimo absoluto. Existe para demostrar el punto central del
modelo: **autenticarse no es autorizarse**. Un invitado presenta un token
perfectamente válido y aun así no alcanza ningún recurso del sistema.

## 6. Decisiones de diseño

### 6.1 Denegación por defecto

La matriz es una lista de permitidos, no de prohibidos. Un permiso que no
aparece escrito no existe, y un rol ausente de la matriz no obtiene nada.
Consecuencia: crear un grupo nuevo en el directorio nunca abre accesos por
accidente.

### 6.2 Respuesta 404 ante recursos ajenos

Cuando un usuario pide un incidente que existe pero no le pertenece, el
sistema responde **404 Not Found**, no 403 Forbidden.

Un 403 confirmaría que el recurso existe. Iterando identificadores
(`/incidentes/1`, `/2`, `/3`…) alguien podría deducir cuántos incidentes hay
abiertos sin leer ninguno. Esa fuga es un caso de **A01:2021 – Broken Access
Control** del OWASP Top 10. Con 404 uniforme, «no existe» y «existe y no es
tuyo» son indistinguibles desde afuera.

El 403 sí se usa cuando el permiso falta por completo —por ejemplo, un AUDITOR
intentando editar—, porque ahí no se revela nada: el rol ya sabe que la
operación existe.

### 6.3 Verificación en el servidor

El frontend oculta los botones que el rol no puede usar, pero esa no es la
decisión real. Ocultar no es autorizar: la comprobación que cuenta ocurre en
el servidor, en cada ruta.

### 6.4 Registro de decisiones

Todo intento denegado es un evento de seguridad —puede ser un error honesto o
un intento de escalada de privilegios— y debe quedar registrado con el
usuario, la acción y la ruta. En la bitácora no se escribe nunca un token, una
contraseña ni un secreto.

El cumplimiento de este punto es parcial: ver **H2** en `HALLAZGOS.md`.

## 7. Verificación

Automatizada en `verificacion/pruebas_autorizacion.py`, que ejecuta la
aplicación real.

| Bloque | Comprobaciones | Resultado |
|---|---|---|
| 1 — Matriz rol × ruta | 25 | 25 conforme |
| 2 — Aislamiento por propietario | 4 | 4 conforme |
| 3 — Controles complementarios | 3 | 3 conforme |
| 4 — Hallazgos de la revisión | 3 | 3 abiertos |

Las comprobaciones centrales son la 27, que demuestra que un recurso ajeno es
indistinguible de uno inexistente, y la 30, que demuestra que sin sesión no se
concede nada.
