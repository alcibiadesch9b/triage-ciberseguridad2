# Verificación del control de acceso

**Responsable:** Jennifer Yau — Integrante 4
**Fase:** 5 — Autorización basada en roles (RBAC)
**Asignatura:** Ciberseguridad II — Universidad Tecnológica de Panamá

---

## Contenido

| Archivo | Qué es |
|---|---|
| `MATRIZ_AUTORIZACION.md` | Especificación de la matriz rol × recurso, justificación de mínimo privilegio y decisiones de diseño. |
| `pruebas_autorizacion.py` | Verificación automatizada. Ejecuta la aplicación real y contrasta su comportamiento contra la matriz. |
| `HALLAZGOS.md` | Hallazgos de la revisión, con evidencia y corrección propuesta para cada uno. |

## Qué hace esta carpeta

La matriz dice lo que **debería** ocurrir. La aplicación hace lo que **ocurre**.
Esta carpeta comprueba que ambas cosas coinciden, y documenta dónde no.

No reimplementa la autorización: importa `app.py` tal como está en el
repositorio y la ejercita rol por rol. Si una prueba falla, el defecto está en
la aplicación, no aquí.

## Cómo ejecutarla

Desde la raíz del repositorio:

```
pip install -r requirements.txt
cd verificacion
python pruebas_autorizacion.py
```

No hace falta Keycloak, ni red, ni certificados. La base de datos del proyecto
no se toca: las pruebas usan una temporal.

### Salida esperada

```
Conformidad con la matriz : 32 de 32 comprobaciones superadas
Hallazgos abiertos        : 3 de 3
```

Los tres hallazgos aparecen marcados como `FALLA` **a propósito**. No son
errores del banco de pruebas: son desviaciones reales que siguen abiertas, y
se quedan visibles hasta que se corrijan. Cuando se corrijan, esas tres líneas
pasarán a `OK` solas.

## Por qué se inyecta la sesión

La aplicación decide los permisos leyendo `session["user"]["roles"]`. En
ejecución normal ese valor lo escribe únicamente el callback de OIDC, tras
validar la firma del token contra el JWKS de Keycloak y comprobar `iss`, `aud`
y `exp`.

El banco de pruebas lo escribe directamente. Eso permite aislar la
**autorización** de la **autenticación**: así un fallo de red o del proveedor
de identidad no puede enmascarar un fallo de permisos, ni al revés. La
autenticación se verifica por separado, en la Fase 3.

La inyección vive únicamente en `pruebas_autorizacion.py` y no modifica la
aplicación.

## Hallazgos abiertos

| # | Hallazgo | Severidad |
|---|---|:---:|
| H1 | `/evidencia-token` no exige ningún permiso; accesible hasta para `ROL_INVITADO` | Media |
| H2 | Las denegaciones por propiedad (404) no quedan en la bitácora | Media |
| H3 | `ROL_INVITADO` está fuera de la matriz y recibe conteos globales | Baja |

El detalle, la evidencia y la corrección propuesta de cada uno están en
`HALLAZGOS.md`.
