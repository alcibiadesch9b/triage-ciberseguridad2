# Hallazgos de la revisión de autorización

**Revisora:** Jennifer Yau — Integrante 4 (Autorización)
**Objeto revisado:** `app.py`, `db.py` — rama `main`
**Método:** ejecución de `verificacion/pruebas_autorizacion.py` contra la aplicación real
**Resultado global:** 32 de 32 comprobaciones de conformidad superadas, 3 hallazgos abiertos

---

## Resumen

La implementación del control de acceso es correcta en lo esencial. La matriz
rol × recurso se aplica en el servidor, el filtrado por propietario ocurre en
la consulta y no en la interfaz, un recurso ajeno responde 404 en lugar de 403
y los formularios están protegidos contra CSRF. Las 32 comprobaciones de
conformidad con la matriz pasan sin excepción.

Los tres hallazgos que siguen no son fallos de la matriz, sino superficies que
quedaron fuera de ella.

---

## H1 — `/evidencia-token` no exige ningún permiso

**Severidad:** media
**Estado:** abierto

### Descripción

La ruta `/evidencia-token` está protegida únicamente con `@login_required`. No
lleva `@permiso_requerido`, de modo que cualquier usuario autenticado accede,
incluido `ROL_INVITADO`, que es el rol de menor privilegio del sistema.

La página muestra `iss`, `aud`, `azp`, `sub`, `nonce`, `kid`, `alg` y las
marcas de tiempo del ID token de la sesión.

### Evidencia

Comprobación 33 del banco de pruebas. Los cinco roles reciben **200**:

```
ROL_ADMIN     /evidencia-token = 200
ROL_ANALISTA  /evidencia-token = 200
ROL_AUDITOR   /evidencia-token = 200
ROL_USUARIO   /evidencia-token = 200
ROL_INVITADO  /evidencia-token = 200
```

### Análisis

Los datos expuestos no incluyen el token completo ni el Client Secret, así que
no hay compromiso directo de credenciales. Lo que sí revela es la topología de
confianza del sistema: emisor, audiencias, identificador de clave de firma y
algoritmo. Para un atacante con una cuenta de mínimo privilegio, eso es
reconocimiento gratuito.

El propio código la marca como temporal:

```python
# TEMPORAL: solo para capturas del informe. Quitar antes de la entrega final.
```

### Recomendación

Eliminar la ruta y su plantilla antes de la entrega, que es lo que el autor ya
previó. Si se decide conservarla para la sustentación, restringirla al rol
administrador:

```python
@app.route("/evidencia-token")
@login_required
@permiso_requerido("configuracion", "R")   # solo ROL_ADMIN
def evidencia_token():
    ...
```

---

## H2 — Las denegaciones por propiedad no quedan en la bitácora

**Severidad:** media
**Estado:** abierto

### Descripción

El manejador `errorhandler(403)` registra `ACCESO_DENEGADO` en la bitácora.
Pero la función `incidente_accesible()` deniega con `abort(404)` cuando el
incidente existe y pertenece a otro usuario, y ese camino no pasa por ningún
manejador que audite.

Consecuencia: un usuario que tantea identificadores ajenos —el patrón exacto
de un intento de acceso horizontal— no deja ningún rastro.

### Evidencia

Comprobación 34. Dos usuarios finales distintos; el segundo intenta comentar
en el incidente del primero:

```
Beto -> POST /incidentes/1/comentarios   respuesta 404
Bitácora: ningún registro ACCESO_DENEGADO
```

Para contraste, una denegación por falta de permiso sí se registra
(comprobación 32), lo que confirma que el hueco está en esta ruta concreta y
no en el mecanismo de auditoría.

### Análisis

Es la denegación más importante de registrar, precisamente porque es la más
difícil de cometer por accidente. Un usuario no llega a `/incidentes/7/editar`
navegando: llega escribiendo la URL.

Que la respuesta sea 404 es correcto y debe mantenerse — eso es lo que evita
revelar la existencia del recurso. Lo que falta es el registro interno, que no
es visible para el atacante.

### Recomendación

Auditar antes de abortar, dentro de `incidente_accesible()`:

```python
def incidente_accesible(incidente_id):
    incidente = obtener_incidente(incidente_id)
    if incidente is None:
        abort(404)
    if not ve_todos() and incidente["creado_por"] != session["user"].get("sub"):
        auditar("ACCESO_DENEGADO", f"INC-{incidente_id:03d}: recurso ajeno")
        abort(404)
    return incidente
```

La respuesta al cliente no cambia. Solo cambia lo que sabe el sistema.

---

## H3 — `ROL_INVITADO` está fuera de la matriz y recibe conteos globales

**Severidad:** baja
**Estado:** abierto

### Descripción

`ROL_INVITADO` no aparece en el diccionario `PERMISOS`. Su acceso se resuelve
con una rama especial dentro de `dashboard()`:

```python
elif "ROL_INVITADO" in session["user"].get("roles", []):
    stats = calcular_stats(listar_incidentes())
    publico = True
```

Dos consecuencias. La primera es de diseño: hay un rol cuyos permisos no están
en la matriz, sino repartidos en el código, lo que rompe la idea de una fuente
única de verdad. La segunda es de exposición: `listar_incidentes()` sin
argumentos devuelve **todos** los incidentes, y de ahí se calculan los totales
que ve el invitado.

### Evidencia

Comprobación 35. Con incidentes creados por otros usuarios, el panel del
invitado muestra el total real de la organización, incluidos incidentes que
ese rol no puede listar ni abrir.

### Análisis

No se filtran títulos ni descripciones: solo conteos. Pero el número de
incidentes abiertos de una organización es, por sí mismo, información de
postura de seguridad. Un pico de incidentes abiertos visible desde la cuenta
de menor privilegio es una señal que no debería estar disponible ahí.

Puede ser una decisión deliberada —el rol existe para demostrar que
autenticarse no es autorizarse— pero entonces debe estar escrita como
decisión, no implícita en un `elif`.

### Recomendación

Incorporar el rol a la matriz y acotar lo que ve:

```python
PERMISOS = {
    ...
    "estadisticas_publicas": {"ROL_INVITADO": "R"},
}
```

y en el panel, o bien no mostrar conteos, o documentar expresamente en el
informe que los totales agregados se consideran información pública del
sistema de demostración.

---

## Comprobaciones que sí pasaron

Conviene dejarlas registradas: son la parte del control que funciona y que la
revisión confirma.

| Verificado | Resultado |
|---|---|
| Matriz rol × ruta, 5 roles × 5 rutas | 25/25 conforme |
| El usuario final no ve incidentes ajenos en el listado | Conforme |
| Recurso ajeno responde 404, no 403 | Conforme |
| Filtrado por propietario aplicado en la consulta | Conforme |
| Petición sin sesión redirigida al login | Conforme |
| Formulario sin token CSRF rechazado con 400 | Conforme |
| Denegación por falta de permiso registrada en bitácora | Conforme |

---

## Nota sobre el método

El banco de pruebas inyecta la sesión directamente en lugar de autenticarse
contra Keycloak. Esto es intencional: permite ejercitar la **autorización** de
forma aislada, sin que un fallo de red o del proveedor de identidad enmascare
un fallo de permisos. La autenticación se verifica por separado en la Fase 3.

La inyección existe únicamente dentro de `verificacion/pruebas_autorizacion.py`
y no altera la aplicación. En ejecución normal, `session["user"]["roles"]` solo
lo escribe el callback de OIDC tras validar la firma del token contra el JWKS
y comprobar `iss`, `aud` y `exp`.
