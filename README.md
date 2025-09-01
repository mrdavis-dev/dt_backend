# DocuTrack Backend

DocuTrack es un sistema sencillo para gestionar solicitudes y emisión de certificados, desarrollado con FastAPI y PostgreSQL.

## Requisitos
- Python 3.11+
- PostgreSQL
- (Opcional) Docker y Docker Compose

## Instalación manual
1. Copia el archivo de ejemplo de variables de entorno:
   ```
   copy .env.example .env
   ```
   Edita `.env` con tus valores si lo deseas.
2. Instala las dependencias:
   ```
   pip install -r requirements.txt
   ```
3. Asegúrate de tener PostgreSQL corriendo y accesible con los datos de `.env`.
4. Ejecuta el servidor:
   ```
   uvicorn app.main:app --reload --port 8000
   ```

## Uso con Docker
1. Copia el archivo de ejemplo de variables de entorno:
   ```
   copy .env.example .env
   ```
   (En Linux/Mac: `cp .env.example .env`)
2. Levanta los servicios:
   ```
   docker compose up --build
   ```

## Acceso inicial
- Usuario admin: `admin@demo.test`
- Contraseña: `admin123`

## Endpoints principales
- Registro: `POST /api/auth/register`
- Login: `POST /api/auth/login`
- Info usuario: `GET /api/auth/me`
- Solicitar certificado: `POST /api/requests`
- Ver mis solicitudes: `GET /api/requests`
- Descargar certificado: `GET /api/requests/{id}/certificate`
- (Admin) Ver todas: `GET /api/admin/requests`
- (Admin) Cambiar estado: `PATCH /api/admin/requests/{id}/status`

## Notas
- Los certificados se generan en PDF al aprobar una solicitud.
- El sistema es solo una base para pruebas técnicas, no para producción.

---

Cualquier duda, revisa el código fuente o contacta al desarrollador.
