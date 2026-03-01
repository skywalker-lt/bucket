import os

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app import database, crypto
from app.routes import auth_routes, vault_routes, verify_routes

app = FastAPI(title="CatVault", docs_url=None, redoc_url=None)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Templates
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# Include routers
app.include_router(auth_routes.router)
app.include_router(vault_routes.router)
app.include_router(verify_routes.router)


@app.on_event("startup")
async def startup():
    await database.init_db()
    crypto.derive_key()
    app.state.templates = templates


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Prevent caching of static assets during development
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    if "Content-Security-Policy" not in response.headers:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://static.cloudflareinsights.com; "
            "connect-src 'self' https://cloudflareinsights.com; "
            "style-src 'self'; img-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
    return response


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    session_token = request.cookies.get("session")
    if session_token and await database.validate_session(session_token):
        return RedirectResponse(url="/vault", status_code=302)
    has_credentials = await database.credential_count() > 0
    return templates.TemplateResponse("login.html", {
        "request": request,
        "has_credentials": has_credentials,
    })
