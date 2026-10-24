"""A loopback-only server owned by one waiting commit review."""
import asyncio
import difflib
import secrets
import socket
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict
from barakagate.review import ReviewError

STATIC = Path(__file__).parent / 'static'


class Revision(BaseModel):
    model_config = ConfigDict(extra='forbid')
    revision: int


class Edit(Revision):
    path: str | None = None
    content: str | None = None
    regions: list[list[float]] | None = None
    style: str | None = None
    decisions: dict[str, str] | None = None


def create_review_app(session):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    mutex = threading.RLock()

    @app.middleware('http')
    async def protect(request: Request, call_next):
        host = request.url.hostname
        if host not in ('127.0.0.1', 'localhost', 'testserver'):
            return JSONResponse({'detail': 'Invalid host'}, status_code=403)
        if request.headers.get('origin') and request.headers['origin'] != f'{request.url.scheme}://{request.url.netloc}':
            return JSONResponse({'detail': 'Cross-origin access denied'}, status_code=403)
        if request.url.path.startswith('/api/'):
            token = request.headers.get('authorization', '').removeprefix('Bearer ')
            if not secrets.compare_digest(token, session.token):
                return JSONResponse({'detail': 'Review credential required'}, status_code=401)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' blob: data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @app.exception_handler(ReviewError)
    async def review_error(request, exc):
        return JSONResponse({'detail': str(exc)}, status_code=409)

    @app.get('/')
    def page():
        return FileResponse(STATIC / 'review.html')

    @app.get('/static/{name}')
    def asset(name: str):
        if name not in ('review.js', 'review.css'):
            return Response(status_code=404)
        return FileResponse(STATIC / name)

    @app.get('/api/review')
    def get_review():
        with mutex:
            session.last_seen = time.monotonic()
            return session.public()

    @app.put('/api/review')
    def edit(body: Edit):
        with mutex:
            return session.update(**body.model_dump(exclude_none=True))

    @app.post('/api/review/validate')
    def validate(body: Revision):
        with mutex:
            return session.validate(body.revision)

    @app.post('/api/review/approve')
    def approve(body: Revision):
        with mutex:
            return session.approve(body.revision)

    @app.post('/api/review/cancel')
    def cancel():
        with mutex:
            return session.cancel()

    @app.post('/api/review/heartbeat')
    def heartbeat():
        with mutex:
            session.last_seen = time.monotonic()
            return {'state': session.state}

    @app.get('/api/review/image')
    def image(path: str, proposed: bool = False):
        with mutex:
            if path not in session.files or session.files[path]['kind'] != 'image':
                return Response(status_code=404)
            return Response(session.image_bytes(path, proposed), media_type='application/octet-stream')

    @app.get('/api/review/preview')
    def preview():
        with mutex:
            return {'revision': session.revision, 'files': {p: ''.join(difflib.unified_diff(
                f['original'].splitlines(keepends=True), f['proposed'].splitlines(keepends=True),
                fromfile='staged/' + p, tofile='proposed/' + p))
                for p, f in session.files.items() if f['kind'] == 'text'}}
    return app


def serve_review(session, output=print):
    import uvicorn
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_review_app(session), log_level='error', access_log=False))
    url = f'http://127.0.0.1:{port}/#token={session.token}'
    output('Review in your browser: ' + url)

    async def run():
        task = asyncio.create_task(server.serve(sockets=[sock]))
        while not server.started and not task.done():
            await asyncio.sleep(.05)
        if server.started and session.policy.open_browser:
            await asyncio.to_thread(webbrowser.open, url)
        while not task.done() and session.state == 'reviewing':
            if time.monotonic() - session.last_seen > session.policy.timeout_seconds:
                session.cancel()
                output('Review expired; commit cancelled.')
                break
            await asyncio.sleep(.2)
        # Allow the approval response and terminal page to render before teardown.
        await asyncio.sleep(1)
        server.should_exit = True
        await task
    try:
        asyncio.run(run())
    finally:
        sock.close()
        if session.state == 'reviewing':
            session.cancel()
    return session.state == 'approved'
