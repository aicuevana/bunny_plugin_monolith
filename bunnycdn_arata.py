"""
bunnycdn_arata.py
─────────────────
The last bunny.net SDK you'll ever need. One file. Four APIs. Async-first.

USAGE (FastAPI):

    from fastapi import FastAPI, Depends
    from bunnycdn_arata import bunny_lifespan, get_bunny, BunnyClient

    app = FastAPI(lifespan=bunny_lifespan)

    @app.get("/upload")
    async def upload(bunny: BunnyClient = Depends(get_bunny)):
        url = await bunny.storage.upload_bytes("user_42", "pic.jpg", b"...", "image/jpeg")
        return {"url": url}

USAGE (standalone script):

    import asyncio
    from bunnycdn_arata import BunnyClient

    async def main():
        async with BunnyClient.standalone() as bunny:
            videos = await bunny.stream.list_videos()
            print(videos)

    asyncio.run(main())

.env (BUNNY_-prefixed):

    BUNNY_STORAGE_KEY=...
    BUNNY_STORAGE_ZONE=my-zone
    BUNNY_STORAGE_ENDPOINT=la.storage.bunnycdn.com
    BUNNY_CDN_HOST=my-zone.b-cdn.net
    BUNNY_STREAM_KEY=...
    BUNNY_LIBRARY_ID=12345
    BUNNY_PULL_ZONE=vz-xxxxxx
    BUNNY_STREAM_WEBHOOK_SECRET=...
    BUNNY_CORE_KEY=...
    BUNNY_TOKEN_SECURITY_KEY=...
    BUNNY_TOKEN_EXPIRES=3600
    BUNNY_USE_TOKEN_AUTH=true
    BUNNY_TIMEOUT=120
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import time
import urllib.parse
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, AsyncIterator, Optional
from urllib.parse import quote

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()  # honor a project-level .env even outside pydantic-settings

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# 1. SETTINGS  —  one source of truth, cached forever
# ════════════════════════════════════════════════════════════════════════════

class BunnySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="BUNNY_",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Storage ──
    storage_key: str = Field(default="", description="Storage zone password")
    storage_zone: str = Field(default="", description="Storage zone name")
    storage_endpoint: str = Field(
        default="storage.bunnycdn.com",
        description="storage.bunnycdn.com / la / ny / sg / uk / se / br / jh / syd",
    )
    cdn_host: str = Field(default="", description="myzone.b-cdn.net")

    # ── Stream ──
    stream_key: str = Field(default="", description="Video library API key")
    library_id: str = Field(default="", description="Stream library ID")
    pull_zone: str = Field(default="", description="vz-xxxxxx (no .b-cdn.net)")
    stream_webhook_secret: str = Field(default="", description="Library Read-Only key")

    # ── Core / Account ──
    core_key: str = Field(default="", description="Account-level API key")

    # ── Token Auth (CDN + Embed) ──
    token_security_key: str = Field(default="")
    token_expires: int = Field(default=3600, description="Seconds until tokens expire")
    use_token_auth: bool = Field(default=True)

    # ── Networking ──
    timeout: float = Field(default=120.0)


@lru_cache(maxsize=1)
def get_settings() -> BunnySettings:
    return BunnySettings()


# ════════════════════════════════════════════════════════════════════════════
# 2. SIGNER  —  all token math in one place (SHA256 everywhere)
# ════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CDNToken:
    token: str
    expires: int
    token_path: str

    def query(self) -> str:
        return (
            f"token={self.token}"
            f"&expires={self.expires}"
            f"&token_path={urllib.parse.quote(self.token_path)}"
        )


class BunnySigner:
    """Embed tokens, CDN tokens, TUS signatures, webhook verification."""

    def __init__(self, security_key: str, default_expires: int = 3600,
                 webhook_secret: str = ""):
        self.security_key = security_key
        self.default_expires = default_expires
        self.webhook_secret = webhook_secret

    @staticmethod
    def _sha256_hex(*parts: str) -> str:
        return hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()

    @staticmethod
    def _sha256_b64url(*parts: str) -> str:
        digest = hashlib.sha256("".join(parts).encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    def _expires_at(self, expires: Optional[int]) -> int:
        if expires is None:
            return int(time.time()) + self.default_expires
        # Treat large values as absolute UNIX timestamps, small as seconds-from-now
        return expires if expires > 10**9 else int(time.time()) + expires

    # ── Embed (Stream iframe) ─────────────────────────────────────────────
    def embed(self, video_id: str, expires: Optional[int] = None) -> tuple[str, int]:
        if not self.security_key:
            logger.warning("BUNNY_TOKEN_SECURITY_KEY missing — empty embed token")
            return "", 0
        exp = self._expires_at(expires)
        return self._sha256_hex(self.security_key, video_id, str(exp)), exp

    def embed_url(self, library_id: str, video_id: str, autoplay: bool = False,
                  preload: bool = True, expires: Optional[int] = None) -> str:
        base = f"https://iframe.mediadelivery.net/embed/{library_id}/{video_id}"
        params = (
            f"autoplay={'true' if autoplay else 'false'}"
            f"&preload={'true' if preload else 'false'}"
        )
        if not self.security_key:
            return f"{base}?{params}"
        token, exp = self.embed(video_id, expires)
        return f"{base}?{params}&token={token}&expires={exp}"

    # ── CDN (HLS, files) ──────────────────────────────────────────────────
    def cdn(self, url_path: str, expires: Optional[int] = None) -> CDNToken:
        clean = url_path.lstrip("/")
        exp = self._expires_at(expires)
        if not self.security_key:
            return CDNToken("", exp, f"/{clean}")
        token = self._sha256_b64url(self.security_key, clean, str(exp))
        return CDNToken(token=token, expires=exp, token_path=f"/{clean}")

    def hls_url(self, pull_zone: str, video_id: str,
                expires: Optional[int] = None) -> str:
        base = f"https://{pull_zone}.b-cdn.net/{video_id}/playlist.m3u8"
        if not self.security_key:
            return base
        return f"{base}?{self.cdn(f'{video_id}/', expires).query()}"

    # ── TUS resumable upload signature ────────────────────────────────────
    def tus(self, library_id: str, api_key: str, video_id: str,
            expires: Optional[int] = None) -> tuple[str, int]:
        exp = self._expires_at(expires or 3600)
        sig = self._sha256_hex(library_id, api_key, str(exp), video_id)
        return sig, exp

    # ── Webhook signature (HMAC-SHA256) ───────────────────────────────────
    def verify_webhook(self, body: bytes, header_signature: str) -> bool:
        if not self.webhook_secret or not header_signature:
            return False
        expected = hmac.new(
            self.webhook_secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, header_signature.lower())


# ════════════════════════════════════════════════════════════════════════════
# 3. BASE CLIENT  —  shared httpx wiring
# ════════════════════════════════════════════════════════════════════════════

class _BaseBunnyClient:
    """Tiny wrapper that injects AccessKey on every call to a fixed base_url."""

    def __init__(self, base_url: str, access_key: str, http: httpx.AsyncClient):
        self.base_url = base_url.rstrip("/")
        self.access_key = access_key
        self.http = http

    def _headers(self, extra: Optional[dict] = None) -> dict:
        h = {"AccessKey": self.access_key, "Accept": "application/json"}
        if extra:
            h.update(extra)
        return h

    def _url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    async def _request(self, method: str, path: str, *, json: Any = None,
                       content: Optional[bytes] = None, params: Optional[dict] = None,
                       headers: Optional[dict] = None,
                       raise_for_status: bool = True) -> httpx.Response:
        resp = await self.http.request(
            method, self._url(path),
            json=json, content=content, params=params,
            headers=self._headers(headers),
        )
        if raise_for_status:
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError:
                logger.error("Bunny %s %s → %s: %s",
                             method, path, resp.status_code, resp.text[:500])
                raise
        return resp

    async def _get(self, path: str, **kw):    return await self._request("GET", path, **kw)
    async def _post(self, path: str, **kw):   return await self._request("POST", path, **kw)
    async def _put(self, path: str, **kw):    return await self._request("PUT", path, **kw)
    async def _delete(self, path: str, **kw): return await self._request("DELETE", path, **kw)


# ════════════════════════════════════════════════════════════════════════════
# 4. STORAGE CLIENT  —  Edge Storage (upload, list, delete, download)
# ════════════════════════════════════════════════════════════════════════════

class StorageClient(_BaseBunnyClient):
    def __init__(self, http: httpx.AsyncClient, *, endpoint: str, zone: str,
                 key: str, cdn_host: str):
        super().__init__(f"https://{endpoint}", key, http)
        self.zone = zone
        self.cdn_host = cdn_host
        if not key:
            logger.warning("Bunny storage_key missing — uploads will 401")

    def _zone_path(self, *parts: str) -> str:
        joined = "/".join(p.strip("/") for p in (self.zone, *parts) if p)
        return quote(joined, safe="/")

    def cdn_url(self, *parts: str) -> str:
        path = "/".join(p.strip("/") for p in parts if p)
        return f"https://{self.cdn_host}/{quote(path, safe='/')}"

    async def upload_bytes(self, path_prefix: str, filename: str, data: bytes,
                           content_type: str = "application/octet-stream",
                           randomize: bool = True) -> str:
        """PUT raw bytes. Returns public CDN URL."""
        safe_name = f"{uuid.uuid4().hex[:12]}_{filename}" if randomize else filename
        await self._put(
            f"/{self._zone_path(path_prefix, safe_name)}",
            content=data,
            headers={"Content-Type": content_type},
        )
        url = self.cdn_url(path_prefix, safe_name)
        logger.info("Bunny upload: %s (%d bytes)", url, len(data))
        return url

    async def upload_from_url(self, path_prefix: str, source_url: str,
                              ext: Optional[str] = None) -> str:
        """Pipe a remote URL straight into storage. Sniffs content-type."""
        resp = await self.http.get(source_url)
        resp.raise_for_status()
        ct = resp.headers.get("content-type", "application/octet-stream").split(";")[0].strip()
        if not ext:
            ext = {
                "image/png": ".png",  "image/jpeg": ".jpg", "image/webp": ".webp",
                "image/gif": ".gif",  "video/mp4": ".mp4",  "audio/mpeg": ".mp3",
                "application/pdf": ".pdf",
            }.get(ct, ".bin")
        return await self.upload_bytes(path_prefix, f"file{ext}", resp.content, ct)

    async def list(self, path: str = "") -> list[dict]:
        resp = await self._get(f"/{self._zone_path(path)}/")
        return resp.json()

    async def download(self, path: str) -> bytes:
        return (await self._get(f"/{self._zone_path(path)}")).content

    async def delete(self, path: str) -> bool:
        r = await self._delete(f"/{self._zone_path(path)}", raise_for_status=False)
        return r.status_code in (200, 204, 404)

    async def exists(self, path: str) -> bool:
        r = await self._request("GET", f"/{self._zone_path(path)}", raise_for_status=False)
        return r.status_code == 200


# ════════════════════════════════════════════════════════════════════════════
# 5. STREAM CLIENT  —  Video Library / Stream API
# ════════════════════════════════════════════════════════════════════════════

class StreamClient(_BaseBunnyClient):
    def __init__(self, http: httpx.AsyncClient, *, library_id: str, key: str):
        super().__init__("https://video.bunnycdn.com", key, http)
        self.library_id = library_id
        if not key or not library_id:
            logger.warning("Bunny stream_key/library_id missing — stream calls will fail")

    def _lib(self, *path: str) -> str:
        suffix = "/".join(p.strip("/") for p in path if p)
        return f"/library/{self.library_id}/{suffix}".rstrip("/")

    # ── videos ────────────────────────────────────────────────────────────
    async def list_videos(self, page: int = 1, per_page: int = 100,
                          search: str = "",
                          collection_id: Optional[str] = None) -> dict:
        params: dict = {"page": page, "itemsPerPage": per_page}
        if search:        params["search"] = search
        if collection_id: params["collection"] = collection_id
        return (await self._get(self._lib("videos"), params=params)).json()

    async def get_video(self, video_id: str) -> dict:
        return (await self._get(self._lib("videos", video_id))).json()

    async def create_video(self, title: str, collection_id: Optional[str] = None,
                           thumbnail_time: Optional[int] = None) -> dict:
        body: dict = {"title": title}
        if collection_id:  body["collectionId"] = collection_id
        if thumbnail_time: body["thumbnailTime"] = thumbnail_time
        return (await self._post(
            self._lib("videos"), json=body,
            headers={"Content-Type": "application/json"},
        )).json()

    async def upload_video(self, video_id: str, data: bytes,
                           content_type: str = "application/octet-stream") -> dict:
        resp = await self._put(
            self._lib("videos", video_id),
            content=data,
            headers={"Content-Type": content_type},
        )
        return resp.json() if resp.content else {"ok": True}

    async def upload_video_full(self, title: str, data: bytes,
                                content_type: str = "video/mp4",
                                collection_id: Optional[str] = None) -> dict:
        """Convenience: create + upload in one call. Returns the created video."""
        created = await self.create_video(title, collection_id=collection_id)
        await self.upload_video(created["guid"], data, content_type)
        return created

    async def fetch_video(self, url: str, title: Optional[str] = None,
                          collection_id: Optional[str] = None,
                          headers: Optional[dict] = None) -> dict:
        """Tell Bunny to pull a video from a remote URL (no proxying through us)."""
        body: dict = {"url": url}
        if title:         body["title"] = title
        if collection_id: body["collectionId"] = collection_id
        if headers:       body["headers"] = headers
        return (await self._post(
            self._lib("videos", "fetch"), json=body,
            headers={"Content-Type": "application/json"},
        )).json()

    async def delete_video(self, video_id: str) -> bool:
        r = await self._delete(self._lib("videos", video_id), raise_for_status=False)
        return r.status_code in (200, 204, 404)

    async def reencode(self, video_id: str) -> dict:
        return (await self._post(self._lib("videos", video_id, "reencode"))).json()

    async def set_thumbnail(self, video_id: str, thumbnail_url: str) -> dict:
        return (await self._post(
            self._lib("videos", video_id, "thumbnail"),
            params={"thumbnailUrl": thumbnail_url},
        )).json()

    # ── captions ──────────────────────────────────────────────────────────
    async def add_caption(self, video_id: str, srclang: str, label: str,
                          captions_data: bytes) -> dict:
        body = {
            "srclang": srclang,
            "label": label,
            "captionsFile": base64.b64encode(captions_data).decode("ascii"),
        }
        return (await self._post(
            self._lib("videos", video_id, "captions", srclang),
            json=body, headers={"Content-Type": "application/json"},
        )).json()

    async def delete_caption(self, video_id: str, srclang: str) -> bool:
        r = await self._delete(
            self._lib("videos", video_id, "captions", srclang),
            raise_for_status=False,
        )
        return r.status_code in (200, 204, 404)

    # ── collections ───────────────────────────────────────────────────────
    async def list_collections(self, page: int = 1, per_page: int = 100) -> dict:
        return (await self._get(
            self._lib("collections"),
            params={"page": page, "itemsPerPage": per_page,
                    "includeThumbnails": "true"},
        )).json()

    async def create_collection(self, name: str) -> dict:
        return (await self._post(
            self._lib("collections"),
            json={"name": name},
            headers={"Content-Type": "application/json"},
        )).json()

    async def delete_collection(self, collection_id: str) -> bool:
        r = await self._delete(self._lib("collections", collection_id),
                               raise_for_status=False)
        return r.status_code in (200, 204, 404)


# ════════════════════════════════════════════════════════════════════════════
# 6. CORE CLIENT  —  account: purge cache, list zones, manage libraries
# ════════════════════════════════════════════════════════════════════════════

class CoreClient(_BaseBunnyClient):
    def __init__(self, http: httpx.AsyncClient, *, key: str):
        super().__init__("https://api.bunny.net", key, http)

    # ── cache ─────────────────────────────────────────────────────────────
    async def purge_url(self, url: str, async_purge: bool = False) -> bool:
        r = await self._post(
            "/purge",
            params={"url": url, "async": str(async_purge).lower()},
            raise_for_status=False,
        )
        return r.status_code in (200, 204)

    async def purge_pull_zone(self, pull_zone_id: int,
                              cache_tag: Optional[str] = None) -> bool:
        body = {"CacheTag": cache_tag} if cache_tag else None
        r = await self._post(
            f"/pullzone/{pull_zone_id}/purgeCache",
            json=body,
            headers={"Content-Type": "application/json"} if body else None,
            raise_for_status=False,
        )
        return r.status_code in (200, 204)

    # ── pull zones ────────────────────────────────────────────────────────
    async def list_pull_zones(self, page: int = 1, per_page: int = 100) -> dict:
        return (await self._get(
            "/pullzone", params={"page": page, "perPage": per_page}
        )).json()

    async def get_pull_zone(self, pull_zone_id: int) -> dict:
        return (await self._get(f"/pullzone/{pull_zone_id}")).json()

    # ── storage zones ─────────────────────────────────────────────────────
    async def list_storage_zones(self) -> list[dict]:
        return (await self._get("/storagezone")).json()

    # ── video libraries ───────────────────────────────────────────────────
    async def list_video_libraries(self) -> list[dict]:
        return (await self._get("/videolibrary")).json()

    async def get_video_library(self, library_id: int) -> dict:
        return (await self._get(f"/videolibrary/{library_id}")).json()


# ════════════════════════════════════════════════════════════════════════════
# 7. FACADE  —  one object, four APIs, one connection pool
# ════════════════════════════════════════════════════════════════════════════

class BunnyClient:
    """
    Composition root. Reuses a single httpx.AsyncClient across all sub-clients.

        async with BunnyClient.standalone() as bunny:
            url = await bunny.storage.upload_bytes("user_42", "pic.jpg", data, "image/jpeg")
            await bunny.stream.create_video("Hello")
            playback = bunny.hls_url(video_id)
            await bunny.core.purge_url("https://cdn.example.com/foo.jpg")
    """

    def __init__(self, settings: BunnySettings, http: httpx.AsyncClient):
        self.settings = settings
        self.http = http

        self.storage = StorageClient(
            http,
            endpoint=settings.storage_endpoint,
            zone=settings.storage_zone,
            key=settings.storage_key,
            cdn_host=settings.cdn_host,
        )
        self.stream = StreamClient(
            http, library_id=settings.library_id, key=settings.stream_key,
        )
        self.core = CoreClient(http, key=settings.core_key)
        self.signer = BunnySigner(
            security_key=settings.token_security_key,
            default_expires=settings.token_expires,
            webhook_secret=settings.stream_webhook_secret,
        )

    # ── ergonomic shortcuts ───────────────────────────────────────────────
    def embed_url(self, video_id: str, **kw) -> str:
        if not self.settings.use_token_auth or not self.settings.token_security_key:
            return (
                f"https://iframe.mediadelivery.net/embed/"
                f"{self.settings.library_id}/{video_id}?autoplay=false&preload=true"
            )
        return self.signer.embed_url(self.settings.library_id, video_id, **kw)

    def hls_url(self, video_id: str, **kw) -> str:
        if not self.settings.use_token_auth or not self.settings.token_security_key:
            return f"https://{self.settings.pull_zone}.b-cdn.net/{video_id}/playlist.m3u8"
        return self.signer.hls_url(self.settings.pull_zone, video_id, **kw)

    @classmethod
    def standalone(cls, settings: Optional[BunnySettings] = None) -> "BunnyClient":
        s = settings or get_settings()
        return cls(s, httpx.AsyncClient(timeout=s.timeout))

    async def aclose(self):
        await self.http.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.aclose()


# ════════════════════════════════════════════════════════════════════════════
# 8. FASTAPI INTEGRATION  —  lifespan, dependency, webhook verifier
# ════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def bunny_lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Use as `app = FastAPI(lifespan=bunny_lifespan)`."""
    settings = get_settings()
    async with httpx.AsyncClient(timeout=settings.timeout) as http:
        app.state.bunny = BunnyClient(settings, http)
        logger.info("BunnyClient ready (zone=%s, library=%s)",
                    settings.storage_zone, settings.library_id)
        try:
            yield
        finally:
            logger.info("BunnyClient shutting down")


def get_bunny(request: Request) -> BunnyClient:
    """FastAPI dependency: `bunny: BunnyClient = Depends(get_bunny)`."""
    bunny = getattr(request.app.state, "bunny", None)
    if bunny is None:
        raise RuntimeError(
            "BunnyClient not initialized. Add `lifespan=bunny_lifespan` to FastAPI()."
        )
    return bunny


def get_bunny_settings() -> BunnySettings:
    return get_settings()


async def verify_bunny_webhook(
    request: Request,
    x_bunnystream_signature: str = Header(..., alias="X-BunnyStream-Signature"),
    x_bunnystream_signature_version: str = Header("v1", alias="X-BunnyStream-Signature-Version"),
    bunny: BunnyClient = Depends(get_bunny),
) -> bytes:
    """
    Use on Stream webhook routes:

        @app.post("/webhooks/bunny")
        async def hook(body: bytes = Depends(verify_bunny_webhook)):
            payload = json.loads(body)
            ...
    """
    body = await request.body()
    if not bunny.signer.verify_webhook(body, x_bunnystream_signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Bunny webhook signature",
        )
    return body


# ════════════════════════════════════════════════════════════════════════════
# 9. PYDANTIC MIXIN  —  drop into any model with a `video_id` field
# ════════════════════════════════════════════════════════════════════════════

class SignedVideoMixin(BaseModel):
    """
    Mix into any pydantic model that has a `video_id: str` field.
    Inherits two computed properties: `video_embed_url` and `video_hls_url`.

        class Module(SignedVideoMixin):
            id: str
            video_id: str
            name: str
    """
    video_id: str

    @staticmethod
    def _signer_and_settings():
        s = get_settings()
        return s, BunnySigner(
            security_key=s.token_security_key,
            default_expires=s.token_expires,
            webhook_secret=s.stream_webhook_secret,
        )

    @computed_field  # type: ignore[misc]
    @property
    def video_embed_url(self) -> str:
        s, signer = self._signer_and_settings()
        if not s.use_token_auth or not s.token_security_key:
            return (
                f"https://iframe.mediadelivery.net/embed/"
                f"{s.library_id}/{self.video_id}?autoplay=false&preload=true"
            )
        return signer.embed_url(s.library_id, self.video_id)

    @computed_field  # type: ignore[misc]
    @property
    def video_hls_url(self) -> str:
        s, signer = self._signer_and_settings()
        if not s.use_token_auth or not s.token_security_key:
            return f"https://{s.pull_zone}.b-cdn.net/{self.video_id}/playlist.m3u8"
        return signer.hls_url(s.pull_zone, self.video_id)


__all__ = [
    "BunnySettings", "get_settings",
    "BunnySigner", "CDNToken",
    "StorageClient", "StreamClient", "CoreClient", "BunnyClient",
    "bunny_lifespan", "get_bunny", "get_bunny_settings", "verify_bunny_webhook",
    "SignedVideoMixin",
]
