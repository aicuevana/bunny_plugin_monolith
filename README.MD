```markdown
# BunnyCDN Arata SDK (`bunnycdn_arata.py`)

## What is our goal

Provide a **single-file, async-first, procedural Python SDK** for bunny.net (BunnyCDN) that unifies four APIs—**Edge Storage**, **Stream Video**, **Core Platform**, and **Token Authentication**—into one persistent `httpx.AsyncClient` interface. It is designed to drop into any FastAPI application via lifespan managers and dependency injection, but works identically in standalone async scripts, CLIs, or workers.

## Context

Bunny.net exposes multiple APIs with different base URLs, auth headers, and payload rules:

| API | Base URL | Key Type | Purpose |
|---|---|---|---|
| **Core** | `https://api.bunny.net` | Account API Key | Purge cache, manage zones, libraries, DNS |
| **Edge Storage** | `https://{region}.storage.bunnycdn.com` | Storage Zone Password | Upload/download/list/delete files |
| **Stream** | `https://video.bunnycdn.com` | Library API Key | Upload videos, collections, captions |
| **Token Auth** | N/A (client-side signing) | Pull-Zone Security Key | Sign embed & CDN URLs to prevent hotlinking |

Managing separate clients, connection pools, URL-encoding, signatures, and webhook verification manually is error-prone. This library abstracts all of that. It reads secrets from a `.env` file (via `pydantic-settings`), reuses one HTTP connection pool, exposes simple async methods, and includes FastAPI-specific helpers for lifespan management and webhook HMAC verification.

---

## Usage

### 1. Configuration (`.env`)

**What it is**  
A cached `pydantic-settings` loader that reads environment variables prefixed with `BUNNY_`.

**How to use**  
Create a `.env` file in your project root. All fields are optional at import time, but the sub-client you use will warn or fail at runtime if its required key is missing.

```bash
# ── Edge Storage ──
BUNNY_STORAGE_KEY=your-storage-zone-password
BUNNY_STORAGE_ZONE=myzone
BUNNY_STORAGE_ENDPOINT=la.storage.bunnycdn.com
BUNNY_CDN_HOST=myzone.b-cdn.net

# ── Stream Video ──
BUNNY_STREAM_KEY=your-video-library-api-key
BUNNY_LIBRARY_ID=12345
BUNNY_PULL_ZONE=vz-xxxxxx
BUNNY_STREAM_WEBHOOK_SECRET=your-library-readonly-key

# ── Core Platform ──
BUNNY_CORE_KEY=your-account-api-key

# ── Token Authentication (Embed + CDN) ──
BUNNY_TOKEN_SECURITY_KEY=your-pull-zone-token-key
BUNNY_TOKEN_EXPIRES=3600
BUNNY_USE_TOKEN_AUTH=true

# ── Networking ──
BUNNY_TIMEOUT=120.0
```

**Why**  
Centralizes secrets, avoids hardcoding credentials in source control, and validates types automatically. The loader is cached with `@lru_cache`, so calling `get_settings()` multiple times is free.

---

### 2. Standalone / Script Usage

**What it is**  
Initialize the unified `BunnyClient` with a settings object and an `httpx.AsyncClient`, then call procedural async methods.

**How to use**  

```python
import asyncio
import httpx
from bunnycdn_arata import BunnyClient, get_settings

async def main():
    settings = get_settings()
    async with httpx.AsyncClient(timeout=settings.timeout) as http:
        bunny = BunnyClient(settings, http)

        # ── Storage ──
        url = await bunny.storage.upload_bytes(
            path_prefix="avatars",
            filename="user1.jpg",
            data=b"<raw image bytes>",
            content_type="image/jpeg",
            randomize=True,          # Prefixes filename with 12-char UUID
        )
        print("CDN URL:", url)

        # ── Stream ──
        video = await bunny.stream.create_video(title="Welcome")
        print("Reserved video ID:", video["guid"])

        # ── Core ──
        ok = await bunny.core.purge_url("https://myzone.b-cdn.net/avatars/user1.jpg")
        print("Purged:", ok)

asyncio.run(main())
```

**Why**  
Useful for admin scripts, one-off migrations, background workers, or Jupyter notebooks where FastAPI is not running. You control the `httpx.AsyncClient` lifetime, so connection pooling still works.

---

### 3. FastAPI Integration (Lifespan + Dependency Injection)

**What it is**  
A lifespan context manager (`bunny_lifespan`) attaches a single `BunnyClient` instance to `app.state`. A dependency getter (`get_bunny`) injects that instance into routes.

**How to use**  

```python
from fastapi import FastAPI, Depends
from bunnycdn_arata import BunnyClient, bunny_lifespan, get_bunny

app = FastAPI(lifespan=bunny_lifespan)

@app.post("/upload-report")
async def upload_report(
    bunny: BunnyClient = Depends(get_bunny),
):
    cdn_url = await bunny.storage.upload_bytes(
        path_prefix="reports",
        filename="monthly.pdf",
        data=b"%PDF...",
        content_type="application/pdf",
    )
    return {"cdn_url": cdn_url}
```

**Why**  
This guarantees **one shared connection pool** across all requests, proper lifecycle cleanup on server shutdown, and makes the SDK trivial to mock during testing by overriding `app.state.bunny`.

---

### 4. Edge Storage Operations

**What it is**  
CRUD for Bunny Edge Storage. The client automatically URL-encodes paths, joins the storage zone name, and generates public CDN URLs.

**How to use**  

```python
# Upload raw bytes. Returns the public CDN URL.
cdn_url = await bunny.storage.upload_bytes(
    path_prefix="users/42",          # becomes /{zone}/users/42/
    filename="avatar.png",
    data=png_bytes,
    content_type="image/png",
    randomize=True,                  # safe_name = {uuid12}_avatar.png
)

# Fetch a remote URL and pipe it directly into storage.
# Sniffs Content-Type and guesses extension automatically.
cdn_url = await bunny.storage.upload_from_url(
    path_prefix="users/42",
    source_url="https://example.com/photo.jpg",
)

# List a directory relative to the zone root.
items: list[dict] = await bunny.storage.list(path="users/42")

# Download a file.
file_bytes: bytes = await bunny.storage.download("users/42/avatar.png")

# Delete a file. Returns True on success or 404.
deleted: bool = await bunny.storage.delete("users/42/old.png")

# Check existence without raising on 404.
exists: bool = await bunny.storage.exists("users/42/avatar.png")

# Convert any storage path to a public CDN URL manually.
url: str = bunny.storage.cdn_url("users/42", "avatar.png")
```

**Why**  
Abstracts away Bunny’s path encoding rules, trailing-slash requirements for `LIST`, and the difference between the storage endpoint (write) and the CDN host (public read).

---

### 5. Stream Video Operations

**What it is**  
Two-step uploads (reserve slot → send binary), remote URL fetching, captions, collections, and re-encoding.

**How to use**  

```python
# Step 1: Reserve a video slot.
video = await bunny.stream.create_video(
    title="Lesson 4",
    collection_id="optional-collection-guid",
    thumbnail_time=15000,            # ms into video for thumbnail
)

# Step 2: Upload raw MP4 bytes.
await bunny.stream.upload_video(
    video_id=video["guid"],
    data=mp4_bytes,
    content_type="video/mp4",
)

# Convenience: Step 1 + 2 in one call.
video = await bunny.stream.upload_video_full(
    title="Lesson 4", data=mp4_bytes
)

# Server-side fetch: Bunny pulls from a remote URL directly.
video = await bunny.stream.fetch_video(
    url="https://example.com/video.mp4",
    title="Lesson 4",
    collection_id="...",
)

# Management
await bunny.stream.reencode(video_id)
await bunny.stream.set_thumbnail(video_id, "https://example.com/thumb.jpg")
await bunny.stream.delete_video(video_id)

# Search / paginate
result = await bunny.stream.list_videos(
    page=1, per_page=100, search="Lesson", collection_id="..."
)

# Captions (pass raw VTT/SRT bytes; the client base64-encodes them).
await bunny.stream.add_caption(
    video_id, srclang="en", label="English", captions_data=vtt_bytes
)
await bunny.stream.delete_caption(video_id, srclang="en")

# Collections
cols = await bunny.stream.list_collections()
col = await bunny.stream.create_collection("Season 1")
```

**Why**  
Bunny Stream requires a `POST` to create metadata before you can `PUT` the binary. The SDK enforces this flow automatically and handles base64 encoding for captions and JSON payloads for collections.

---

### 6. Core Platform Operations

**What it is**  
Account-level cache purging and zone introspection.

**How to use**  

```python
# Purge a single URL from the CDN edge cache.
ok: bool = await bunny.core.purge_url(
    "https://myzone.b-cdn.net/static/app.css",
    async_purge=False,
)

# Purge an entire pull zone by ID, optionally filtered by cache tag.
ok: bool = await bunny.core.purge_pull_zone(
    pull_zone_id=123456,
    cache_tag="product-99",
)

# Inspect zones
zones = await bunny.core.list_pull_zones(page=1, per_page=100)
zone  = await bunny.core.get_pull_zone(123456)

# Storage zones (management metadata, not file operations)
storage_zones = await bunny.core.list_storage_zones()

# Video libraries (management metadata)
libs = await bunny.core.list_video_libraries()
lib  = await bunny.core.get_video_library(133)
```

**Why**  
Cache invalidation is the most common Core API need in application code. These shortcuts let you purge immediately after a storage upload or database change without constructing raw REST calls.

---

### 7. Signed URLs & Token Authentication (Signer)

**What it is**  
SHA256-based signing for the **Embed iframe** and **CDN HLS/file** endpoints. If `BUNNY_USE_TOKEN_AUTH=false` or no security key is configured, the methods return clean unsigned URLs so your code does not branch.

**How to use**  

```python
# Convenience methods on the facade
embed_url = bunny.embed_url(
    video_id="abc-123",
    autoplay=False,
    preload=True,
)
# → https://iframe.mediadelivery.net/embed/{library_id}/abc-123?...

hls_url = bunny.hls_url(video_id="abc-123")
# → https://{pull_zone}.b-cdn.net/abc-123/playlist.m3u8?token=...&expires=...&token_path=...

# Lower-level signer access
token_hex, expires = bunny.signer.embed(video_id="abc-123", expires=7200)
cdn_token = bunny.signer.cdn(url_path="abc-123/", expires=7200)
query_string = cdn_token.query()
# → token=...&expires=...&token_path=...

# TUS resumable upload signature (for direct browser-to-Bunny uploads).
signature, expires = bunny.signer.tus(
    library_id=bunny.settings.library_id,
    api_key=bunny.settings.stream_key,
    video_id=video_guid,
    expires=3600,
)
```

**Why**  
Prevents hotlinking and unauthorized playback. The signer automatically decides whether a value is an absolute UNIX timestamp or a relative “seconds from now” offset.

---

### 8. Pydantic Model Mixin (Computed Video URLs)

**What it is**  
A `BaseModel` mixin that adds `video_embed_url` and `video_hls_url` computed fields to any Pydantic schema containing a `video_id: str` field.

**How to use**  

```python
from pydantic import BaseModel
from bunnycdn_arata import SignedVideoMixin

class ModuleOut(SignedVideoMixin, BaseModel):
    id: str
    name: str
    video_id: str

# When serialized, the output JSON automatically includes signed URLs:
# {
#   "id": "rec_123",
#   "name": "Intro",
#   "video_id": "vid_456",
#   "video_embed_url": "https://iframe.mediadelivery.net/embed/...",
#   "video_hls_url": "https://vz-xxx.b-cdn.net/.../playlist.m3u8?..."
# }
```

**Why**  
Eliminates manual URL construction in every route. Your frontend receives ready-to-use URLs without the service layer knowing whether token auth is enabled.

---

### 9. Stream Webhook Verification

**What it is**  
A FastAPI dependency that validates the `X-BunnyStream-Signature` header against the library’s **Read-Only API key** using HMAC-SHA256 in constant time.

**How to use**  

```python
from fastapi import APIRouter, Depends
import json
from bunnycdn_arata import verify_bunny_webhook

router = APIRouter()

@router.post("/webhooks/bunny-stream")
async def handle_stream_webhook(
    body: bytes = Depends(verify_bunny_webhook),
):
    payload = json.loads(body)
    # payload keys: VideoLibraryId, VideoGuid, Status (0–10)
    if payload.get("Status") == 3:
        # Video encoding finished
        ...
    return {"ok": True}
```

**Why**  
Protects your webhook endpoint from spoofed callbacks. The dependency returns the raw verified bytes so you can parse JSON, msgpack, or form data yourself.

---

### 10. Error Handling & Logging

**What it is**  
All HTTP 4xx/5xx responses are logged via the standard `logging` module and raised as `httpx.HTTPStatusError`. Destructive operations (`delete`, `purge`) return booleans when a 404 is acceptable.

**How to use**  

```python
import httpx

try:
    await bunny.storage.download("missing/file.txt")
except httpx.HTTPStatusError as exc:
    # exc.response.status_code == 404
    ...

# Idempotent delete returns False on 404 instead of raising.
if await bunny.storage.delete("maybe_missing.txt"):
    print("File removed")
```

**Why**  
Transparent error propagation. You do not need to learn a custom exception hierarchy; standard `httpx` patterns apply everywhere.

---

## Architecture Notes for LLM Consumers

- **Single file**: Everything lives in `bunnycdn_arata.py`. Import names are:
  `BunnyClient`, `BunnySettings`, `get_settings`, `bunny_lifespan`, `get_bunny`, `verify_bunny_webhook`, `SignedVideoMixin`.
- **Lazy settings**: `.env` is parsed only when `get_settings()` is first called.
- **Connection pooling**: Always pass an existing `httpx.AsyncClient` into `BunnyClient(...)`; the FastAPI lifespan helper does this automatically.
- **Auth isolation**: Storage uses the zone password; Stream uses the library key; Core uses the account key. Missing a key only breaks the corresponding sub-client.
- **Opt-out security**: Set `BUNNY_USE_TOKEN_AUTH=false` to receive raw unsigned CDN/Embed URLs from the signer.
```
