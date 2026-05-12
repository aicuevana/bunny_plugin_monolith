from fastapi import FastAPI, Depends, UploadFile
from bunnycdn_arata import (
    bunny_lifespan, get_bunny_dep, verify_bunny_webhook, BunnyClient,
    bunny_upload_bytes, bunny_create_video, bunny_purge_url,
)

app = FastAPI(lifespan=bunny_lifespan)


@app.post("/upload-image")
async def upload_image(file: UploadFile):
    data = await file.read()
    url = await bunny_upload_bytes("user_42", file.filename, data, file.content_type)
    return {"url": url}


@app.post("/videos")
async def new_video(title: str, bunny: BunnyClient = Depends(get_bunny_dep)):
    return await bunny.stream.create_video(title)


@app.post("/purge")
async def purge(url: str):
    return {"ok": await bunny_purge_url(url)}


@app.post("/webhooks/bunny")
async def hook(body: bytes = Depends(verify_bunny_webhook)):
    import json
    return {"received": json.loads(body)}
