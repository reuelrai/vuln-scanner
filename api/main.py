from fastapi import FastAPI

app = FastAPI(title="Vulnerability Scanner API")


@app.get("/health")
def health():
    return {"status": "ok"}