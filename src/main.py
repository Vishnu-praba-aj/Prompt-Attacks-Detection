from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .canonical_rewriter import CanonicalPromptRewriter
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

rewriter = CanonicalPromptRewriter()

class PromptRequest(BaseModel):
    prompt: str

@app.post("/canonicalize")
def canonicalize(req: PromptRequest):
    return rewriter.process(req.prompt)

# 👇 Serve React build
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_PATH = os.path.join(BASE_DIR, "../dist")

app.mount("/", StaticFiles(directory=DIST_PATH, html=True), name="static")