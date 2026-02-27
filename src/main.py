from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from canonical_rewriter import CanonicalPromptRewriter

app = FastAPI()

# 🔥 ADD THIS BLOCK
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development only
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