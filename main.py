from fastapi import FastAPI, Request, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import uvicorn
import os
import sqlite3
from datetime import datetime
from contextlib import asynccontextmanager
from threat_engine import ThreatEngine
import threat_stream

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start threat streaming ingester in background
    import asyncio
    asyncio.create_task(threat_stream.ingest_threats())
    yield
    
app = FastAPI(title="Link Defender API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure public directory exists
os.makedirs("public", exist_ok=True)
app.mount("/static", StaticFiles(directory="public"), name="static")

engine = ThreatEngine()

# Setup Local SQLite DB
def init_db():
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS history 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT,
                  score INTEGER,
                  verdict TEXT,
                  timestamp TEXT)''')
    conn.commit()
    conn.close()

init_db()

def log_scan(url, score, verdict):
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    c.execute("INSERT INTO history (url, score, verdict, timestamp) VALUES (?, ?, ?, ?)", (url, score, verdict, now))
    conn.commit()
    conn.close()

class AnalyzeRequest(BaseModel):
    urls: List[str]

class AnalyzeEmailRequest(BaseModel):
    message: str

@app.post("/api/analyze")
async def analyze_urls(req: AnalyzeRequest):
    results = []
    for url in req.urls:
        if not url.strip():
            continue
        analysis = engine.analyze(url.strip())
        score = analysis.get("score", 0)
        verdict = "Safe" if score < 20 else "Suspicious" if score < 60 else "Malicious"
        log_scan(url.strip(), score, verdict)
        
        # Inject to live map
        if score >= 20: # Only inject suspicious/malicious to map
            import asyncio
            asyncio.create_task(threat_stream.inject_local_scan(url.strip(), verdict, score))
        
        # Add Gemini AI summary for all links
        ai_summary = engine.generate_url_summary(
            url.strip(), 
            analysis.get("risk", "Unknown"), 
            score, 
            analysis.get("flags", []), 
            analysis.get("details", {})
        )
        
        results.append({
            "url": url.strip(),
            "analysis": analysis,
            "ai_summary": ai_summary
        })
    return {"results": results}

@app.post("/api/analyze-email")
async def analyze_email(req: AnalyzeEmailRequest):
    if not req.message.strip():
        return {"risk": "Error", "score": 0, "tactics": [], "verdict": "Empty message provided."}
    analysis = engine.analyze_message(req.message.strip())
    # Log AI execution in history as well
    log_scan("AI Message Analysis", analysis.get("score", 0), analysis.get("risk", "Unknown"))
    return analysis

@app.post("/api/analyze-file")
async def analyze_file_endpoint(file: UploadFile = File(...)):
    try:
        contents = await file.read()
    except Exception as e:
        return {"risk": "Error", "score": 0, "flags": [str(e)], "details": {}}
        
    analysis = engine.analyze_file(file.filename, contents)
    score = analysis.get("score", 0)
    verdict = "Safe" if score < 35 else "Suspicious" if score < 65 else "Malicious"
    log_scan(f"File: {file.filename}", score, verdict)
    
    if score >= 35:
        import asyncio
        asyncio.create_task(threat_stream.inject_local_scan(f"FILE: {file.filename}", verdict, score))
    
    ai_summary = engine.generate_file_summary(
        file.filename, 
        analysis.get("risk", "Unknown"), 
        score, 
        analysis.get("flags", []), 
        analysis.get("details", {})
    )
    
    return {"analysis": analysis, "ai_summary": ai_summary}

@app.get("/api/history")
async def get_history(limit: int = 50):
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    c.execute("SELECT url, score, verdict, timestamp FROM history ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    
    history_list = [{"url": r[0], "score": r[1], "verdict": r[2], "timestamp": r[3]} for r in rows]
    return {"history": history_list}

@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("public/index.html", "r") as f:
        return f.read()

@app.get("/map", response_class=HTMLResponse)
async def read_map_page():
    with open("public/map.html", "r") as f:
        return f.read()

@app.get("/history", response_class=HTMLResponse)
async def read_history_page():
    with open("public/history.html", "r") as f:
        return f.read()

@app.get("/api/live-threats")
async def get_live_threats_api():
    return {"threats": threat_stream.get_live_threats()}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
