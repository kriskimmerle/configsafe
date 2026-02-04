# FastAPI configuration - INSECURE example

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(debug=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_SECRET = 'sk-proj-abcdefghijklmnopqrstuvwxyz_1234567890abcdef'
DATABASE_TOKEN = 'changeme'
