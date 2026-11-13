@echo off
title Heimdall Run Script
echo ===================================================
echo Starting Heimdall Services: Backend, Middleware, Frontend
echo ===================================================

if not exist multi-llm-backend\.env (
  echo Missing multi-llm-backend\.env. Copy multi-llm-backend\.env.example and fill it in.
  pause
  exit /b 1
)
if not exist heimdall-middleware\.env (
  echo Missing heimdall-middleware\.env. Copy heimdall-middleware\.env.example and fill it in.
  pause
  exit /b 1
)

:: Start Backend
echo [1/3] Starting Multi-LLM Backend (Port 8001)...
start "Heimdall Backend" cmd /k "cd multi-llm-backend && (if not exist venv python -m venv venv) && call venv\Scripts\activate.bat && pip install -r requirements.txt && uvicorn main:app --port 8001 --host 0.0.0.0"

:: Start Middleware
echo [2/3] Starting Heimdall Middleware (Port 8000)...
start "Heimdall Middleware" cmd /k "cd heimdall-middleware && (if not exist venv python -m venv venv) && call venv\Scripts\activate.bat && pip install -r requirements.txt && uvicorn heimdall_app:app --port 8000 --host 0.0.0.0"

:: Start Frontend
echo [3/3] Starting Heimdall Frontend (Port 5173)...
start "Heimdall Frontend" cmd /k "cd heimdall-frontend && (if not exist node_modules call npm ci) && npm run dev"

echo.
echo All services have been launched in separate windows!
echo - Backend: http://localhost:8001
echo - Middleware: http://localhost:8000
echo - Frontend: http://localhost:5173
echo.
