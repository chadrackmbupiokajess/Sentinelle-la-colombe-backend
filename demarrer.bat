@echo off
REM Lance le backend Sentinelle, accessible depuis tout le reseau (tablettes, telephones).
cd /d "%~dp0"
if exist .venv\Scripts\activate.bat call .venv\Scripts\activate.bat
python main.py
pause
