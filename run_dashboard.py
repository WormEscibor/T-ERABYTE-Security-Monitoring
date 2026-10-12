"""One-click launcher for T-ERABYTE CSIRT SOC PRO.

Creates the virtualenv/install set once, starts Streamlit on all LAN interfaces and opens the
local browser automatically. The application itself starts the location receiver when needed.
"""
from __future__ import annotations
import os, socket, subprocess, sys, time, webbrowser
from pathlib import Path

ROOT=Path(__file__).resolve().parent
VENV=ROOT/'.venv'
PYTHON=VENV/'bin'/'python' if os.name!='nt' else VENV/'Scripts'/'python.exe'


def free_port(preferred:int=1500)->int:
    for port in range(preferred, preferred+20):
        with socket.socket() as s:
            try:
                s.bind(('0.0.0.0',port)); return port
            except OSError: continue
    raise RuntimeError('Tidak ada port LAN yang tersedia dalam rentang default.')


def main():
    os.chdir(ROOT)
    if not PYTHON.exists():
        subprocess.check_call([sys.executable,'-m','venv',str(VENV)])
    stamp=VENV/'.fusion_requirements.ok'
    if not stamp.exists():
        subprocess.check_call([str(PYTHON),'-m','pip','install','-r','requirements.txt'])
        stamp.write_text('installed\n',encoding='utf-8')
    port=int(os.getenv('PORT') or free_port(1500))
    env=os.environ.copy(); env['PORT']=str(port)
    cmd=[str(PYTHON),'-m','streamlit','run','app.py','--server.address=0.0.0.0',f'--server.port={port}']
    proc=subprocess.Popen(cmd,env=env)
    url=f'http://127.0.0.1:{port}'
    for _ in range(80):
        time.sleep(0.25)
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=0.5): break
        except OSError: pass
    webbrowser.open(url,new=2)
    print(f'T-ERABYTE CSIRT SOC PRO aktif: {url}')
    print(f'LAN: http://<IP perangkat>:{port}')
    try: proc.wait()
    except KeyboardInterrupt:
        proc.terminate()

if __name__=='__main__': main()
