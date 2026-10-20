"""
MailTrace local command bridge - MCP-style stdio server.

This process is intended to be launched by a local MCP-capable client.
It exposes only safe, allowlisted development actions and returns structured
JSON-RPC responses over stdin/stdout.

It never invokes a shell. Commands run with shell=False and are restricted
to the MailTrace project root.
"""
import json, os, subprocess, sys, time
from pathlib import Path
from datetime import datetime, timezone

ROOT=Path(os.environ.get("MAILTRACE_PROJECT_ROOT",
    r"C:\Users\ritur\New folder\mailtrace\MailTrace-AI")).resolve()
LOG=ROOT/".mailtrace_bridge"/"mcp_audit.jsonl"
LOG.parent.mkdir(parents=True, exist_ok=True)

def audit(x):
    x={"timestamp":datetime.now(timezone.utc).isoformat(),**x}
    with LOG.open("a",encoding="utf-8") as f: f.write(json.dumps(x)+"\n")

def py():
    p=ROOT/"backend"/"venv"/"Scripts"/"python.exe"
    return str(p) if p.exists() else "python"

def run_action(action,args,timeout=120):
    if action=="python_version":
        cmd=[py(),"--version"]
    elif action=="pytest":
        cmd=[py(),"-m","pytest"]+(args or ["backend/tests"])
    elif action=="py_compile":
        if not args: raise ValueError("py_compile requires .py paths")
        cmd=[py(),"-m","py_compile"]+args
    elif action=="git_status":
        cmd=["git","status","--short"]
    else:
        raise ValueError("Action is not allowlisted")

    for a in cmd:
        if any(x in str(a) for x in ["&","|",";","`","$(","\x00"]):
            raise ValueError("Unsafe argument")

    for a in args:
        p=(ROOT/a).resolve()
        if action=="py_compile" and (ROOT not in p.parents or p.suffix.lower()!=".py"):
            raise ValueError("Path outside project or not a .py file")

    t=time.time()
    audit({"event":"start","action":action,"args":args})
    try:
        r=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,
                         timeout=timeout,shell=False)
        out={"ok":r.returncode==0,"action":action,"command":cmd,
             "exit_code":r.returncode,"stdout":r.stdout,"stderr":r.stderr,
             "duration_seconds":round(time.time()-t,3)}
    except subprocess.TimeoutExpired as e:
        out={"ok":False,"action":action,"command":cmd,"exit_code":None,
             "stdout":e.stdout or "","stderr":(e.stderr or "")+"\nTimed out.",
             "duration_seconds":round(time.time()-t,3)}
    audit({"event":"finish",**out})
    return out

def response(req,result=None,error=None):
    obj={"jsonrpc":"2.0","id":req.get("id")}
    if error: obj["error"]={"code":-32000,"message":str(error)}
    else: obj["result"]=result
    return json.dumps(obj,separators=(",",":"))

for line in sys.stdin:
    try:
        req=json.loads(line)
        method=req.get("method")
        if method=="initialize":
            result={"protocolVersion":"2025-06-18",
                    "serverInfo":{"name":"mailtrace-powershell-bridge","version":"2.0.0"},
                    "capabilities":{"tools":{"listChanged":False}}}
        elif method=="tools/list":
            result={"tools":[
                {"name":"mailtrace_run",
                 "description":"Run an allowlisted MailTrace development/test action locally.",
                 "inputSchema":{"type":"object","properties":{
                     "action":{"type":"string","enum":["python_version","pytest","py_compile","git_status"]},
                     "args":{"type":"array","items":{"type":"string"}},
                     "timeout_seconds":{"type":"integer","minimum":1,"maximum":300}},
                     "required":["action"]}}]}
        elif method=="tools/call":
            a=req.get("params",{}).get("arguments",{})
            result=run_action(a.get("action"),a.get("args",[]),a.get("timeout_seconds",120))
        elif method in ("notifications/initialized","ping"):
            result={}
        else:
            raise ValueError("Unsupported method")
        print(response(req,result=result),flush=True)
    except Exception as e:
        print(response(req,error=e),flush=True)
