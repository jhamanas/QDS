"""Launch the local dashboard: python dashboard.py"""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import argparse,json,webbrowser
from pathlib import Path
from scenario_runner import run_scenario
ROOT=Path(__file__).resolve().parent
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path in ("/","/index.html"): self.send(200,(ROOT/"dashboard.html").read_bytes(),"text/html; charset=utf-8")
  else:self.send(404,b"Not found","text/plain")
 def do_POST(self):
  try:self.send(200,json.dumps(run_scenario(**json.loads(self.rfile.read(int(self.headers.get("Content-Length","0")))))).encode(),"application/json")
  except (ValueError,TypeError,json.JSONDecodeError) as e:self.send(400,json.dumps({"error":str(e)}).encode(),"application/json")
 def send(self,status,body,content_type):self.send_response(status);self.send_header("Content-Type",content_type);self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
if __name__=="__main__":
 p=argparse.ArgumentParser();p.add_argument("--port",type=int,default=8000);p.add_argument("--no-browser",action="store_true");a=p.parse_args();url=f"http://127.0.0.1:{a.port}";print(f"QDS dashboard: {url}  (Ctrl+C to stop)");
 if not a.no_browser:webbrowser.open(url)
 ThreadingHTTPServer(("127.0.0.1",a.port),Handler).serve_forever()
