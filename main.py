"""
Infrastructure Explorer — Local Server & Application Entrypoint
Serves the local-first web UI for interactive infrastructure graph exploration.
"""

import http.server
import socketserver
import os
import sys
import webbrowser
import argparse

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        directory = os.path.join(os.path.dirname(__file__), 'web')
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format, *args):
        # Keep terminal clean
        sys.stdout.write(f"[SysDiag Explorer] {self.address_string()} - {format%args}\n")

def run_server(port=8080, open_browser=True):
    web_dir = os.path.join(os.path.dirname(__file__), 'web')
    if not os.path.isdir(web_dir):
        print(f"[Error] Web directory not found at: {web_dir}")
        sys.exit(1)

    url = f"http://localhost:{port}/index.html"
    print("=" * 70)
    print("   INFRASTRUCTURE EXPLORER — CANONICAL SYSDIAG VIEWER (PHASE 0/1)")
    print("=" * 70)
    print(f"[*] Local UI Server Running at: {url}")
    print(f"[*] Serving files from: {web_dir}")
    print("[*] Mode: Observational Read-Only")
    print("[*] Press Ctrl+C to terminate.")
    print("=" * 70)

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("", port), CustomHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[SysDiag Explorer] Server stopped.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Infrastructure Explorer Local Server")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind server (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    args = parser.parse_args()

    run_server(port=args.port, open_browser=not args.no_browser)
