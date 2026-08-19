import uvicorn
import os
from dotenv import load_dotenv

load_dotenv()

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.getenv("APP_HOST", "0.0.0.0"),
        port=int(os.getenv("APP_PORT", "8000")),
        reload=os.getenv("APP_ENV", "production") == "development",
        # Uvicorn's own proxy-header handling rewrites scope["client"] from
        # X-Forwarded-For whenever the peer is in its `forwarded_allow_ips`
        # (which defaults to 127.0.0.1 — i.e. every request through Apache).
        # That would hand app/net.py an already-substituted address and make
        # our TRUSTED_PROXIES setting a rubber stamp on uvicorn's separate,
        # differently-configured trust list. One layer must own this decision:
        # it is app/net.py:client_ip, so request.client stays the real socket
        # peer. Do not turn this on.
        proxy_headers=False,
    )
