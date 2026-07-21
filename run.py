import os
import webbrowser
from threading import Timer

import uvicorn


def open_browser() -> None:
    webbrowser.open("http://127.0.0.1:8787")


if __name__ == "__main__":
    Timer(1.2, open_browser).start()
    uvicorn.run(
        "production:app",
        host=os.environ.get("DATASNIPER_HOST", "127.0.0.1"),
        port=int(os.environ.get("DATASNIPER_PORT", "8787")),
        reload=False,
        access_log=os.environ.get("DATASNIPER_ACCESS_LOG", "0") == "1",
        proxy_headers=False,
        server_header=False,
    )
