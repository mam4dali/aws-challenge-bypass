import uvicorn
from app.config import HOST, PORT, SSL_CERTFILE, SSL_KEYFILE

if __name__ == "__main__":
    kwargs = {"host": HOST, "port": PORT}
    if SSL_CERTFILE and SSL_KEYFILE:
        kwargs["ssl_certfile"] = SSL_CERTFILE
        kwargs["ssl_keyfile"] = SSL_KEYFILE
    uvicorn.run("app.main:app", **kwargs)
