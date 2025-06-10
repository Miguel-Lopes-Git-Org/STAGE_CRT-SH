from fastapi import FastAPI, HTTPException, Depends

# Import the router
import routes.subdomains as subdomains
import routes.cert as cert

app = FastAPI()

app.include_router(subdomains.router, prefix="/domains", tags=["subdomains"])
app.include_router(cert.router, prefix="/certs", tags=["certificates"])