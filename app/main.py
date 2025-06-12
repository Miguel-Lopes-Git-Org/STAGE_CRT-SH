from fastapi import FastAPI, HTTPException, Depends

# Import the router
import routes.subdomains as subdomains
import routes.certs as certs

app = FastAPI(
    title="crt.sh API",
    description="A comprehensive REST API for Certificate Transparency data from crt.sh",
    version="1.0.0",
)

app.include_router(subdomains.router, prefix="/domains")
app.include_router(certs.router, prefix="/certs")