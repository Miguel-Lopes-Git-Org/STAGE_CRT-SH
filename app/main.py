from fastapi import FastAPI, Depends
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

# Import the router
import routes.subdomains as subdomains
import routes.certs as certs
import auth

app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    title="crt.sh API",
    description="A comprehensive REST API for Certificate Transparency data from crt.sh",
    version="1.0.0",
)


@app.get("/health", include_in_schema=False)
async def health_check():
    return {"status": "ok"}


@app.get("/openapi.json", include_in_schema=False)
async def protected_openapi(api_key: str = Depends(auth.validate_docs_api_key)):
    return get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )


@app.get("/docs", include_in_schema=False)
async def protected_swagger(api_key: str = Depends(auth.validate_docs_api_key)):
    return get_swagger_ui_html(
        openapi_url=f"/openapi.json?api_key={api_key}",
        title=f"{app.title} - Swagger UI",
    )

app.include_router(
    subdomains.router,
    prefix="/domains",
    dependencies=[Depends(auth.validate_api_key)],
)
app.include_router(
    certs.router,
    prefix="/certs",
    dependencies=[Depends(auth.validate_api_key)],
)
