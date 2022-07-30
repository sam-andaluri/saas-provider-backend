import datetime
import logging
from sys import stdout
from typing import Optional

import pydng
import uvicorn
from fastapi import FastAPI, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from tinydb import TinyDB, where

from pydantic import BaseModel
from typing import Optional

# Tenant object received from provider UI
class Tenant(BaseModel):
    name: str
    email: str
    tier: str
    namespace: Optional[str] = None
    cloud_provider: Optional[str] = None
    tenant_url: Optional[str] = None
    created_time: Optional[datetime.datetime] = None

# Logging
logging.basicConfig(stream=stdout,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                    level=logging.DEBUG)

# Initialize FastAPI
app = FastAPI()

# Define origins for API
origins = [
    "https://saas-provider.us.auth0.com",
    "https://saas-provider.cloud",
    "http://localhost:3000"
]

# Enabled CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize TinyDB
db = TinyDB('tenant-db.json')

# Create tenants table
tenants = db.table('tenants')

# Test url for testing front-end integration
@app.get("/ping")
async def get_pong():
    return JSONResponse(status_code=status.HTTP_200_OK, content={"status" : "OK"})

# API for creating a tenant
@app.post("/tenant")
async def create_tenant(tenant: Tenant, request: Request):
    logging.debug(tenant)
    logging.debug(request.headers)
    results = tenants.search(where("email") == tenant.email)
    if len(results) > 0:
        tenant = results[0]
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=tenant)
    logging.debug("create_tenant enter " + str(tenant))
    if tenant.namespace == None:
        tenant.namespace = pydng.generate_name().replace("_", "-")
    if tenant.created_time == None:
        tenant.created_time = str(datetime.datetime.now())
    if tenant.cloud_provider == None:
        tenant.cloud_provider = "AWS"

    # Save tenant info
    logging.debug("create_tenant save_tenant")
    tenant.tenant_url = tenant.namespace + ".saas-tenant.cloud"
    logging.debug("create_tenant dump_tenant_obj " + str(tenant))
    tenants.insert(tenant.dict())
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=tenant.json())

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)