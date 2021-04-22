import datetime
import json
import logging
import os
from base64 import b64encode
from string import Template
from sys import stdout
from typing import Optional
from six.moves.urllib.request import urlopen
from jose import jwt

import nacl.utils
import pydng
import requests
import uvicorn
from fastapi import FastAPI, status, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from github import Github
from nacl.public import PublicKey
from pydantic import BaseModel
from tinydb import TinyDB, where

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

# Auth0 API security
AUTH0_DOMAIN = 'saas-provider.us.auth0.com'
API_AUDIENCE = "https://tenant-api.saas-provider.cloud/"
ALGORITHMS = ["RS256"]

# Get Auth0 token
def get_token_auth_header(request):
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise HTTPException(status_code=401, detail="Authorization header is expected")
    parts = auth.split()
    if parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization header must start with Bearer")
    elif len(parts) == 1:
        raise HTTPException(status_code=401, detail="invalid_header. Token not found")
    elif len(parts) > 2:
        raise HTTPException(status_code=401, detail="Authorization header must be bearer token")
    token = parts[1]
    return token

# Validate Auth0 token and scopes
def validate_token_and_scopes(request, required_scope):
    isValid = False
    token = get_token_auth_header(request)
    jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
            token_scopes = unverified_claims["scope"].split()
            logging.debug("Token scopes " + str(token_scopes))
            for token_scope in token_scopes:
                if token_scope == required_scope:
                    isValid = True
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer="https://"+AUTH0_DOMAIN+"/"
            )
            logging.debug("Decoded Payload " + str(payload))
            if payload != None:
                isValid = True
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="token expired")
        except jwt.JWTClaimsError:
            raise HTTPException(status_code=401, detail="please check the audience and issuer")
        except Exception:
            raise HTTPException(status_code=401, detail="Unable to parse authentication")
    else:
        raise HTTPException(status_code=401, detail="Unable to find appropriate key")
    return isValid

# Tenant object received from provider UI
class Tenant(BaseModel):
    name: str
    email: str
    tier: str
    namespace: Optional[str] = None
    cloud_provider: Optional[str] = None
    tenant_url: Optional[str] = None
    created_time: Optional[datetime.datetime] = None

# Initialize TinyDB
db = TinyDB('tenant-db.json')

# Create tenants table
tenants = db.table('tenants')

# Load from kubernetes sealed secrets
env_github_token = os.environ.get("GITHUB_TOKEN")
env_github_user = os.environ.get("GITHUB_USER")
env_github_templated_repo = os.environ.get("GITHUB_TEMPLATED_REPO")
env_aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
env_aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

#TODO Move this to kustomize
tier_limits = {
    "free" : {
        "cpu": "250m",
        "mem": "256Mi"
    },
    "pro" : {
        "cpu": "500m",
        "mem": "512Mi"
    },
    "enterprise" : {
        "cpu": "1000m",
        "mem": "1024Mi"
    }
}

tier_reqs = {
    "free" : {
        "cpu": "125m",
        "mem": "128Mi"
    },
    "pro" : {
        "cpu": "250m",
        "mem": "256Mi"
    },
    "enterprise" : {
        "cpu": "500m",
        "mem": "512Mi"
    }
}

# Create GitHub objects
github = Github(env_github_token)
github_user = github.get_user()

# Get Public key from repo. Used for encrypting github secrets
def gh_get_publickey(owner, repo, token):
    query_url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key"
    headers = {'Authorization': f'token {token}'}
    r = requests.get(query_url, headers=headers).json()
    return [r["key_id"], r["key"]]

# Encrypt github secrets
def encrypt(public_key: str, secret_value: str) -> str:
    public_key = nacl.public.PublicKey(public_key.encode("utf-8"), nacl.encoding.Base64Encoder())
    sealed_box = nacl.public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")

# Add github secrets to new tenant repo
def gh_add_secret(owner, repo, token, secret_name, secret_value):
    public_key_tuple = gh_get_publickey(owner, repo, token)
    key_id = public_key_tuple[0]
    key_val = public_key_tuple[1]
    enc_secret_value = encrypt(key_val, secret_value)
    query_url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}"
    headers = {'Authorization': f'token {token}'}
    params = {
        "accept": "application/vnd.github.v3+json",
        "encrypted_value": enc_secret_value,
        "owner": owner,
        "repo": repo,
        "secret_name": secret_name,
        "key_id": key_id
    }
    r = requests.put(query_url, headers=headers, data=json.dumps(params))
    return r.status_code


# Test url for testing front-end integration
@app.get("/ping")
async def get_pong():
    return JSONResponse(status_code=status.HTTP_200_OK, content={"status" : "OK"})

#For testing
@app.post("/delete/{repo}")
async def delete_repo(repo):
    if "saas-tenant" in repo:
        r = github_user.get_repo(repo)
        r.delete()
        return JSONResponse(status_code=status.HTTP_200_OK, content={"status" : "OK"})
    else:
        return JSONResponse(status_code=status.HTTP_404_NOT_FOUND)

# API for creating a tenant
@app.post("/tenant")
async def create_tenant(tenant: Tenant, request: Request):
    logging.debug(tenant)
    logging.debug(request.headers)
    # User must have write:tenant scope to create tenants
    if validate_token_and_scopes(request, "write:tenant") == False:
        raise HTTPException(status_code=401, detail="token and scope validation failed. user is not permitted for this action")
    # Check if tenant exists to prevent accidental creation
    results = tenants.search(where("email") == tenant.email)
    if len(results) > 0:
        tenant = results[0]
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=tenant)
    # Default values not supplied.
    # TODO Add GCP support
    logging.debug("create_tenant enter " + str(tenant))
    if tenant.namespace == None:
        tenant.namespace = pydng.generate_name().replace("_", "-")
    if tenant.created_time == None:
        tenant.created_time = str(datetime.datetime.now())
    if tenant.cloud_provider == None:
        tenant.cloud_provider = "AWS"

    logging.debug("create_tenant overrides " + str(tenant))

    # Each tenant gets their own repo
    repo_name = "saas-tenant-" + tenant.namespace

    # Create tenant repo
    logging.debug("creating_tenant_repo " + repo_name)
    tenant_repo_obj = github_user.create_repo(repo_name)

    # Add github secrets to repo
    logging.debug("create_tenant add_secrets " + repo_name)
    gh_add_secret(env_github_user, repo_name, env_github_token, "AWS_ACCESS_KEY_ID", env_aws_access_key_id)
    gh_add_secret(env_github_user, repo_name, env_github_token, "AWS_SECRET_ACCESS_KEY", env_aws_secret_access_key)

    # Access the tenant template repo
    logging.debug("create_tenant copy_template")
    templated_repo_obj = github_user.get_repo(env_github_templated_repo)

    # Create contents of tenant repo from template repo contents

    #TODO Use kustomize to build base and overlays
    #kust_template = Template(templated_repo_obj.get_contents("/tier-customization/kustomization.yaml").decoded_content.decode('ascii'))
    #kust_spec = kust_template.substitute(tenantId=tenant.namespace, tier=tenant.tier)
    #tenant_repo_obj.create_file("kubernetes/kustomization.yaml", "creating tenant tier", kust_spec.encode('ascii'))
    # for repo_file in templated_repo_obj.get_contents("/tier"):
    #     tenant_repo_obj.create_file("kubernetes/" + repo_file.name, "creating tenant", repo_file.decoded_content)

    logging.debug("create_tenant prepare_tenant")
    # Add deployment
    deployment_template = Template(templated_repo_obj.get_contents("/tier/deployment.yaml").decoded_content.decode('ascii'))
    tier = tenant.tier.lower()
    deployment_spec = deployment_template.substitute(tenantId=tenant.namespace,
                                                     reqCpu=tier_reqs[tier]["cpu"],
                                                     reqMem=tier_reqs[tier]["mem"],
                                                     limCpu=tier_limits[tier]["cpu"],
                                                     limMem=tier_limits[tier]["mem"])
    tenant_repo_obj.create_file("tier/deployment.yaml", "creating tenant deployment", deployment_spec.encode('ascii'))

    # Add service
    service_template = Template(templated_repo_obj.get_contents("/tier/service.yaml").decoded_content.decode('ascii'))
    service_spec = service_template.substitute(tenantId=tenant.namespace)
    tenant_repo_obj.create_file("tier/service.yaml", "creating tenant service", service_spec.encode('ascii'))

    # ArgoCD Application
    logging.debug("create_tenant prepare_argo_app")
    gh_action_file = None
    if tenant.cloud_provider == "AWS":
        argocd_app_spec_template = Template(templated_repo_obj.get_contents("/tier-customization/application.yaml").decoded_content.decode('ascii'))
        argocd_app_spec = argocd_app_spec_template.substitute(tenantId=tenant.namespace, repo="saas-tenant-" + tenant.namespace)
        tenant_repo_obj.create_file("application.yaml", "creating tenant app", argocd_app_spec.encode('ascii'))
        gh_action_file = templated_repo_obj.get_contents("/tier-customization/deploy-argocd-app.yaml")
    else:
        config_sync_spec_template = Template(templated_repo_obj.get_contents("/tier-customization/config_sync.yaml").decoded_content.decode('ascii'))
        config_sync_spec = config_sync_spec_template.substitute(tenantId=tenant.namespace, repo="saas-tenant-" + tenant.namespace)
        tenant_repo_obj.create_file("config_sync.yaml", "creating tenant app", config_sync_spec.encode('ascii'))
        gh_action_file = templated_repo_obj.get_contents("/tier-customization/deploy-config-sync.yaml")
        tenant_repo_obj.create_file(".github/workflows/deploy.yaml", "adding github action",
                                    gh_action_file.decoded_content.decode('ascii'))

    # Copy the github action LAST.
    tenant_repo_obj.create_file(".github/workflows/deploy.yaml", "adding github action",
                                gh_action_file.decoded_content.decode('ascii'))

    # Save tenant info
    logging.debug("create_tenant save_tenant")
    tenant.tenant_url = tenant.namespace + ".saas-tenant.cloud"
    logging.debug("create_tenant dump_tenant_obj " + str(tenant))
    tenants.insert(tenant.dict())
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=tenant.json())

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)