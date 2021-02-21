import json
import logging
import os
import pydng
import requests
import nacl.utils
import datetime

from sys import stdout
from base64 import b64encode
from string import Template
from github import Github
from pydantic import BaseModel
from tinydb import TinyDB, where
from typing import Optional
from fastapi import FastAPI

logging.basicConfig(stream=stdout, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# Tenant object received from provider UI
class Tenant(BaseModel):
    name: str
    email: str
    tier: str
    namespace: Optional[str] = None
    cloud_provider: Optional[str] = None
    tenant_url: Optional[str] = None
    created_time: Optional[datetime.datetime] = None

# API
app = FastAPI()

# Local db
# Uncomment for testing
#db = TinyDB('./tenant-db.json')
db = TinyDB('/data/tenant-db.json')

tenants = db.table('tenants')

# Load from kubernetes sealed secrets
github_token = os.environ.get("GITHUB_TOKEN")
github_user = os.environ.get("GITHUB_USER")
github_templated_repo = os.environ.get("GITHUB_TEMPLATED_REPO")
aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

# Create GitHub objects
github = Github(github_token)
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
    logging.debug(r)

# Test url for testing front-end integration
@app.get("/ping")
async def get_pong():
    return json.dumps({"status":"success", "time": str(datetime.datetime.now())})

# API for creating a tenant
@app.post("/tenant")
async def create_tenant(tenant: Tenant):
    logging.debug("create_tenant enter " + json.dumps(tenant))
    if tenant.namespace == None:
        tenant.namespace = pydng.generate_name()
    if tenant.created_time == None:
        tenant.created_time = datetime.datetime.now()
    if tenant.cloud_provider == None:
        tenant.cloud_provider = "AWS"

    logging.debug("create_tenant overrides " + json.dumps(tenant))

    # Each tenant gets their own repo
    repo_name = "saas-tenant-" + tenant.namespace

    # Create tenant repo
    logging.debug("creating_tenant_repo " + repo_name)
    tenant_repo_obj = github_user.create_repo(repo_name)

    # Add github secrets to repo
    logging.debug("create_tenant add_secrets " + repo_name)
    gh_add_secret(github_user, repo_name, github_token, "AWS_ACCESS_KEY_ID", aws_access_key_id)
    gh_add_secret(github_user, repo_name, github_token, "AWS_SECRET_ACCESS_KEY", aws_secret_access_key)

    # Access the tenant template repo
    logging.debug("create_tenant copy_template")
    templated_repo_obj = github_user.get_repo(github_templated_repo)

    # Create contents of tenant repo from template repo contents
    logging.debug("create_tenant prepare_argo_app")
    argocd_app_spec_template = Template(templated_repo_obj.get_contents("/tier-customization/application.yaml").decoded_content.decode('ascii'))
    argocd_app_spec = argocd_app_spec_template.substitute(tenantId=tenant.namespace, repo="saas-tenant-" + tenant.namespace)
    kust_template = Template(templated_repo_obj.get_contents("/tier-customization/kustomization.yaml").decoded_content.decode('ascii'))
    kust_spec = kust_template.substitute(tenantId=tenant.namespace, tier=tenant.tier)

    logging.debug("create_tenant prepare_tenant")
    for repo_file in templated_repo_obj.get_contents("/tier"):
        logging.debug("create_tenant file_contents" + repo_file.decoded_content)
        tenant_repo_obj.create_file("kubernetes/" + repo_file.name, "creating tenant", repo_file.decoded_content)
    tenant_repo_obj.create_file("kubernetes/kustomization.yaml", "creating tenant tier", kust_spec.encode('ascii'))
    gh_action_file = templated_repo_obj.get_contents("/tier-customization/deploy-argocd-app.yaml")
    tenant_repo_obj.create_file(".github/workflows/deploy.yaml", "adding deployment", gh_action_file)
    tenant_repo_obj.create_file("application.yaml", "creating tenant app", argocd_app_spec.encode('ascii'))

    # Save tenant info
    logging.debug("create_tenant save_tenant")
    results = tenants.search(where("email")==tenant.email)
    tenant.tenant_url = tenant.namespace + ".saas-tenant.cloud"
    logging.debug("create_tenant dump_tenant_obj" + json.dumps(tenant))
    if results.len == 0:
        tenants.insert(tenant)
    else:
        tenant = results[0]
    return tenant
