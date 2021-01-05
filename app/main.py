import json
import os
from base64 import b64encode
from datetime import datetime
from pprint import pprint
from string import Template
from typing import Optional

import pydng
import requests
from fastapi import FastAPI
from nacl import encoding, public
from pydantic import BaseModel
from tinydb import TinyDB, where
from github import Github

# Tenant object received from provider UI
class Tenant(BaseModel):
    name: str
    email: str
    tier: str
    namespace: Optional[str] = None
    cloud_provider: Optional[str] = None
    tenant_url: Optional[str] = None
    created_time: Optional[datetime] = None

# API
app = FastAPI()

# Local db
db = TinyDB('/data/tenant-db.json')
tenants = db.table('tenants')

# Load from secrets
github_token = os.environ.get("GITHUB_TOKEN","1ff971d0dc076f4d74c2ad6692eee0e756ca1002")
github_user = os.environ.get("GITHUB_USER","sam-andaluri")
github_templated_repo = os.environ.get("GITHUB_TEMPLATED_REPO","saas-tenant-k8s-template")
aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID", "AKIAWHAXMPNBZQU57THI")
aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "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")

# Create GitHub objects
github = Github(github_token)
github_user = github.get_user()

# Encrypt secrets
def encrypt(public_key: str, secret_value: str) -> str:
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")

# Get Public key from repo. Used for encrypting secrets
def gh_get_publickey(owner, repo, token):
    query_url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key"
    headers = {'Authorization': f'token {token}'}
    r = requests.get(query_url, headers=headers).json()
    return [r["key_id"], r["key"]]

# Add secret to new tenant repo
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
    pprint(r)

@app.get("/test")
async def get_test():
    return json.dumps({"status":"success", "time": str(datetime.now())})

# API for creating a tenant
@app.post("/tenant/")
async def create_tenant(tenant: Tenant):
    print("got a new tenant request " + json.dumps(tenant) + " @ " + datetime.now())
    if tenant.namespace == None:
        tenant.namespace = pydng.generate_name()
    if tenant.created_time == None:
        tenant.created_time = datetime.now()
    if tenant.cloud_provider == None:
        tenant.cloud_provider = "AWS"

    print("final tenant obj " + json.dumps(tenant))
    repo_name = "saas-tenant-" + tenant.namespace

    print("creating new repo " + repo_name + " @ " + datetime.now())
    tenant_repo_obj = github_user.create_repo(repo_name)

    print("adding repo secrets " + repo_name + " @ " + datetime.now())
    gh_add_secret(github_user, repo_name, github_token, "AWS_ACCESS_KEY_ID", aws_access_key_id)
    gh_add_secret(github_user, repo_name, github_token, "AWS_SECRET_ACCESS_KEY", aws_secret_access_key)

    print("creating files from templates" + " @ " + datetime.now())
    templated_repo_obj = github_user.get_repo(github_templated_repo)
    argocd_app_spec_template = Template(templated_repo_obj.get_contents("/tier-customization/application.yaml").decoded_content.decode('ascii'))
    argocd_app_spec = argocd_app_spec_template.substitute(tenantId=tenant.namespace, repo="saas-tenant-" + tenant.namespace)
    kust_template = Template(templated_repo_obj.get_contents("/tier-customization/kustomization.yaml").decoded_content.decode('ascii'))
    kust_spec = kust_template.substitute(tenantId=tenant.namespace, tier=tenant.tier)

    print("copying files to new repo" + " @ " + datetime.now())
    for repo_file in templated_repo_obj.get_contents("/tier"):
        print(repo_file.decoded_content)
        tenant_repo_obj.create_file("kubernetes/" + repo_file.name, "creating tenant", repo_file.decoded_content)
    tenant_repo_obj.create_file("kubernetes/kustomization.yaml", "creating tenant tier", kust_spec.encode('ascii'))
    gh_action_file = templated_repo_obj.get_contents("/tier-customization/deploy-argocd-app.yaml")
    tenant_repo_obj.create_file(".github/workflows/deploy.yaml", "adding deployment", gh_action_file)
    tenant_repo_obj.create_file("application.yaml", "creating tenant app", argocd_app_spec.encode('ascii'))

    print("saving tenant to db" + " @ " + datetime.now())
    results = tenants.search(where("email")==tenant.email)
    if results.len == 0:
        tenants.insert(tenant)
    else:
        tenant = results[0]
    #TODO add background task to get tenant URL
    #https://fastapi.tiangolo.com/tutorial/background-tasks/
    return tenant
