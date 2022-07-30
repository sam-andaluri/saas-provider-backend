import logging
import os
import requests
from github import Github
import nacl.utils
from base64 import b64encode
from string import Template

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

async def delete_repo(repo):
    ret = False
    if "saas-tenant" in repo:
        r = github_user.get_repo(repo)
        r.delete()
        ret = True
    return ret

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

def gh_tenant_flow(tenant):
    logging.debug("create_tenant overrides " + str(tenant))

    # Each tenant gets their own repo
    repo_name = "saas-tenant-" + tenant.namespace

    # Create tenant repo
    logging.debug("creating_tenant_repo " + repo_name)
    tenant_repo_obj = github_user.create_repo(repo_name)

    # Add github secrets to repo
    logging.debug("create_tenant add_secrets " + repo_name)
    # gh_add_secret(env_github_user, repo_name, env_github_token, "AWS_ACCESS_KEY_ID", env_aws_access_key_id)
    # gh_add_secret(env_github_user, repo_name, env_github_token, "AWS_SECRET_ACCESS_KEY", env_aws_secret_access_key)

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
    # tenant_repo_obj.create_file(".github/workflows/deploy.yaml", "adding github action",
    #                             gh_action_file.decoded_content.decode('ascii'))
