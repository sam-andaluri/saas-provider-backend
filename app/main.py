from fastapi import FastAPI
from kubernetes import client, config

app = FastAPI()

# Configs can be set in Configuration class directly or using helper utility
config.load_kube_config()

@app.get("/pods")
def get_pods():
    v1 = client.CoreV1Api()
    ret = v1.list_pod_for_all_namespaces(watch=False)
    return ret







