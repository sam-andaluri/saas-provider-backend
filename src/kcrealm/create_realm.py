from keycloak import KeycloakAdmin
import os

SERVER_URL = "http://iam.saas-provider.cloud:8080/"
CLIENT_SECRET_KEY = os.environ.get("KEYCLOAK_MASTER_CLIENT_SECRET")

def create_realm(realm_name="demo"):
    keycloak_admin = KeycloakAdmin(server_url=SERVER_URL, 
                                   client_id="python-sdk", 
                                   realm_name="master",
                                   client_secret_key=CLIENT_SECRET_KEY,
                                   verify=True, 
                                   timeout=300)
    keycloak_admin.delete_realm(realm_name="demo")
    keycloak_admin.create_realm(
        payload={
            "realm": "demo", 
            "enabled": "true", 
            "userManagedAccessAllowed": "true"
            }, skip_exists=False)
    #print(keycloak_admin.get_realm_roles())
    keycloak_admin.realm_name = "demo"
    keycloak_admin.create_client(
        payload={
            "name": "demo-client",
            "clientId": "demo-client",
            "authorizationServicesEnabled": True,
            "serviceAccountsEnabled": True,
            "clientAuthenticatorType": "client-secret",
            "directAccessGrantsEnabled": False,
            "enabled": True,
            "implicitFlowEnabled": False,
            "publicClient": False,
        }
    )
    secret = keycloak_admin.generate_client_secrets(client_id=keycloak_admin.get_client_id("demo-client"))
    #print(keycloak_admin.get_role_mappings(client_id=keycloak_admin.get_client_id("demo-client")))

    print(secret)

    keycloak_admin.create_user({"username": 'demo',
                            "credentials": [{"value": "demo", "type": "password", }],
                            "enabled": True,
                            "firstName": 'Demo',
                            "lastName": 'Admin'})
    user_id = keycloak_admin.get_user_id("demo")
    client_id = keycloak_admin.get_client_id("realm-management")
    client_roles = keycloak_admin.get_client_roles(client_id=client_id)
    for role in client_roles:
        print(role['name'])
        role = keycloak_admin.get_client_role(client_id=client_id, role_name=role['name'])
        keycloak_admin.assign_client_role(client_id=client_id, user_id=user_id, roles=[role])
