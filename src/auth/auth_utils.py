# Auth0 API security
from http.client import HTTPException
from jose import jwt
from six.moves.urllib.request import urlopen
import json
import logging

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
