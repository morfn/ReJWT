import jwt
import hashlib
import random
from datetime import datetime, timedelta
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

CONFIG_DEFAULTS = {
    'JWT_ALGORITHM': 'HS256',
    'JWT_LEEWAY': timedelta(seconds=10),
    'JWT_VERIFY_CLAIMS': ['signature', 'exp', 'nbf', 'iat'],
    'JWT_REQUIRED_CLAIMS': ['exp', 'iat', 'nbf','id'],
    'JWT_EXPIRATION_DELTA': timedelta(seconds=300),
    'JWT_NOT_BEFORE_DELTA': timedelta(seconds=0),
    'JWT_CLAIM_AUD':'',
    'JWT_CLAIM_SUB':'',
    'JWT_CLAIM_ISS':'',
    'JWT_CLAIM_JTI':'',
    'JWT_PAYLOAD':['id'],
    'REFRESH_TOKEN_OWNER_KEY':'id',
    'REFRESH_TOKEN_LIFE':timedelta(days=7)
}

class ReJWT(object):
	"""docstring for ReJWT"""
	
    def __init__(self, auth_handler=None,identity_handler=None,storage_handler=None,revoke_handler=None):
		super(ReJWT, self).__init__()

		self.auth_handler = auth_handler
		self.identity_handler = identity_handler
        self.storage_handler = storage_handler
        self.revoke_handler = revoke_handler
        self.config = CONFIG_DEFAULTS

    def authenticate(self,username,password):
        payload = self.auth_handler(username,password)
        
        if not payload:
            raise ReJWTAuthError(error="Error authenticating", description="The username or password is incorrect")

        return {
            "refresh_token":self.generate_refresh_token(payload),
            "access_token":self.generate_access_token(payload)
        }

    def refresh_access(self,refresh_token):
        payload = self.verify_refresh_token(refresh_token)
        if not payload:
            raise ReJWTAuthError(
                error="refresh token invalid",
                description="The refresh token is invalid or has expired"
                )

        new_payload = self.identity_handler()

    def generate_refresh_token(self, payload):
        token_life = self.JWT_life(
            expiration = self.config.get("REFRESH_TOKEN_LIFE"),
            not_before = self.config.get("JWT_NOT_BEFORE_DELTA")
            )
        
        token_owner = payload[self.config.get("REFRESH_TOKEN_OWNER_KEY")]
        
        if self.storage_handler(token_owner,token_hash,expiration):
            raise ReJWTError(error="Unable to store token",description="The token could not be saved")
        
        return token_hash

    def verify_refresh_token(self,refresh_token):
        s = Serializer(self.get("SECRET_KEY"))
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token

        return payload

    def JWT_life(self,expiration,not_before):
        return {
            "iat": datetime.utcnow(),
            "exp": iat + expiration,
            "nbf": iat + not_before
        }

    def process_JWT_payload(self,payload):
        required_claims = self.config.get("REQUIRED_CLAIMS")

        jwt_payload = {
            claim:payload.get(claim,None)
            for claim in self.config.get("JWT_PAYLOAD")
        }
        
        jwt_payload.update(jwt_claims)

        missing_claims = list(set(required_claims) - set([c for c in jwt_payload if jwt_payload[c]]))
        if missing_claims:
            raise RuntimeError('Payload is missing required claims: %s' % ', '.join(missing_claims))

        return jwt_payload

    def generate_access_token(self,payload):
        secret = self.config.get("SECRET_KEY")        
        algorithm = self.config.get("JWT_ALGORITHM")
        jwt_payload = self.process_JWT_payload(payload)
        return jwt.encode(payload, secret, algorithm=algorithm)

    def decode_JWT(self,token):
        secret = self.config.get("SECRET_KEY")        
        algorithm = self.config.get("JWT_ALGORITHM")
        leeway = self.config.get("JWT_LEEWAY")
        
        verify_claims = self.config['JWT_VERIFY_CLAIMS']
        required_claims = self.config['JWT_REQUIRED_CLAIMS']

        options = { 'verify_' + claim: True for claim in verify_claims }
        options.update({ 'require_' + claim: True for claim in required_claims })

        return jwt.decode(token, secret, options=options, algorithms=[algorithm], leeway=leeway)


class ReJWTError(Exception):
    def __init__(self, error, description):
        self.error = error
        self.description = description

    def __repr__(self):
        return 'JWTError: %s' % self.error

    def __str__(self):
        return '%s. %s' % (self.error, self.description)

class ReJWTAuthError(ReJWTError):
    def __init__(self, arg):
        super(ReJWTAuthError, self).__init__()
        