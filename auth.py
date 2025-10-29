from typing import Dict, Any, Optional
import requests
from .exceptions import AuthenticationError

# --- Handlers de Autenticação ---

class AuthHandler:
    def authenticate(self, session: requests.Session):
        raise NotImplementedError

    def handle_401(self, client, method: str, endpoint: str, **kwargs):
        raise AuthenticationError("Token inválido e não há mecanismo de refresh.")


class NoAuthHandler(AuthHandler):
    def authenticate(self, session: requests.Session):
        pass


class StaticBearerHandler(AuthHandler):
    def __init__(self, token: str):
        self.token = token

    def authenticate(self, session: requests.Session):
        session.headers["Authorization"] = f"Bearer {self.token}"


class BearerUserPassHandler(AuthHandler):
    def __init__(self, session, base_url, username, password, login_endpoint, token_field):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.login_endpoint = login_endpoint
        self.token_field = token_field
        self._token = None

    def _login(self):
        url = f"{self.base_url}/{self.login_endpoint.lstrip('/')}"
        resp = self.session.post(url, json={"username": self.username, "password": self.password})
        resp.raise_for_status()
        data = resp.json()
        if self.token_field not in data:
            raise AuthenticationError(f"Campo '{self.token_field}' não encontrado.")
        self._token = data[self.token_field]

    def authenticate(self, session: requests.Session):
        if not self._token:
            self._login()
        session.headers["Authorization"] = f"Bearer {self._token}"

    def handle_401(self, client, method: str, endpoint: str, **kwargs):
        self._token = None
        self.authenticate(client.session)
        return client._do_request(method, endpoint, **kwargs)


class APIKeyHeaderHandler(AuthHandler):
    def __init__(self, header_name: str, api_key: str):
        self.header_name = header_name
        self.api_key = api_key

    def authenticate(self, session: requests.Session):
        session.headers[self.header_name] = self.api_key


class APIKeyQueryHandler(AuthHandler):
    def __init__(self, param_name: str, api_key: str):
        self.param_name = param_name
        self.api_key = api_key

    def authenticate(self, session: requests.Session):
        pass

    def inject_params(self, params: Optional[Dict]) -> Dict:
        params = params or {}
        params[self.param_name] = self.api_key
        return params


class StaticHeadersHandler(AuthHandler):
    """Adiciona headers estáticos arbitrários (ex: email + senha)."""
    def __init__(self, headers: Dict[str, str]):
        self.headers = headers

    def authenticate(self, session: requests.Session):
        session.headers.update(self.headers)


# --- Fábrica de Handlers ---

def get_auth_handler(auth_method: str, config: Dict[str, Any], session: requests.Session, base_url: str):
    if auth_method == "none":
        return NoAuthHandler()
    elif auth_method == "static_bearer":
        return StaticBearerHandler(config["token"])
    elif auth_method == "bearer_user_pass":
        return BearerUserPassHandler(
            session=session,
            base_url=base_url,
            username=config["username"],
            password=config["password"],
            login_endpoint=config.get("login_endpoint", "/auth/login"),
            token_field=config.get("token_field", "access_token")
        )
    elif auth_method == "api_key_header":
        return APIKeyHeaderHandler(
            header_name=config["header_name"],
            api_key=config["api_key"]
        )
    elif auth_method == "api_key_query":
        return APIKeyQueryHandler(
            param_name=config["param_name"],
            api_key=config["api_key"]
        )
    elif auth_method == "static_headers":
        return StaticHeadersHandler(headers=config["headers"])
    else:
        raise ValueError(f"Método de autenticação não suportado: {auth_method}")