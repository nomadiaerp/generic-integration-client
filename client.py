import time
import requests
from typing import Optional, Dict, Any
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from pybreaker import CircuitBreaker
import structlog
from prometheus_client import Counter, Histogram
from .auth import get_auth_handler, AuthHandler
from .exceptions import AuthenticationError, IntegrationError

# Métricas Prometheus
REQUESTS_TOTAL = Counter('integration_requests_total', 'Total requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('integration_request_duration_seconds', 'Request duration', ['method', 'endpoint'])
logger = structlog.get_logger()

class GenericIntegrationClient:
    def __init__(
        self,
        base_url: str,
        auth_method: str = "none",
        auth_config: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
        extra_headers: Optional[Dict[str, str]] = None,  # ← NOVO
        enable_retry: bool = True,
        max_retries: int = 3,
        enable_circuit_breaker: bool = False,
        circuit_breaker_fail_max: int = 5,
        circuit_breaker_reset_timeout: int = 60,
        enable_logging: bool = True,
        enable_metrics: bool = True,
        service_name: str = "integration-client"
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.enable_logging = enable_logging
        self.enable_metrics = enable_metrics
        self.service_name = service_name

        self.session = requests.Session()
        # Headers base + extras
        base_headers = {"User-Agent": f"{service_name}/1.0"}
        if extra_headers:
            base_headers.update(extra_headers)
        self.session.headers.update(base_headers)

        auth_config = auth_config or {}
        self.auth_handler: AuthHandler = get_auth_handler(
            auth_method, auth_config, self.session, self.base_url
        )
        self.auth_handler.authenticate(self.session)  # pode adicionar/sobrescrever headers

        self.enable_retry = enable_retry
        self.max_retries = max_retries
        if enable_circuit_breaker:
            self.circuit_breaker = CircuitBreaker(
                fail_max=circuit_breaker_fail_max,
                reset_timeout=circuit_breaker_reset_timeout * 1000
            )
        else:
            self.circuit_breaker = None

    def _do_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        start = time.time()

        if hasattr(self.auth_handler, 'inject_params'):
            kwargs['params'] = self.auth_handler.inject_params(kwargs.get('params'))

        try:
            response = self.session.request(method, url, timeout=self.timeout, **kwargs)
        except Exception as e:
            if self.enable_logging:
                logger.error("request_failed", method=method, url=url, error=str(e), service=self.service_name)
            raise

        duration = time.time() - start
        status = str(response.status_code)

        if self.enable_metrics:
            REQUESTS_TOTAL.labels(method=method, endpoint=endpoint, status=status).inc()
            REQUEST_DURATION.labels(method=method, endpoint=endpoint).observe(duration)

        if self.enable_logging:
            logger.info("request_completed",
                        method=method,
                        url=url,
                        status=status,
                        duration_s=round(duration, 3),
                        service=self.service_name)

        return response

    def _execute_with_retry_and_cb(self, method: str, endpoint: str, **kwargs):
        def target():
            return self._do_request(method, endpoint, **kwargs)

        if self.circuit_breaker:
            def wrapped():
                return self.circuit_breaker.call(self._do_request, method, endpoint, **kwargs)
            target = wrapped

        if self.enable_retry:
            @retry(
                stop=stop_after_attempt(self.max_retries),
                wait=wait_exponential(multiplier=1, min=1, max=10),
                retry=retry_if_exception_type((requests.RequestException,)),
                reraise=True
            )
            def call():
                return target()
            return call()
        else:
            return target()

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        try:
            response = self._execute_with_retry_and_cb(method, endpoint, **kwargs)
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                try:
                    new_resp = self.auth_handler.handle_401(self, method, endpoint, **kwargs)
                    new_resp.raise_for_status()
                    return new_resp.json() if new_resp.content else {}
                except Exception:
                    pass
            raise IntegrationError(f"Erro na requisição: {e}") from e

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        return self._request("GET", endpoint, params=params)

    def post(self, endpoint: str,  data: Optional[Dict] = None) -> Dict[str, Any]:
        return self._request("POST", endpoint, json=data)

    def put(self, endpoint: str,  data: Optional[Dict] = None) -> Dict[str, Any]:
        return self._request("PUT", endpoint, json=data)

    def delete(self, endpoint: str) -> Dict[str, Any]:
        return self._request("DELETE", endpoint)

    def patch(self, endpoint: str,  data: Optional[Dict] = None) -> Dict[str, Any]:
        return self._request("PATCH", endpoint, json=data)