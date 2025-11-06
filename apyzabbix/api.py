# pylint: disable=wrong-import-order

import logging
from collections.abc import Mapping, Sequence
from typing import Optional, Union
from warnings import warn

from packaging.version import Version
import httpx

__all__ = [
    "AsyncZabbixAPI",
    "AsyncZabbixAPIException",
    "AsyncZabbixAPIMethod",
    "AsyncZabbixAPIObject",
    "AsyncZabbixAPIObjectClass",
]

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

ZABBIX_5_4_0 = Version("5.4.0")
ZABBIX_6_4_0 = Version("6.4.0")


class AsyncZabbixAPIException(Exception):
    """Generic Zabbix API exception

    Codes:
      -32700: invalid JSON. An error occurred on the server while
              parsing the JSON text (typo, wrong quotes, etc.)
      -32600: received JSON is not a valid JSON-RPC Request
      -32601: requested remote-procedure does not exist
      -32602: invalid method parameters
      -32603: Internal JSON-RPC error
      -32400: System error
      -32300: Transport error
      -32500: Application error
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args)

        self.error = kwargs.get("error", None)


# pylint: disable=too-many-instance-attributes
class AsyncZabbixAPI:
    # pylint: disable=too-many-arguments, too-many-positional-arguments
    def __init__(
        self,
        server: str = "http://localhost/zabbix",
        client: Optional[httpx.AsyncClient] = None,
        use_authenticate: bool = False,
        timeout: Optional[Union[float, int, tuple[int, int]]] = None,
        detect_version: bool = True,
    ):
        """
        :param server: Base URI for zabbix web interface (omitting /api_jsonrpc.php)
        :param client: optional pre-configured httpx.AsyncClient instance
        :param use_authenticate: Use old (Zabbix 1.8) style authentication
        :param timeout: optional connect and read timeout in seconds, default: None
                        If you're using httpx you can set it as
                        tuple: "(connect, read)" which is used to set individual
                        connect and read timeouts.
        :param detect_version: autodetect Zabbix API version
        """
        self._client_provided = client is not None
        self.client = client or httpx.AsyncClient()

        # Default headers for all requests
        self.client.headers.update(
            {
                "Content-Type": "application/json-rpc",
                "User-Agent": "python/pyzabbix",
                "Cache-Control": "no-cache",
            }
        )

        self.use_authenticate = use_authenticate
        self.use_api_token = False
        self.auth = ""
        self.id = 0  # pylint: disable=invalid-name

        self.timeout = timeout

        if not server.endswith("/api_jsonrpc.php"):
            server = server.rstrip("/") + "/api_jsonrpc.php"
        self.url = server
        logger.info("JSON-RPC Server Endpoint: %s", self.url)

        self.version: Optional[Version] = None
        self._detect_version = detect_version

    async def __aenter__(self) -> "AsyncZabbixAPI":
        return self

    async def __aexit__(self, exception_type, exception_value, traceback):
        try:
            if isinstance(exception_value, (AsyncZabbixAPIException, type(None))):
                if await self.is_authenticated() and not self.use_api_token:
                    # Logout the user if they are authenticated using username + password.
                    await self.user.logout()
                return True
        finally:
            # Close the client if we created it
            if not self._client_provided:
                await self.client.aclose()
        return None

    async def login(
        self,
        user: str = "",
        password: str = "",
        api_token: Optional[str] = None,
    ) -> None:
        """Convenience method for calling user.authenticate
        and storing the resulting auth token for further commands.

        If use_authenticate is set, it uses the older (Zabbix 1.8)
        authentication command

        :param password: Password used to login into Zabbix
        :param user: Username used to login into Zabbix
        :param api_token: API Token to authenticate with
        """

        if self._detect_version:
            self.version = Version(await self.api_version())
            logger.info("Zabbix API version is: %s", self.version)

        # If the API token is explicitly provided, use this instead.
        if api_token is not None:
            self.use_api_token = True
            self.auth = api_token
            return

        # If we have an invalid auth token, we are not allowed to send a login
        # request. Clear it before trying.
        self.auth = ""
        if self.use_authenticate:
            self.auth = await self.user.authenticate(user=user, password=password)
        elif self.version and self.version >= ZABBIX_5_4_0:
            self.auth = await self.user.login(username=user, password=password)
        else:
            self.auth = await self.user.login(user=user, password=password)

    async def check_authentication(self):
        if self.use_api_token:
            # We cannot use this call using an API Token
            return True
        # Convenience method for calling user.checkAuthentication of the current session
        return await self.user.checkAuthentication(sessionid=self.auth)

    async def is_authenticated(self) -> bool:
        if self.use_api_token:
            # We cannot use this call using an API Token
            return True

        try:
            await self.user.checkAuthentication(sessionid=self.auth)
        except AsyncZabbixAPIException:
            return False
        return True

    async def confimport(
        self,
        confformat: str = "",
        source: str = "",
        rules: str = "",
    ) -> dict:
        """Alias for configuration.import because it clashes with
        Python's import reserved keyword
        :param rules:
        :param source:
        :param confformat:
        """
        warn(
            "AsyncZabbixAPI.confimport(format, source, rules) has been deprecated, please use "
            "AsyncZabbixAPI.configuration['import'](format=format, source=source, rules=rules) instead",
            DeprecationWarning,
            2,
        )

        return await self.configuration["import"](
            format=confformat,
            source=source,
            rules=rules,
        )

    async def api_version(self) -> str:
        return await self.apiinfo.version()

    async def do_request(
        self,
        method: str,
        params: Optional[Union[Mapping, Sequence]] = None,
    ) -> dict:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self.id,
        }
        headers = {}

        # We don't have to pass the auth token if asking for
        # the apiinfo.version or user.checkAuthentication
        anonymous_methods = {
            "apiinfo.version",
            "user.checkAuthentication",
            "user.login",
        }
        if self.auth and method not in anonymous_methods:
            if self.version and self.version >= ZABBIX_6_4_0:
                headers["Authorization"] = f"Bearer {self.auth}"
            else:
                payload["auth"] = self.auth

        logger.debug("Sending: %s", payload)
        resp = await self.client.post(
            self.url,
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )
        logger.debug("Response Code: %s", resp.status_code)

        # NOTE: Getting a 412 response code means the headers are not in the
        # list of allowed headers.
        resp.raise_for_status()

        if not resp.text:
            raise AsyncZabbixAPIException("Received empty response")

        try:
            response = resp.json()
        except ValueError as exception:
            raise AsyncZabbixAPIException(
                f"Unable to parse json: {resp.text}"
            ) from exception

        logger.debug("Response Body: %s", response)

        self.id += 1

        if "error" in response:  # some exception
            error = response["error"]

            # some errors don't contain 'data': workaround for ZBX-9340
            if "data" not in error:
                error["data"] = "No data"

            raise AsyncZabbixAPIException(
                f"Error {error['code']}: {error['message']}, {error['data']}",
                error["code"],
                error=error,
            )

        return response

    def _object(self, attr: str) -> "AsyncZabbixAPIObject":
        """Dynamically create an object class (ie: host)"""
        return AsyncZabbixAPIObject(attr, self)

    def __getattr__(self, attr: str) -> "AsyncZabbixAPIObject":
        return self._object(attr)

    def __getitem__(self, attr: str) -> "AsyncZabbixAPIObject":
        return self._object(attr)


# pylint: disable=too-few-public-methods
class AsyncZabbixAPIMethod:
    def __init__(self, method: str, parent: AsyncZabbixAPI):
        self._method = method
        self._parent = parent

    async def __call__(self, *args, **kwargs):
        if args and kwargs:
            raise TypeError("Found both args and kwargs")

        result = await self._parent.do_request(self._method, args or kwargs)
        return result["result"]


# pylint: disable=too-few-public-methods
class AsyncZabbixAPIObject:
    def __init__(self, name: str, parent: AsyncZabbixAPI):
        self._name = name
        self._parent = parent

    def _method(self, attr: str) -> AsyncZabbixAPIMethod:
        """Dynamically create a method (ie: get)"""
        return AsyncZabbixAPIMethod(f"{self._name}.{attr}", self._parent)

    def __getattr__(self, attr: str) -> AsyncZabbixAPIMethod:
        return self._method(attr)

    def __getitem__(self, attr: str) -> AsyncZabbixAPIMethod:
        return self._method(attr)


class AsyncZabbixAPIObjectClass(AsyncZabbixAPIObject):
    def __init__(self, *args, **kwargs):
        warn(
            "AsyncZabbixAPIObjectClass has been renamed to AsyncZabbixAPIObject",
            DeprecationWarning,
            2,
        )
        super().__init__(*args, **kwargs)