from changeme.scanners.http_post import HTTPPostScanner
from typing import Dict, Any, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core import Config


class HTTPRawPostScanner(HTTPPostScanner):
    def __init__(
        self,
        cred: Dict[str, Any],
        target: Any,
        username: str,
        password: str,
        config: "Config",
        cookies: Optional[Dict[str, str]],
        csrf: Optional[str],
        raw: str,
    ) -> None:
        super(HTTPRawPostScanner, self).__init__(cred, target, username, password, config, cookies, csrf)
        self.raw: str = raw

    def __reduce__(self) -> Tuple[type, Tuple[Any, ...]]:
        return (
            self.__class__,
            (self.cred, self.target, self.username, self.password, self.config, self.cookies, self.csrf, self.raw),
        )

    def _make_request(self) -> None:
        self.logger.debug("_make_request")
        self.logger.debug(f"target: {self.target}")
        self.response = self.request.post(
            self.target,
            self.raw,
            verify=False,
            proxies=self.config.proxy,
            timeout=self.config.timeout,
            headers=self.headers,
            cookies=self.cookies,
        )
