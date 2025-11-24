from changeme.scanners.http_get import HTTPGetScanner
from typing import Dict, Any, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core import Config


class HTTPPostScanner(HTTPGetScanner):
    def __init__(
        self,
        cred: Dict[str, Any],
        target: Any,
        username: str,
        password: str,
        config: "Config",
        cookies: Optional[Dict[str, str]],
        csrf: Optional[str],
    ) -> None:
        super(HTTPPostScanner, self).__init__(cred, target, username, password, config, cookies)
        self.csrf: Optional[str] = csrf

    def __reduce__(self) -> Tuple[type, Tuple[Any, ...]]:
        return (
            self.__class__,
            (self.cred, self.target, self.username, self.password, self.config, self.cookies, self.csrf),
        )

    def _make_request(self) -> None:
        self.logger.debug("_make_request")
        self.logger.debug(f"target: {self.target}")
        data = self.render_creds(self.cred, self.csrf)

        if self.cred.get("form_data"):
            form_data = {}
            for k in data:
                form_data[k] = (None, data[k])

            self.response = self.request.post(
                self.target,
                file=form_data,
                verify=False,
                proxies=self.config.proxy,
                timeout=self.config.timeout,
                headers=self.headers,
                cookies=self.cookies,
            )
        else:
            self.response = self.request.post(
                self.target,
                data,
                verify=False,
                proxies=self.config.proxy,
                timeout=self.config.timeout,
                headers=self.headers,
                cookies=self.cookies,
            )
