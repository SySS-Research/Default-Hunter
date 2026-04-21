from default_hunter.scanners.http_get import HTTPGetScanner
from typing import Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core import Config


class HTTPPostScanner(HTTPGetScanner):
    def __init__(
        self,
        cred: Dict[str, Any],
        target: Any,
        *,
        username: str,
        password: str,
        config: "Config",
        cookies: Optional[Dict[str, str]],
        csrf: Optional[str],
    ) -> None:
        super().__init__(cred, target, username=username, password=password, config=config, cookies=cookies)
        self.csrf: Optional[str] = csrf

    def _make_request(self) -> None:
        self.logger.debug("_make_request")
        self.logger.debug(f"target: {self.target}")
        data = self.render_creds(self.cred, self.csrf)

        if self.cred.get("form_data"):
            form_data = {}
            if data:
                for k in data:
                    form_data[k] = (None, data[k])

            self.response = self.request.post(
                str(self.target),
                files=form_data,  # type: ignore[call-arg]
                verify=False,
                proxies=self.config.proxy,
                timeout=self.config.timeout,
                headers=self.headers,
                cookies=self.cookies,
            )
        else:
            self.response = self.request.post(
                str(self.target),
                data,
                verify=False,
                proxies=self.config.proxy,
                timeout=self.config.timeout,
                headers=self.headers,
                cookies=self.cookies,
            )
