import base64
import random
from requests import session
from .scanner import Scanner
import re
from selenium import webdriver
from time import sleep
from typing import Dict, Any, Optional, Tuple, TYPE_CHECKING
import requests

if TYPE_CHECKING:
    from ..core import Config

try:
    # Python 3
    from urllib.parse import urlencode, urlparse
except ImportError:
    # Python 2
    from urllib import urlencode  # type: ignore
    from urlparse import urlparse  # type: ignore

HEADERS_USERAGENTS = [
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
    "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)",
    "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)",
    "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)",
    "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51",
]


def get_useragent() -> str:
    return random.choice(HEADERS_USERAGENTS)


class HTTPGetScanner(Scanner):
    def __init__(
        self,
        cred: Dict[str, Any],
        target: Any,
        username: str,
        password: str,
        config: "Config",
        cookies: Optional[Dict[str, str]],
    ) -> None:
        super(HTTPGetScanner, self).__init__(cred, target, config, username, password)
        self.cred: Dict[str, Any] = cred
        self.config: "Config" = config
        self.cookies: Optional[Dict[str, str]] = cookies
        self.headers: Dict[str, str] = dict()
        self.request: requests.Session = session()
        self.response: Optional[requests.Response] = None

        headers = self.cred["auth"].get("headers", dict())
        custom_ua = False
        if headers:
            for h in headers:
                self.headers.update(h)
                if not custom_ua and any(k.lower() == "user-agent" for k in h):
                    custom_ua = True

        # If set, take user agent from CLI args, otherwise, pick a random
        # one if not provided in the cred file.
        if self.config.useragent:
            self.headers.update(self.config.useragent)
        elif not custom_ua:
            self.headers.update({"User-Agent": get_useragent()})

        # make the cred have only one u:p combo
        self.cred["auth"]["credentials"] = [{"username": self.username, "password": self.password}]

    def __reduce__(self) -> Tuple[type, Tuple[Any, ...]]:
        return self.__class__, (self.cred, self.target, self.username, self.password, self.config, self.cookies)

    def scan(self) -> Optional[Dict[str, Any]]:
        try:
            self._make_request()
        except Exception as e:
            self.logger.error(f"Failed to connect to {self.target}")
            exception_str = e.__str__().replace('\n', '|')
            self.logger.debug(f"Exception: {type(e).__name__}: {exception_str}")
            return None

        if self.response.status_code == 429:
            self.warn(f"Status 429 received. Sleeping for {self.config.delay} seconds and trying again")
            sleep(self.config.delay)
            try:
                self._make_request()
            except Exception:
                self.logger.error(f"Failed to connect to {self.target}")

        return self.check_success()

    def check_success(self) -> Optional[Dict[str, Any]]:
        match = False
        success = self.cred["auth"]["success"]

        if self.cred["auth"].get("base64", None):
            self.username = base64.b64decode(self.cred.username)
            self.password = base64.b64decode(self.cred.password)

        if (
            success.get("status") == self.response.status_code
            or self.response.history
            and self.response.history[0].status_code == success.get("status")
        ):
            self.logger.debug(
                f"{self.target} matched {self.cred['name']} success status code {self.response.status_code}"
            )
            if success.get("body"):
                for string in success.get("body"):
                    if re.search(string, self.response.text, re.IGNORECASE):
                        self.logger.debug(
                            f"{self.target} matched {self.cred['name']} success body text {success.get('body')}"
                        )
                        match = True
                        break
            else:
                match = True

        if match:
            self.logger.critical(
                f"[+] Found {self.cred['name']} default cred {self.username}:{self.password} at {self.target}"
            )
            evidence = ""
            if self.config.output is not None:
                try:
                    evidence = self._screenshot(self.target)
                except Exception as e:
                    self.logger.error(f"Error gathering screenshot for {self.target}")
                    exception_str = e.__str__().replace('\n', '|')
                    self.logger.debug(f"Exception: {type(e).__name__}: {exception_str}")

            return {
                "name": self.cred["name"],
                "username": self.username,
                "password": self.password,
                "target": self.target,
                "evidence": evidence,
            }
        else:
            self.logger.info(
                f"Invalid {self.cred['name']} default cred {self.username}:{self.password} at {self.target}"
            )
            return False

    def _check_fingerprint(self) -> bool:
        self.logger.debug("_check_fingerprint")
        self.request = session()
        self.response = self.request.get(
            self.target,
            timeout=self.config.timeout,
            verify=False,
            proxies=self.config.proxy,
            cookies=self.fingerprint.cookies,
            headers=self.fingerprint.headers,
        )
        self.logger.debug("_check_fingerprint", f"{self.target} - {self.response.status_code}")
        return self.fingerprint.match(self.response)

    def _make_request(self) -> None:
        self.logger.debug("_make_request")
        data = self.render_creds(self.cred)
        qs = urlencode(data)
        url = f"{self.target}?{qs}"
        self.logger.debug(f"url: {url}")
        self.response = self.request.get(
            self.target,
            verify=False,
            proxies=self.config.proxy,
            timeout=self.config.timeout,
            headers=self.headers,
            cookies=self.cookies,
        )

    def render_creds(self, candidate: Dict[str, Any], csrf: Optional[str] = None) -> Optional[Dict[str, str]]:
        """
        Return a list of dicts with post/get data and creds.

        The list of dicts have a data element and a username and password
        associated with the data. The data will either be a dict if its a
        regular GET or POST and a string if its a raw POST.
        """
        b64 = candidate["auth"].get("base64", None)
        type = candidate["auth"].get("type")
        config = None
        if type == "post":
            config = candidate["auth"].get("post", None)
        if type == "get":
            config = candidate["auth"].get("get", None)

        if not type == "raw_post":
            data = self._get_parameter_dict(candidate["auth"])

            if csrf:
                csrf_field = candidate["auth"]["csrf"]
                data[csrf_field] = csrf

            for cred in candidate["auth"]["credentials"]:
                cred_data = {}
                username = ""
                password = ""
                if b64:
                    username = base64.b64encode(cred["username"])
                    password = base64.b64encode(cred["password"])
                else:
                    username = cred["username"]
                    password = cred["password"]

                cred_data[config["username"]] = username
                cred_data[config["password"]] = password

                data_to_send = dict(list(data.items()) + list(cred_data.items()))
                return data_to_send
        else:  # raw post
            return None

    def _get_parameter_dict(self, auth: Dict[str, Any]) -> Dict[str, Any]:
        params = dict()
        data = auth.get("post", auth.get("get", None))
        for k in list(data.keys()):
            if k not in ("username", "password", "url"):
                params[k] = data[k]

        return params

    @staticmethod
    def get_base_url(req: str) -> str:
        parsed = urlparse(req)
        url = f"{parsed[0]}://{parsed[1]}"
        return url

    def _screenshot(self, target: Any) -> str:
        self.logger.debug(f"Screenshotting {self.target}")
        # Set up the selenium webdriver
        # This feels like it will have threading issues
        for key, value in self.response.request.headers.items():
            capability_key = "phantomjs.page.customHeaders.{}".format(key)
            webdriver.DesiredCapabilities.PHANTOMJS[capability_key] = value

        if self.config.proxy:
            webdriver.DesiredCapabilities.PHANTOMJS["proxy"] = {
                "httpProxy": self.config.proxy["http"].replace("http://", ""),
                "ftpProxy": self.config.proxy["http"].replace("http://", ""),
                "sslProxy": self.config.proxy["http"].replace("http://", ""),
                "noProxy": None,
                "proxyType": "MANUAL",
                "autodetect": False,
            }
        driver = webdriver.PhantomJS()
        driver.set_page_load_timeout(int(self.config.timeout) - 0.1)
        driver.set_window_position(0, 0)
        driver.set_window_size(850, 637.5)
        for cookie in self.response.request._cookies.items():
            self.logger.debug(f"Adding cookie: {cookie[0]}:{cookie[1]}")
            driver.add_cookie({"name": cookie[0], "value": cookie[1], "path": "/", "domain": self.target.host})

        try:
            driver.get(str(self.target))
            driver.save_screenshot("screenshot.png")
            evidence = driver.get_screenshot_as_base64()
            driver.quit()
        except Exception as e:
            self.logger.error(f"Error getting screenshot for {self.target}")
            exception_str = e.__str__().replace('\n', '|')
            self.logger.debug(f"Exception: {type(e).__name__}: {exception_str}")
            evidence = ""

        return evidence
