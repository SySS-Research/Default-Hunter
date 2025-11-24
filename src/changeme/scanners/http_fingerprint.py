from changeme.scanners.http_basic_auth import HTTPBasicAuthScanner
from changeme.scanners.http_get import HTTPGetScanner
from changeme.scanners.http_post import HTTPPostScanner
from changeme.scanners.http_raw_post import HTTPRawPostScanner
from changeme.target import Target
from copy import deepcopy
import logging
from lxml import html
import re
import requests
from typing import Optional, Dict, Any, List


class HttpFingerprint:
    def __init__(
        self,
        target: Target,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]],
        config: Any,
    ) -> None:
        self.target: Target = target
        self.headers: Optional[Dict[str, str]] = headers
        self.cookies: Optional[Dict[str, str]] = cookies
        self.config: Any = config
        self.logger: logging.Logger = logging.getLogger("changeme")
        self.res: Optional[requests.Response] = None
        self.req: requests.Session = requests.Session()

    def __getstate__(self):
        state = self.__dict__
        state["logger"] = None  # Need to clear the logger when serializing otherwise mp.Queue blows up
        return state

    def __setstate__(self, d):
        self.__dict__ = d
        self.logger = logging.getLogger("changeme")

    def __hash__(self) -> int:
        return hash(str(self.target) + str(self.headers) + str(self.cookies))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HttpFingerprint):
            return False
        s: Dict[str, Any] = dict()
        o: Dict[str, Any] = dict()
        s["target"] = self.target
        s["headers"] = self.headers
        s["cookies"] = self.cookies
        o["target"] = other.target
        o["headers"] = other.headers
        o["cookies"] = other.cookies
        return s == o

    def fingerprint(self) -> bool:
        try:
            self._fp()
        except Exception as e:
            if self.config.ssl and e.__class__ == requests.exceptions.SSLError:
                self.target.protocol = "http"
                self.logger.debug(f"Retrying with non-SSL target: {self.target}")
                try:
                    self._fp()
                except Exception as e:
                    self.logger.debug(f"Failed to connect to {self.target}")

            return False

        return True

    def _fp(self) -> None:
        self.res = self.req.get(
            str(self.target),
            timeout=self.config.timeout,
            verify=False,
            proxies=self.config.proxy,
            headers=self.headers,
            cookies=self.cookies,
        )

    def _get_csrf_token(self, res: requests.Response, cred: Dict[str, Any]) -> Optional[str]:
        name = cred["auth"].get("csrf", False)
        if name:
            tree = html.fromstring(res.content)
            try:
                csrf = str(tree.xpath(f'//input[@name="{name}"]/@value')[0])
            except Exception:
                self.logger.error(f"Failed to get CSRF token {name} in {res.url}")
                return False
            self.logger.debug(f"Got CSRF token {name}: {csrf}")
        else:
            csrf = False

        return csrf

    def _get_session_id(self, res: requests.Response, cred: Dict[str, Any]) -> Optional[Dict[str, str]]:
        cookie = cred["auth"].get("sessionid", False)

        if cookie:
            try:
                value = res.cookies[cookie]
                self.logger.debug(f"Got session cookie value: {value}")
            except Exception:
                self.logger.error(f"Failed to get {cookie} cookie from {res.url}")
                return False
            return {cookie: value}
        else:
            self.logger.debug("No cookie")
            return False

    def ismatch(self, cred: Dict[str, Any], response: requests.Response) -> bool:
        match = False
        if cred["protocol"] == "http":
            fp = cred["fingerprint"]
            basic_auth = fp.get("basic_auth_realm", None)
            if basic_auth and basic_auth in response.headers.get("WWW-Authenticate", list()):
                self.logger.info(f"{cred['name']} basic auth matched: {basic_auth}")
                match = True

            server = response.headers.get("Server", None)
            fp_server = fp.get("server_header", None)
            if fp_server and server and fp_server in server:
                self.logger.debug(f"{cred['name']} server header matched: {fp_server}")
                match = True

            body = fp.get("body", None)
            if body:
                for b in body:
                    if re.search(b, response.text):
                        match = True
                        self.logger.info(f"{cred['name']} body matched: {b}")
                    elif body:
                        match = False

        return match

    def get_scanners(self, creds: List[Dict[str, Any]]) -> List[Any]:
        scanners = list()
        for cred in creds:
            if self.ismatch(cred, self.res):
                csrf = self._get_csrf_token(self.res, cred)
                if cred["auth"].get("csrf", False) and not csrf:
                    self.logger.error("Missing required CSRF token")
                    return

                sessionid = self._get_session_id(self.res, cred)
                if cred["auth"].get("sessionid") and not sessionid:
                    self.logger.error(f"Missing session cookie {cred['auth'].get('sessionid')} for {self.res.url}")
                    return

                for pair in cred["auth"]["credentials"]:
                    for u in cred["auth"]["url"]:  # pass in the auth url
                        target = deepcopy(self.target)
                        target.url = u
                        self.logger.debug(f"Building {cred['name']} {pair['username']}:{pair['password']}, {target}")

                        if cred["auth"]["type"] == "get":
                            scanners.append(
                                HTTPGetScanner(
                                    cred, target, pair["username"], pair["password"], self.config, self.req.cookies
                                )
                            )
                        elif cred["auth"]["type"] == "post":
                            scanners.append(
                                HTTPPostScanner(
                                    cred,
                                    target,
                                    pair["username"],
                                    pair["password"],
                                    self.config,
                                    self.req.cookies,
                                    csrf,
                                )
                            )
                        elif cred["auth"]["type"] == "raw_post":
                            scanners.append(
                                HTTPRawPostScanner(
                                    cred,
                                    target,
                                    pair["username"],
                                    pair["password"],
                                    self.config,
                                    self.req.cookies,
                                    csrf,
                                    pair["raw"],
                                )
                            )
                        elif cred["auth"]["type"] == "basic_auth":
                            scanners.append(
                                HTTPBasicAuthScanner(
                                    cred, target, pair["username"], pair["password"], self.config, self.req.cookies
                                )
                            )

        return scanners

    @staticmethod
    def build_fingerprints(targets: Any, creds: List[Dict[str, Any]], config: Any) -> List["HttpFingerprint"]:
        fingerprints = list()
        logger = logging.getLogger("changeme")
        # Build a set of unique fingerprints
        for target in targets:
            for c in creds:
                if not c["protocol"] == "http":
                    continue
                if not config.portoverride and (target.port and not c["default_port"] == target.port):
                    continue

                fp = c["fingerprint"]
                for url in fp.get("url"):
                    t = Target(host=target.host, port=target.port, protocol=target.protocol)
                    if c.get("ssl") or config.ssl:
                        t.protocol = "https"
                    else:
                        t.protocol = "http"

                    if not t.port:
                        t.port = c["default_port"]
                    t.url = url

                    hfp = HttpFingerprint(t, fp.get("headers", None), fp.get("cookie", None), config)
                    logger.debug(f"Adding to fingerprint list: {c.get('name')} [{t}]")
                    fingerprints.append(hfp)

        return fingerprints
