from dataclasses import dataclass, asdict
import logging
import socket
from typing import Dict, Any, Optional, List, TYPE_CHECKING
from changeme.target import Target

if TYPE_CHECKING:
    from ..core import Config


@dataclass
class ScanSuccess:
    name: str
    username: str
    password: str
    target: Target
    evidence: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Scanner(object):
    def __init__(
        self,
        cred: Dict[str, Any],
        target: Target,
        config: "Config",
        username: str,
        password: str,
    ) -> None:
        self.logger: logging.Logger = logging.getLogger("changeme")
        self.cred: Dict[str, Any] = cred
        self.target: Target = target
        if self.target.port is None:
            self.target.port = self.cred["default_port"]
        self.config: "Config" = config
        self.username: str = username
        self.password: str = password

    def __hash__(self) -> int:
        return id(self)

    def scan(self) -> Optional[Dict[str, Any]]:
        return self.check_success()

    def fingerprint(self) -> bool:
        if self.target.port is None:
            self.target.port = self.cred["default_port"]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((str(self.target.host), self.target.port))
            sock.shutdown(2)
            if result == 0:
                return True
                self.logger.info(f"Port {self.target.port} open")
            else:
                return False
        except Exception as e:
            self.logger.debug(str(e))
            return False

    def get_scanners(self, creds: List[Dict[str, Any]]) -> List["Scanner"]:
        scanners = list()
        for pair in self.cred["auth"]["credentials"]:
            scanners.append(self._mkscanner(self.cred, self.target, pair["username"], pair["password"], self.config))
        return scanners

    def check_success(self) -> Optional[ScanSuccess]:
        try:
            evidence = self._check()
            self.logger.critical(
                f"[+] Found {self.cred['name']} default cred {self.username}:{self.password} at {self.target}"
            )
            self.logger.debug(f"{self.target} {self.username}:{self.password} evidence: {evidence}")
            return ScanSuccess(
                name=self.cred["name"],
                username=self.username,
                password=self.password,
                target=self.target,
                evidence=evidence,
            )

        except Exception as e:
            self.logger.info(
                f"Invalid {self.cred['name']} default cred {self.username}:{self.password} at {self.target}"
            )
            self.logger.debug(f"{type(e).__name__} Exception: {str(e)}")
            return None

    def _check(self) -> Any:
        raise NotImplementedError("A Scanner class needs to implement a _check method.")

    def __getstate__(self) -> Dict[str, Any]:
        state = self.__dict__
        state["logger"] = None  # Need to clear the logger when serializing otherwise mp.Queue blows up
        return state

    def __setstate__(self, d: Dict[str, Any]) -> None:
        self.__dict__ = d
        self.logger = logging.getLogger("changeme")

    @property
    def scan_id(self) -> str:
        return str(self.target)
