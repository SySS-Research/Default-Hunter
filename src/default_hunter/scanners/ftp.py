from .scanner import Scanner
import ftplib
from typing import Dict, Any, TYPE_CHECKING
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class FTP(Scanner):
    def __init__(
        self,
        cred: Dict[str, Any],
        target: Target,
        *,
        username: str,
        password: str,
        config: "Config",
    ) -> None:
        super().__init__(cred, target, username=username, password=password, config=config)

    def _check(self) -> str:
        if not self.target.host:
            raise ValueError("Target host must be set")
        if not self.target.port:
            raise ValueError("Target port must be set")

        ftp = ftplib.FTP()
        ftp.connect(self.target.host, self.target.port, timeout=30)

        ftp.login(self.username, self.password)
        evidence = ftp.retrlines("LIST")
        ftp.quit()

        return evidence

    def _mkscanner(
        self, *, cred: Dict[str, Any], target: Target, username: str, password: str, config: "Config"
    ) -> "FTP":
        return FTP(cred, target, username=username, password=password, config=config)
