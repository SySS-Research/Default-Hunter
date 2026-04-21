import paramiko
from .scanner import Scanner
from typing import Dict, Any, TYPE_CHECKING
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class SSH(Scanner):
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
        if not self.target.host or not self.target.port:
            raise ValueError("Target host and port must be set")

        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())  # ignore unknown hosts
        c.connect(hostname=self.target.host, port=self.target.port, username=self.username, password=self.password)
        stdin, stdout, stderr = c.exec_command("uname -a")
        evidence = stdout.readlines()[0]
        c.close()

        return evidence

    def _mkscanner(
        self, *, cred: Dict[str, Any], target: Target, username: str, password: str, config: "Config"
    ) -> "SSH":
        return SSH(cred, target, username=username, password=password, config=config)
