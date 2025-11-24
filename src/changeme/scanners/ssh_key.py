import logging
import paramiko
from .ssh import SSH
from io import StringIO
from typing import Dict, Any, TYPE_CHECKING
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class SSHKey(SSH):
    def __init__(
        self,
        cred: Dict[str, Any],
        target: Target,
        username: str,
        key: str,
        config: "Config",
    ) -> None:
        super(SSHKey, self).__init__(cred, target, username, key, config)
        self.logger = logging.getLogger("changeme")

    def _check(self) -> str:
        fake = StringIO(self.password)
        if "RSA PRIVATE KEY" in self.password:
            key = paramiko.RSAKey.from_private_key(fake)
        elif "DSA PRIVATE KEY" in self.password:
            key = paramiko.DSSKey.from_private_key(fake)

        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())  # ignore unknown hosts
        c.connect(hostname=self.target.host, port=self.target.port, username=self.username, pkey=key)
        stdin, stdout, stderr = c.exec_command("uname -a")
        evidence = stdout.readlines()[0]
        c.close()

        self.password = "Private Key"
        return evidence

    def _mkscanner(self, cred: Dict[str, Any], target: Target, u: str, p: str, config: "Config") -> "SSHKey":
        return SSHKey(cred, target, u, p, config)
