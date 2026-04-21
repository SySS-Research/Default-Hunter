from pymongo import MongoClient
from .scanner import Scanner
from typing import Dict, Any, TYPE_CHECKING
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class Mongodb(Scanner):
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

        u_p = ""
        if self.username or self.password:
            u_p = f"{self.username}:{self.password}@"
        client = MongoClient(f"mongodb://{u_p}{self.target.host}:{self.target.port}/")
        dbs = client.database_names()  # type: ignore[call-arg]
        server_info = client.server_info()
        evidence = f"Version: {server_info['version']}, databases: {', '.join(dbs)}"

        return evidence

    def _mkscanner(
        self, *, cred: Dict[str, Any], target: Target, username: str, password: str, config: "Config"
    ) -> "Mongodb":
        return Mongodb(cred, target, username=username, password=password, config=config)
