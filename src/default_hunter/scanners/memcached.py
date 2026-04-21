import memcache
from .scanner import Scanner
from typing import Dict, Any, TYPE_CHECKING
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class MemcachedScanner(Scanner):
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

        mc = memcache.Client([f"{self.target.host}:{self.target.port}"], debug=0)
        stats = mc.get_stats()
        evidence = f"version: {stats[0][1]['version']}"

        return evidence

    def _mkscanner(
        self, *, cred: Dict[str, Any], target: Target, username: str, password: str, config: "Config"
    ) -> "MemcachedScanner":
        return MemcachedScanner(cred, target, username=username, password=password, config=config)
