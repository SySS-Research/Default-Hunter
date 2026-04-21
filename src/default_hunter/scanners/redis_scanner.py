try:
    import redis  # type: ignore[import-not-found]

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

from .scanner import Scanner
from typing import Dict, Any, TYPE_CHECKING
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class RedisScanner(Scanner):
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
        if not HAS_REDIS:
            return "redis module not installed - install with: pip install redis"

        if not self.target.host or not self.target.port:
            raise ValueError("Target host and port must be set")

        r = redis.StrictRedis(host=self.target.host, port=self.target.port)  # type: ignore[possibly-unbound]
        info = r.info()
        evidence = f"redis_version: {info['redis_version']}, os: {info['os']}"

        return evidence

    def _mkscanner(
        self, *, cred: Dict[str, Any], target: Target, username: str, password: str, config: "Config"
    ) -> "RedisScanner":
        return RedisScanner(cred, target, username=username, password=password, config=config)
