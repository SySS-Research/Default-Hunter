try:
    import redis

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
        username: str,
        password: str,
        config: "Config",
    ) -> None:
        super(RedisScanner, self).__init__(cred, target, config, username, password)

    def _check(self) -> str:
        if not HAS_REDIS:
            return "redis module not installed - install with: pip install redis"

        r = redis.StrictRedis(host=self.target.host, port=self.target.port)
        info = r.info()
        evidence = f"redis_version: {info['redis_version']}, os: {info['os']}"

        return evidence

    def _mkscanner(self, cred: Dict[str, Any], target: Target, u: str, p: str, config: "Config") -> "RedisScanner":
        return RedisScanner(cred, target, u, p, config)
