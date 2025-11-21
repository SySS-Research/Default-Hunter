try:
    import redis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

from .scanner import Scanner


class RedisScanner(Scanner):
    def __init__(self, cred, target, username, password, config):
        super(RedisScanner, self).__init__(cred, target, config, username, password)

    def _check(self):
        if not HAS_REDIS:
            return "redis module not installed - install with: pip install redis"

        r = redis.StrictRedis(host=self.target.host, port=self.target.port)
        info = r.info()
        evidence = "redis_version: %s, os: %s" % (info["redis_version"], info["os"])

        return evidence

    def _mkscanner(self, cred, target, u, p, config):
        return RedisScanner(cred, target, u, p, config)
