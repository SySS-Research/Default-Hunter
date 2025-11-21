from pymongo import MongoClient
from .scanner import Scanner


class Mongodb(Scanner):
    def __init__(self, cred, target, username, password, config):
        super(Mongodb, self).__init__(cred, target, config, username, password)

    def _check(self):
        u_p = ""
        if self.username or self.password:
            u_p = f"{self.username}:{self.password}@"
        client = MongoClient(f"mongodb://{u_p}{self.target.host}:{self.target.port}/")
        dbs = client.database_names()
        server_info = client.server_info()
        evidence = f"Version: {server_info['version']}, databases: {', '.join(dbs)}"

        return evidence

    def _mkscanner(self, cred, target, u, p, config):
        return Mongodb(cred, target, u, p, config)
