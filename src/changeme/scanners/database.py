from .scanner import Scanner
import sqlalchemy
from typing import Dict, Any, Optional, TYPE_CHECKING
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class Database(Scanner):
    def __init__(
        self,
        cred: Dict[str, Any],
        target: Target,
        username: str,
        password: str,
        config: "Config",
    ) -> None:
        super(Database, self).__init__(cred, target, config, username, password)
        self.database: Optional[str] = None
        self.query: Optional[str] = None

    def _check(self) -> str:
        url = f"{self.target.protocol}://{self.username}:{self.password}@{self.target.host}:{self.target.port}/{self.database}"
        engine = sqlalchemy.create_engine(url, connect_args={"connect_timeout": self.config.timeout})
        c = engine.connect()
        res = c.execute(self.query)

        results = list()
        [results.append(i) for i in res.fetchall()]

        return str(results[0][0])

    def _mkscanner(self, cred: Dict[str, Any], target: Target, u: str, p: str, config: "Config") -> "Database":
        raise NotImplementedError("A Database class needs to implement a _mkscanner method.")
