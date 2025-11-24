from .database import Database
from typing import Dict, Any, TYPE_CHECKING
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class Postgres(Database):
    def __init__(
        self,
        cred: Dict[str, Any],
        target: Target,
        username: str,
        password: str,
        config: "Config",
    ) -> None:
        super(Postgres, self).__init__(cred, target, username, password, config)
        self.target.protocol = "postgresql+psycopg2"
        self.database = ""
        self.query = "select version();"

    def _mkscanner(self, cred: Dict[str, Any], target: Target, u: str, p: str, config: "Config") -> "Postgres":
        return Postgres(cred, target, u, p, config)
