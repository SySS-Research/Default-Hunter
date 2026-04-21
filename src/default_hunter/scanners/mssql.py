from .database import Database
from typing import Dict, Any, TYPE_CHECKING
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class MSSQL(Database):
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
        self.target.protocol = "mssql+pyodbc"
        self.database = ""
        self.query = "SELECT @@VERSION AS 'SQL Server Version';"

    def _mkscanner(
        self, *, cred: Dict[str, Any], target: Target, username: str, password: str, config: "Config"
    ) -> "MSSQL":
        return MSSQL(cred, target, username=username, password=password, config=config)
