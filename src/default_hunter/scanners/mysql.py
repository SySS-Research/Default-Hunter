from .database import Database
from typing import Dict, Any, TYPE_CHECKING
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class MySQL(Database):
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
        self.database = ""
        self.query = "select version();"

    def _mkscanner(
        self, *, cred: Dict[str, Any], target: Target, username: str, password: str, config: "Config"
    ) -> "MySQL":
        return MySQL(cred, target, username=username, password=password, config=config)
