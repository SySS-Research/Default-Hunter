from .scanner import Scanner
import telnetlib3.telnetlib as telnetlib
from typing import Dict, Any, TYPE_CHECKING
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class Telnet(Scanner):
    def __init__(
        self,
        cred: Dict[str, Any],
        target: Target,
        username: str,
        password: str,
        config: "Config",
    ) -> None:
        super(Telnet, self).__init__(cred, target, config, username, password)

    def _check(self) -> str:
        try:
            telnet = telnetlib.Telnet(str(self.target.host))
            timeout_allowed = int(self.cred["auth"]["blockingio_timeout"])
            wait_for_pass_prompt = int(self.cred["auth"]["telnet_read_timeout"])

            telnet.open(str(self.target.host), int(self.target.port or 23), timeout=timeout_allowed)
            telnet.write((str(self.username) + "\n").encode())

            password = str(self.password) if self.password else ""

            result = telnet.read_until(b"Password: ", timeout=wait_for_pass_prompt)
            result = Telnet._trim_string(result.decode(errors="ignore"))

            if "Password:" in result:
                telnet.write((str(password) + "\n").encode())
            else:
                self.logger.debug("Check closed at: 1")
                telnet.close()
                raise Exception("Telnet credential not found")

            telnet.write(b"ls\n")

            evidence = telnet.read(1024, timeout=3)
            evidence_fp_check = Telnet._trim_string(evidence.decode(errors="ignore"))

            self.logger.debug(f"Evidence string returned (stripped): {evidence_fp_check}")
            evidence_fp_check_as_bytes = ":".join("{:02x}".format(ord(c)) for c in evidence_fp_check)
            self.logger.debug(f"Evidence string returned (bytes): {str(evidence_fp_check_as_bytes)}")

            # Remove simple echos or additional password prompt (wrong password)
            if (
                (not evidence_fp_check)
                or (evidence_fp_check == "ls")
                or ("Password:" in evidence_fp_check)
                or ("Invalid" in evidence_fp_check)
                or ("failed" in evidence_fp_check)
                or (evidence_fp_check == "")
            ):
                self.logger.debug("Check closed at: 2")
                telnet.close()
                raise Exception("Telnet credential not found")

            # Remove additional prompts to login - we have a correct username, but incorrect password
            if evidence_fp_check.strip().endswith("login:"):
                self.logger.debug("Check closed at: 3")
                telnet.close()
                raise Exception("Telnet credential not found")

            telnet.close()

            return evidence.decode(errors="ignore")

        except Exception as e:
            self.logger.debug(f"Error: {str(e)}")
            raise e

    @staticmethod
    def _trim_string(str_to_trim: str) -> str:
        return (
            str(str_to_trim).replace(" ", "").replace(r"\s", "").replace("\t", "").replace("\r", "").replace("\n", "")
        )

    def _mkscanner(self, cred: Dict[str, Any], target: Target, u: str, p: str, config: "Config") -> "Telnet":
        return Telnet(cred, target, u, p, config)
