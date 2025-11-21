import asyncio
from pysnmp.hlapi.asyncio import (
    get_cmd,
    SnmpEngine,
    CommunityData,
    ContextData,
    UdpTransportTarget,
    ObjectType,
    ObjectIdentity,
)
from typing import Dict, Any, TYPE_CHECKING

from .scanner import Scanner
from ..target import Target

if TYPE_CHECKING:
    from ..core import Config


class SNMP(Scanner):
    def __init__(
        self,
        cred: Dict[str, Any],
        target: Target,
        username: str,
        password: str,
        config: "Config",
    ) -> None:
        super(SNMP, self).__init__(cred, target, config, username, password)

    def fingerprint(self) -> bool:
        # Don't fingerprint since it's UDP
        return True

    def _check(self) -> str:
        # Run the async SNMP check in a synchronous context
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an event loop, we can't use run_until_complete
                # This shouldn't happen in multiprocessing context, but handle it anyway
                raise RuntimeError("Cannot run async SNMP in an already running event loop")
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        try:
            return loop.run_until_complete(self._check_async())
        finally:
            # Clean up to avoid issues with multiprocessing
            if not loop.is_running():
                loop.close()

    async def _check_async(self) -> str:
        transport_target = await UdpTransportTarget.create((str(self.target.host), 161))
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            SnmpEngine(),
            CommunityData(self.password),
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
        )

        evidence = ""
        if errorIndication:
            self.logger.debug(str(errorIndication))
            raise Exception(f"SNMP error: {errorIndication}")
        elif errorStatus:
            error_msg = f"{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
            self.logger.debug(error_msg)
            raise Exception(error_msg)
        else:
            for varBind in varBinds:
                evidence += " = ".join([x.prettyPrint() for x in varBind])

        if evidence == "":
            raise Exception("No SNMP response received")

        return evidence

    def _mkscanner(self, cred: Dict[str, Any], target: Target, u: str, p: str, config: "Config") -> "SNMP":
        return SNMP(cred, target, u, p, config)
