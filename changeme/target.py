from libnmap.parser import NmapParser as np
import logging
from netaddr import IPNetwork
from netaddr.core import AddrFormatError
import re
from os.path import isfile
import shodan
import socket
from typing import Optional, Set, Any


class Target(object):
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int | str] = None,
        protocol: Optional[str] = None,
        url: Optional[str] = None,
    ) -> None:
        self.host: Optional[str] = host
        if port:
            port = re.sub(r"\D", "", str(port))
            if 0 < int(port) < 65535:
                self.port: Optional[int] = int(port)
            else:
                # just disregard the port for now.
                self.port = None
        else:
            self.port = None
        self.protocol: Optional[str] = protocol
        self.url: Optional[str] = url
        self.ip: Optional[str] = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Target):
            return False
        return self.__dict__ == other.__dict__

    def __hash__(self) -> int:
        return id(self)

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        target: str = ""

        if self.host:
            target = self.host

        if self.port:
            target += f":{self.port}"

        if self.protocol:
            target = f"{self.protocol}://" + target

        if self.url:
            target += self.url

        return target

    def get_ip(self) -> Optional[str]:
        if self.ip is None and self.host:
            regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
            result = regex.match(self.host)
            if not result:
                self.ip = socket.gethostbyname(self.host)
            else:
                self.ip = self.host

        return self.ip

    @staticmethod
    def parse_target(target: str) -> Set["Target"]:
        logger = logging.getLogger("changeme")
        targets: Set[Target] = set()
        if isfile(target):
            try:
                # parse nmap
                report = np.parse_fromfile(target)  # type: ignore
                logger.info(f"Loaded {len(report.hosts)} hosts from {target}")  # type: ignore
                for h in report.hosts:  # type: ignore
                    for s in h.services:  # type: ignore
                        targets.add(Target(host=h.address, port=s.port))  # type: ignore
            except:
                # parse text file
                with open(target, "r") as fin:
                    for line in fin:
                        res = Target._parse_target_string(line)
                        for t in res:
                            targets.add(t)
        else:
            targets = Target._parse_target_string(target)

        return targets

    @staticmethod
    def _parse_target_string(target: str) -> Set["Target"]:
        logger = logging.getLogger("changeme")
        logger.debug(f"Parsing target {target}")
        target = target.strip().rstrip("/")
        targets: Set[Target] = set()
        try:
            for ip in IPNetwork(target).iter_hosts():  # (covers IP or cidr) #3,4
                targets.add(Target(host=str(ip)))
        except AddrFormatError:
            if len(target.split(":")) == 3:
                # mysql://127.0.0.1:3306
                protocol = target.split(":")[0]
                host = target.split(":")[1].replace("//", "")
                port = target.split(":")[2]
                targets.add(Target(host=host, port=port, protocol=protocol))
            elif "://" in target:
                # snmp://127.0.0.1
                protocol = target.split(":")[0]
                host = target.split(":")[1].replace("//", "")
                targets.add(Target(host=host, protocol=protocol))
            elif ":" in target:
                # 127.0.0.1:8080
                host = target.split(":")[0]
                port = target.split(":")[1]
                targets.add(Target(host=host, port=port))
            else:
                targets.add(Target(host=target))

        return targets

    @staticmethod
    def get_shodan_targets(config: Any) -> Set["Target"]:
        logger = logging.getLogger("changeme")
        targets: Set[Target] = set()
        api = shodan.Shodan(config.shodan_key)
        results = api.search(config.shodan_query)
        logger.debug(f"shodan results: {results}")
        for r in results["matches"]:
            targets.add(Target(host=r["ip_str"]))

        return targets
