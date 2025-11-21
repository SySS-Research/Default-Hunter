import logging
import multiprocessing as mp
import queue
import time
from typing import List, Dict, Any, Set, Type, TYPE_CHECKING

from .redis_queue import RedisQueue
from .scanners.http_fingerprint import HttpFingerprint
from . import scanners
from .target import Target
from .scanners.scanner import Scanner

if TYPE_CHECKING:
    from .core import Config

# scanner_map maps the friendly proto:// name to the actual class
SCANNER_MAP: Dict[str, Type[Scanner]] = {
    "ssh": scanners.SSH,
    "ssh_key": scanners.SSHKey,
    "ftp": scanners.FTP,
    "memcached": scanners.MemcachedScanner,
    "mongodb": scanners.Mongodb,
    "mssql": scanners.MSSQL,
    "mysql": scanners.MySQL,
    "postgres": scanners.Postgres,
    "redis": scanners.RedisScanner,
    "snmp": scanners.SNMP,
    "telnet": scanners.Telnet,
}


def get_scanner_class(protocol: str) -> Type[Scanner]:
    """
    Get the scanner class for a given protocol.

    Args:
        protocol: The protocol name (e.g., 'ssh', 'ftp', 'mysql')

    Returns:
        The scanner class for the protocol

    Raises:
        KeyError: If the protocol is not supported
    """
    return SCANNER_MAP[protocol]


class ScanEngine(object):
    def __init__(self, creds: List[Dict[str, Any]], config: "Config") -> None:
        self.creds: List[Dict[str, Any]] = creds
        self.config: "Config" = config
        self.logger: logging.Logger = logging.getLogger("changeme")
        self._manager: Any = mp.Manager()
        self.scanners: RedisQueue = self._get_queue("scanners")
        self.total_scanners: int = 0
        self.targets: Set[Target] = set()
        self.fingerprints: RedisQueue = self._get_queue("fingerprints")
        self.total_fps: int = 0
        self.found_q: RedisQueue = self._get_queue("found_q")
        self.scanned_targets = set()
        self.lock = mp.Lock()

    def scan(self) -> None:
        # Phase I - Fingerprint
        ######################################################################
        if not self.config.resume:
            self._build_targets()

        if self.config.dryrun:
            self.dry_run()

        num_procs = (
            self.config.threads if self.fingerprints.qsize() > self.config.threads else self.fingerprints.qsize()
        )

        self.logger.debug(f"Number of threads: {num_procs}")
        self.total_fps = self.fingerprints.qsize()
        procs = [mp.Process(target=self.fingerprint_targets) for _ in range(num_procs)]

        for proc in procs:
            proc.start()

        for proc in procs:
            proc.join()

        self.logger.info("Fingerprinting completed")
        self.logger.debug(f"Scanners: {self.scanners.qsize()}")

        # Phase II - Scan
        ######################################################################
        if not self.config.fingerprint:
            num_procs = self.config.threads if self.scanners.qsize() > self.config.threads else self.scanners.qsize()
            self.total_scanners = self.scanners.qsize()

            self.logger.debug(f"Starting {num_procs} scanner threads")
            procs = [mp.Process(target=self._scan, args=(self.scanners, self.found_q)) for i in range(num_procs)]

            for proc in procs:
                self.logger.debug("Starting scanner thread")
                proc.start()

            for proc in procs:
                proc.join()

            self.logger.info("Scanning Completed")

            # Hack to address a broken pipe IOError per https://stackoverflow.com/questions/36359528/broken-pipe-error-with-multiprocessing-queue
            time.sleep(0.1)

    def _scan(self, scanq: RedisQueue, foundq: RedisQueue) -> None:
        while True:
            with self.lock:
                try:
                    scanner = scanq.get(block=False)
                except queue.Empty:
                    return
                except Exception as e:
                    self.logger.debug(f"Caught exception: {type(e).__name__}", exc_info=True)
                    continue

                if not scanner:
                    return

                if scanner.scan_id in self.scanned_targets:
                    continue

                self.scanned_targets.add(scanner.scan_id)
                remaining = self.scanners.qsize()

            self.logger.debug(f"{remaining} scanners remaining")

            result = scanner.scan()
            if result:
                foundq.put(result)

    def fingerprint_targets(self) -> None:
        while True:
            with self.lock:
                remaining = self.fingerprints.qsize()

                try:
                    fp = self.fingerprints.get(block=False)
                except queue.Empty:
                    return
                except Exception as e:
                    self.logger.debug(f"Caught exception: {type(e).__name__}")
                    exception_str = e.__str__().replace("\n", "|")
                    self.logger.debug(f"Exception: {type(e).__name__}: {exception_str}")
                    return

            if not fp:
                return

            self.logger.debug(f"{remaining} fingerprints remaining")
            if fp.fingerprint():
                results = fp.get_scanners(self.creds)
                if results:
                    for result in results:
                        self.scanners.put(result)
            else:
                self.logger.debug("failed fingerprint")

    def _build_targets(self) -> None:
        self.logger.debug("Building targets")

        if self.config.target:
            self.targets = Target.parse_target(self.config.target)
        else:
            self.logger.warning("shodan")
            self.targets = Target.get_shodan_targets(self.config)

        # Load set of targets into queue
        self.logger.debug(f"{len(self.targets)} targets")

        # If there's only one target and the user specified a protocol, override the defaults
        if len(self.targets) == 1:
            t = self.targets.pop()
            if t.protocol:
                self.config.protocols = [t.protocol]
            self.targets.add(t)

        fingerprints = list()
        # Build a set of unique fingerprints
        if "http" in self.config.protocols:
            fingerprints = fingerprints + HttpFingerprint.build_fingerprints(self.targets, self.creds, self.config)

        fingerprints = list(set(fingerprints))  # unique the HTTP fingerprints

        self.logger.info(f"Configured protocols: {', '.join(self.config.protocols)}")

        for target in self.targets:
            for cred in self.creds:
                for proto in SCANNER_MAP.keys():
                    if cred["protocol"] == proto and (proto in self.config.protocols):
                        # Target may already have a protocol if imported from nmap
                        if target.protocol is None or target.protocol == proto:
                            t = Target(host=target.host, port=target.port, protocol=proto)
                            scanner_class = get_scanner_class(proto)
                            fingerprints.append(scanner_class(cred, t, self.config, "", ""))

        self.logger.info("Loading creds into queue")
        for fp in set(fingerprints):
            self.fingerprints.put(fp)
        self.total_fps = self.fingerprints.qsize()
        self.logger.debug(f"{self.fingerprints.qsize()} fingerprints")

    def dry_run(self) -> None:
        self.logger.info("Dry run targets:")
        while self.fingerprints.qsize() > 0:
            fp = self.fingerprints.get()
            if fp is not None:
                self.logger.info(fp.target)
        quit()

    def _get_queue(self, name: str) -> RedisQueue:
        self.logger.debug(f"Using multiprocessing queue for {name}")
        q = self._manager.Queue()
        return RedisQueue(name, manager_queue=q)
