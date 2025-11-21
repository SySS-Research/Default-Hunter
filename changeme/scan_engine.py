import logging
import multiprocessing as mp
from changeme.redis_queue import RedisQueue
import pickle
from .scanners.http_fingerprint import HttpFingerprint
from .target import Target
import time
from typing import List, Dict, Any, Set


class ScanEngine(object):
    def __init__(self, creds: List[Dict[str, Any]], config: Any) -> None:
        self.creds: List[Dict[str, Any]] = creds
        self.config: Any = config
        self.logger: logging.Logger = logging.getLogger("changeme")
        self._manager: Any = mp.Manager()
        self.scanners: RedisQueue = self._get_queue("scanners")
        self.total_scanners: int = 0
        self.targets: Set[Target] = set()
        self.fingerprints: RedisQueue = self._get_queue("fingerprints")
        self.total_fps: int = 0
        self.found_q: RedisQueue = self._get_queue("found_q")

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

        self.logger.debug(f"Number of procs: {num_procs}")
        self.total_fps = self.fingerprints.qsize()
        procs = [mp.Process(target=self.fingerprint_targets) for i in range(num_procs)]

        self._add_terminators(self.fingerprints)

        for proc in procs:
            proc.start()

        for proc in procs:
            proc.join()

        self.logger.info("Fingerprinting completed")

        # Phase II - Scan
        ######################################################################
        # Unique the queue
        scanners = list()
        while self.scanners.qsize() > 0:
            s = self.scanners.get()

            if s not in scanners:
                scanners.append(s)

        for s in scanners:
            self.scanners.put(s)

        if not self.config.fingerprint:
            num_procs = self.config.threads if self.scanners.qsize() > self.config.threads else self.scanners.qsize()
            self.total_scanners = self.scanners.qsize()

            self.logger.debug(f"Starting {num_procs} scanner procs")
            procs = [mp.Process(target=self._scan, args=(self.scanners, self.found_q)) for i in range(num_procs)]

            self._add_terminators(self.scanners)

            for proc in procs:
                self.logger.debug("Starting scanner proc")
                proc.start()

            for proc in procs:
                proc.join()

            self.logger.info("Scanning Completed")

            # Hack to address a broken pipe IOError per https://stackoverflow.com/questions/36359528/broken-pipe-error-with-multiprocessing-queue
            time.sleep(0.1)

    def _add_terminators(self, q: RedisQueue) -> None:
        # Add poison pills
        for i in range(self.config.threads):
            q.put(None)

    def _scan(self, scanq: RedisQueue, foundq: RedisQueue) -> None:
        while True:
            remaining = self.scanners.qsize()
            self.logger.debug(f"{remaining} scanners remaining")

            try:
                scanner = scanq.get(block=True)
                if scanner is None:
                    return
            except Exception as e:
                self.logger.debug(f"Caught exception: {type(e).__name__}")
                continue

            result = scanner.scan()
            if result:
                foundq.put(result)

    def fingerprint_targets(self) -> None:
        while True:
            remaining = self.fingerprints.qsize()
            self.logger.debug(f"{remaining} fingerprints remaining")

            try:
                fp = self.fingerprints.get()
                if type(fp) is bytes:
                    fp = pickle.loads(fp)

                # Exit process
                if fp is None:
                    return

            except Exception as e:
                self.logger.debug(f"Caught exception: {type(e).__name__}")
                self.logger.debug(f"Exception: {type(e).__name__}: {e.__str__().replace('\n', '|')}")
                return

            if fp.fingerprint():
                results = fp.get_scanners(self.creds)
                if results:
                    for result in results:
                        self.scanners.put(result)
            else:
                self.logger.debug("failed fingerprint")

        self.logger.debug(f"scanners: {self.scanners.qsize()}, {id(self.scanners)}")

    def _build_targets(self) -> None:
        self.logger.debug("Building targets")

        if self.config.target:
            self.targets = Target.parse_target(self.config.target)
        else:
            self.logger.warning("shodan")
            self.targets = Target.get_shodan_targets(self.config)

        # Load set of targets into queue
        self.logger.debug(f"{len(self.targets)} targets")

        # If there's only one protocol and the user specified a protocol, override the defaults
        if len(self.targets) == 1:
            t = self.targets.pop()
            if t.protocol:
                self.config.protocols = t.protocol
            self.targets.add(t)

        fingerprints = list()
        # Build a set of unique fingerprints
        if "http" in self.config.protocols or self.config.all:
            fingerprints = fingerprints + HttpFingerprint.build_fingerprints(self.targets, self.creds, self.config)

        fingerprints = list(set(fingerprints))  # unique the HTTP fingerprints

        # Add any protocols if they were included in the targets
        for t in self.targets:
            if t.protocol and t.protocol not in self.config.protocols:
                self.config.protocols += f",{t.protocol}"

        self.logger.info(f"Configured protocols: {self.config.protocols}")

        # scanner_map maps the friendly proto:// name to the actual class name
        scanner_map = {
            "ssh": "SSH",
            "ssh_key": "SSHKey",
            "ftp": "FTP",
            "memcached": "MemcachedScanner",
            "mongodb": "Mongodb",
            "mssql": "MSSQL",
            "mysql": "MySQL",
            "postgres": "Postgres",
            "redis": "RedisScanner",
            "snmp": "SNMP",
            "telnet": "Telnet",
        }

        for target in self.targets:
            for cred in self.creds:
                for proto, classname in scanner_map.items():
                    if cred["protocol"] == proto and (proto in self.config.protocols or self.config.all):
                        t = Target(host=target.host, port=target.port, protocol=proto)
                        fingerprints.append(globals()[classname](cred, t, self.config, "", ""))

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
