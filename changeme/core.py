import argparse
from cerberus import Validator
import logging
from logutils import colorize
import os
import re
from .report import Report
import requests
from requests import ConnectionError

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
except ImportError:
    from urllib3.exceptions import InsecureRequestWarning  # type: ignore
from .scan_engine import ScanEngine, SCANNER_MAP
from . import schema
import sys
from . import version
import yaml
from typing import Optional, Dict, List, Any

PERSISTENT_QUEUE = "data.db"  # Instantiated in the scan_engine class

all_protocols = list(SCANNER_MAP.keys())


def main() -> Optional[ScanEngine]:
    args = parse_args()
    init_logging(args["args"].verbose, args["args"].debug, args["args"].log)
    config = Config(args["args"], args["parser"])
    if not config.noversion:
        check_version()
    creds = load_creds(config)
    s = None

    if config.mkcred:
        schema.mkcred()
        quit()

    if config.contributors:
        print_contributors(creds)
        quit()

    if config.dump:
        print_creds(creds)
        quit()

    logger = logging.getLogger("changeme")

    if not config.validate:
        check_for_interrupted_scan(config)
        s = ScanEngine(creds, config)
        try:
            s.scan()
        except IOError:
            logger.debug("Caught IOError exception")

        report = Report(s.found_q, config.output)
        report.print_results()

        if config.output and ".json" in config.output or config.output and config.oa:
            report.render_json()
        if config.output and ".csv" in config.output or config.output and config.oa:
            report.render_csv()
        if config.output and ".html" in config.output or config.output and config.oa:
            report.render_html()
        if (
            config.output and not ("json" in config.output or "csv" in config.output or "html" in config.output)
        ) and not config.oa:
            logger.error("Only JSON, CSV and HTML are the only supported output types.")

    return s


def init_logging(verbose: bool = False, debug: bool = False, logfile: Optional[str] = None) -> logging.Logger:
    """
    Logging levels:
        - Critical: Default credential found
        - Error: error in the program
        - Warning: Verbose data
        - Info: more verbose
        - Debug: Extra info for debugging purposes
    """
    # Set up our logging object
    logger = logging.getLogger("changeme")

    if debug:
        logger.setLevel(logging.DEBUG)
    elif verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    if logfile:
        # Create file handler which logs even debug messages
        #######################################################################
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)  # File handler always logs all levels

        # create formatter and add it to the handler
        formatter = logging.Formatter("[%(asctime)s][%(levelname)s] %(message)s")
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # Set up the StreamHandler so we can write to the console
    ###########################################################################
    # create console handler with a higher log level
    ch = colorize.ColorizingStreamHandler(sys.stdout)

    # Set the handler level to match the logger level
    if debug:
        ch.setLevel(logging.DEBUG)
    elif verbose:
        ch.setLevel(logging.INFO)
    else:
        ch.setLevel(logging.WARNING)

    # set custom colorings:
    ch.level_map[logging.DEBUG] = [None, 2, False]
    ch.level_map[logging.INFO] = [None, "white", False]
    ch.level_map[logging.WARNING] = [None, "yellow", False]
    ch.level_map[logging.ERROR] = [None, "red", False]
    ch.level_map[logging.CRITICAL] = [None, "green", False]
    if debug:
        formatter = logging.Formatter("[%(asctime)s][%(module)s][%(funcName)s] %(message)s", datefmt="%H:%M:%S")
    else:
        formatter = logging.Formatter("[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Adjust the loggers for requests and urllib3
    logging.getLogger("requests").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore
    except AttributeError:
        import urllib3

        urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore

    return logger


class Config(object):
    # Define expected attributes with types
    target: Optional[str]
    verbose: bool
    debug: bool
    log: Optional[str]
    noversion: bool
    mkcred: bool
    contributors: bool
    dump: bool
    validate: bool
    resume: bool
    shodan_query: Optional[str]
    output: Optional[str]
    oa: bool
    fingerprint: bool
    delay: int
    protocols: list[str]
    fresh: bool
    name: Optional[str]
    category: Optional[str]
    useragent: Dict[str, str]
    proxy: Optional[Dict[str, str]]
    threads: int
    timeout: int
    ssl: bool
    portoverride: bool
    shodan_key: Optional[str]
    dryrun: bool
    nmap: Optional[str]
    logger: Optional[logging.Logger]

    def __init__(self, args: argparse.Namespace, arg_parser: argparse.ArgumentParser) -> None:
        # Convert argparse Namespace to a dict and make the keys + values member variables of the config class
        args_dict = vars(args)
        self.target = None
        self.logger = None
        for key in args_dict:
            setattr(self, key, args_dict[key])

        self._validate_args(arg_parser)

    def _validate_args(self, ap: argparse.ArgumentParser) -> None:
        logger = logging.getLogger("changeme")
        if (
            not self.validate
            and not self.contributors
            and not self.dump
            and not self.shodan_query
            and not self.mkcred
            and not self.resume
        ) and not self.target:
            ap.print_help()
            quit()

        if self.proxy and isinstance(self.proxy, str) and re.match(r"^https?://[0-9\.]+:[0-9]{1,5}$", self.proxy):
            self.proxy = {"http": self.proxy, "https": self.proxy}
            logger.info(f"Setting proxy to {self.proxy}")
        elif self.proxy and isinstance(self.proxy, str):
            logger.error("Invalid proxy, must be http(s)://x.x.x.x:8080")
            sys.exit()

        if self.delay and self.delay != 0:
            if isinstance(self.delay, int) and 0 <= self.delay <= 1000:
                logger.debug(f"Delay is set to {self.delay} milliseconds")
            else:
                logger.error(
                    f"Invalid delay type. Delay must be an integer between 0 and 1000.  Delay is: {type(self.delay)}"
                )

        # Drop logging level to INFO to see the fingerprint messages
        if self.fingerprint:
            logger.setLevel(logging.INFO)

        if self.verbose:
            logger.setLevel(logging.INFO)
        if self.debug or self.validate:
            logger.setLevel(logging.DEBUG)

        self.useragent = {"User-Agent": str(self.useragent)} if self.useragent else {}

        if isinstance(self.protocols, str):
            self.protocols = self.protocols.split(",")

        logger.debug(f"Protocols: {self.protocols}")

        if self.output and which("phantomjs") is None:
            logger.warning("phantomjs is not in your path, screenshots will not work")

    def _file_exists(self, f: str) -> None:
        if not os.path.isfile(f):
            logger = logging.getLogger("changeme")
            logger.error(f"File {f} not found")
            sys.exit()


def parse_args() -> Dict[str, Any]:
    ap = argparse.ArgumentParser(description=f"Default credential scanner v{version.__version__}")
    ap.add_argument("--category", "-c", type=str, help="Category of default creds to scan for", default=None)
    ap.add_argument("--contributors", action="store_true", help="Display cred file contributors")
    ap.add_argument("--debug", "-d", action="store_true", help="Debug output")
    ap.add_argument(
        "--delay",
        "-dl",
        type=int,
        help="Specify a delay in milliseconds to avoid 429 status codes default=500",
        default=500,
    )
    ap.add_argument("--dump", action="store_true", help="Print all of the loaded credentials")
    ap.add_argument("--dryrun", action="store_true", help="Print urls to be scan, but don't scan them")
    ap.add_argument(
        "--fingerprint", "-f", action="store_true", help="Fingerprint targets, but don't check creds", default=False
    )
    ap.add_argument("--fresh", action="store_true", help="Flush any previous scans and start fresh", default=False)
    ap.add_argument("--log", "-l", type=str, help="Write logs to logfile", default=None)
    ap.add_argument("--mkcred", action="store_true", help="Make cred file", default=False)
    ap.add_argument("--name", "-n", type=str, help="Narrow testing to the supplied credential name", default=None)
    ap.add_argument("--noversion", action="store_true", help="Don't perform a version check", default=False)
    ap.add_argument("--proxy", "-p", type=str, help="HTTP(S) Proxy", default=None)
    ap.add_argument(
        "--output",
        "-o",
        type=str,
        help="Name of result file. File extension determines type (csv, html, json).",
        default=None,
    )
    ap.add_argument(
        "--oa", action="store_true", help="Output results files in csv, html and json formats", default=False
    )
    ap.add_argument(
        "--protocols",
        type=str,
        help="Comma separated list of protocols to test.",
        default=",".join(all_protocols),
    )
    ap.add_argument(
        "--portoverride", action="store_true", help="Scan all protocols on all specified ports", default=False
    )
    ap.add_argument("--resume", "-r", action="store_true", help="Resume previous scan", default=False)
    ap.add_argument("--shodan_query", "-q", type=str, help="Shodan query", default=None)
    ap.add_argument("--shodan_key", "-k", type=str, help="Shodan API key", default=None)
    ap.add_argument(
        "--ssl",
        action="store_true",
        help="Force cred to SSL and fall back to non-SSL if an SSLError occurs",
        default=False,
    )
    ap.add_argument("--threads", "-t", type=int, help="Number of threads, default=10", default=10)
    ap.add_argument("--timeout", type=int, help="Timeout in seconds for a request, default=10", default=10)
    ap.add_argument("--useragent", "-ua", type=str, help="User agent string to use", default=None)
    ap.add_argument("--validate", action="store_true", help="Validate creds files", default=False)
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose output", default=False)

    # Hack to get the help to show up right
    cli = " ".join(sys.argv)
    if "-h" in cli or "--help" in cli:
        ap.add_argument(
            "target",
            type=str,
            help="Target to scan. Can be IP, subnet, hostname, nmap xml file, text file or proto://host:port",
            default=None,
        )

    # initial parse to see if an option not requiring a target was used
    args, unknown = ap.parse_known_args()
    if (
        not args.dump
        and not args.contributors
        and not args.mkcred
        and not args.resume
        and not args.shodan_query
        and not args.validate
    ):
        ap.add_argument(
            "target",
            type=str,
            help="Target to scan. Can be IP, subnet, hostname, nmap xml file, text file or proto://host:port",
            default=None,
        )

    args = ap.parse_args()

    return {"args": args, "parser": ap}


def get_protocol(filename: str) -> str:
    parts = filename.split(os.path.sep)
    cred_index = 0
    for p in parts:
        if p == "creds":
            break
        cred_index += 1

    return parts[cred_index + 1]


def load_creds(config: Config) -> List[Dict[str, Any]]:
    # protocol is based off of the directory and category is a field in the cred file. That way you can
    # have default creds across protocols for a single device like a printer
    logger = logging.getLogger("changeme")
    creds = list()
    total_creds = 0
    cred_names = list()
    cred_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "creds")
    logger.debug(f"cred_path: {cred_path}")
    protocols = [proto for proto in os.walk(cred_path)][0][1]
    for root, dirs, files in os.walk(cred_path):
        for fname in files:
            f = os.path.join(root, fname)
            protocol = get_protocol(f)
            if is_yaml(f):
                parsed = parse_yaml(f)
                if parsed:
                    if parsed["name"] in cred_names:
                        pass
                    elif validate_cred(parsed, f, protocol):
                        parsed["protocol"] = protocol  # Add the protocol after the schema validation
                        if in_scope(config.name, config.category, parsed, protocols):
                            total_creds += len(parsed["auth"]["credentials"])
                            creds.append(parsed)
                            cred_names.append(parsed["name"])
                            logger.debug(f"Loaded {parsed['name']}")

    logger.info(f"Loaded {len(creds)} default credential profiles")
    logger.info(f"Loaded {total_creds} default credentials\n")

    return creds


def validate_cred(cred: Dict[str, Any], f: str, protocol: str) -> bool:
    valid = True
    if protocol == "http":
        v = Validator()
        valid = v.validate(cred, schema.http_schema)  # type: ignore
        for e in v.errors:  # type: ignore
            logging.getLogger("changeme").error(f"[validate_cred] Validation Error: {f}, {e} - {v.errors[e]}")  # type: ignore
    # TODO: implement schema validators for other protocols

    return valid


def parse_yaml(f: str) -> Optional[Dict[str, Any]]:
    logger = logging.getLogger("changeme")
    with open(f, "r") as fin:
        raw = fin.read()
        try:
            parsed = yaml.safe_load(raw)
        except Exception as e:
            logger.error(f"[parse_yaml] {f} is not a valid yaml file")
            logger.debug(e)
            return None
    return parsed


def is_yaml(f: str) -> bool:
    isyaml = False
    try:
        isyaml = os.path.basename(f).split(".")[1] == "yml"
    except Exception:
        pass
    return isyaml


def in_scope(
    name: Optional[str],
    category: Optional[str],
    cred: Dict[str, Any],
    protocols: List[str],
) -> bool:
    add = True

    if name:
        names = name.split(",")
        found = False
        for n in names:
            if n.lower() in cred["name"].lower():
                found = True

        if found is False:
            add = False

    if category and not cred["category"] == category:
        add = False
    elif cred["protocol"] not in protocols:
        add = False

    return add


def print_contributors(creds: List[Dict[str, Any]]) -> None:
    contributors = set()
    for cred in creds:
        cred_contributors = cred["contributor"].split(", ")
        for c in cred_contributors:
            contributors.add(c)

    for c in version.contributors:
        contributors.add(c)

    print("Thank you to our contributors!")
    for i in sorted(contributors, key=str.lower):
        print(i)
    print()


def print_creds(creds: List[Dict[str, Any]]) -> None:
    for cred in creds:
        print(f"\n{cred['name']} ({cred['category']})")
        for i in cred["auth"]["credentials"]:
            print(f"  - {i['username']}:{i['password']}")


def check_for_interrupted_scan(config: Config) -> None:
    logger = logging.getLogger("changeme")
    if config.fresh:
        logger.debug("Forcing a fresh scan")
        remove_queues()
    elif config.resume:
        logger.debug("Resuming previous scan")
        return

    if os.path.exists(PERSISTENT_QUEUE):
        if not prompt_for_resume(config):
            remove_queues()


def prompt_for_resume(config: Config) -> bool:
    logger = logging.getLogger("changeme")
    logger.error("A previous scan was interrupted. Type R to resume or F to start a fresh scan")
    answer = ""
    while not (answer == "R" or answer == "F"):
        prompt = "(R/F)> "
        answer = ""
        try:
            answer = raw_input(prompt)  # type: ignore
        except NameError:
            answer = input(prompt)

        if answer.upper() == "F":
            logger.debug("Forcing a fresh scan")
        elif answer.upper() == "R":
            logger.debug("Resuming previous scan")
            config.resume = True

    return config.resume


def remove_queues() -> None:
    logger = logging.getLogger("changeme")
    try:
        os.remove(PERSISTENT_QUEUE)
        logger.debug(f"{PERSISTENT_QUEUE} removed")
    except OSError:
        logger.debug(f"{PERSISTENT_QUEUE} didn't exist")
        pass


def check_version() -> None:
    logger = logging.getLogger("changeme")

    try:
        res = requests.get("https://raw.githubusercontent.com/ztgrace/changeme/master/changeme/version.py", timeout=2)
    except ConnectionError:
        logger.debug("Unable to retrieve latest changeme version.")
        return

    latest = res.text.split("\n")[0].split(" = ")[1].replace("'", "")
    if not version.__version__ == latest:
        logger.warning(
            f"Your version of changeme is out of date. Local version: {version.__version__}, Latest: {latest}"
        )


# copied from https://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
def which(program: str) -> Optional[str]:
    import os

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None
