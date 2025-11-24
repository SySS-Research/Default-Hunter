import csv
from copy import deepcopy
import dataclasses
from datetime import datetime
import jinja2
import json
import logging
import os
import re
import sys
from tabulate import tabulate
from typing import Optional, List, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from changeme.redis_queue import OurQueue


class DataclassJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)


class Report:
    def __init__(self, queue: "OurQueue", output: Optional[str]) -> None:
        self.results: List[Dict[str, Any]] = self._convert_q2list(queue)
        self.output: Optional[str] = output
        self.logger: logging.Logger = logging.getLogger("changeme")

    def render_csv(
        self,
    ) -> None:
        fname = self.output if self.output else "results.csv"
        if not re.match(r".*\.csv$", fname):
            fname += ".csv"

        with open(fname, "w") as fout:
            fieldnames = ["name", "username", "password", "target"]
            writer = csv.DictWriter(fout, quoting=csv.QUOTE_ALL, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows([r.as_dict() for r in self.results])

        self.logger.critical(f"{len(self.results)} credentials written to {fname}")

    def render_json(self) -> None:
        # convert the Target classes to a string so it can be json'd
        res = deepcopy(self.results)
        for r in res:
            t = r.target
            r.target = str(t)

        results = dict()
        results["results"] = res
        j = json.dumps(results, cls=DataclassJSONEncoder)
        fname = self.output if self.output else "results.json"
        if not re.match(r".*\.json$", fname):
            fname += ".json"

        with open(fname, "w") as fout:
            fout.write(j)

        self.logger.critical(f"{len(self.results)} credentials written to {fname}")

    def print_results(self) -> None:
        if len(self.results) > 0:
            results = deepcopy(self.results)
            for r in results:
                if "http" in r.target.protocol:
                    r.evidence = ""

            print("")
            print("")
            self.logger.critical(f"Found {len(self.results)} default credentials")
            print("")
            print(
                tabulate(
                    results,
                    headers={
                        "name": "Name",
                        "username": "Username",
                        "password": "Password",
                        "target": "Target",
                        "evidence": "Evidence",
                    },
                )
            )

            print("")
        else:
            print("No default credentials found")

    def render_html(self) -> None:
        template_loader = jinja2.FileSystemLoader(searchpath=self.get_template_path())
        template_env = jinja2.Environment(loader=template_loader)
        report_template = template_env.get_template("report.j2")
        cli = " ".join(sys.argv)
        timestamp = datetime.now()
        report = report_template.render({"found": self.results, "cli": cli, "timestamp": timestamp})

        fname = self.output if self.output else "report.html"
        if not re.match(r".*\.html$", fname):
            fname += ".html"

        with open(fname, "w") as fout:
            fout.write(report)

        self.logger.critical(f"{len(self.results)} credentials written to {fname}")

    @staticmethod
    def get_template_path() -> str:
        PATH = os.path.dirname(os.path.abspath(__file__))
        template_path = os.path.join(PATH, "templates")
        return template_path

    def _convert_q2list(self, q: "OurQueue") -> List[Dict[str, Any]]:
        items = list()
        while not q.qsize() == 0:
            i = q.get()
            items.append(i)

        # Restore queue
        for i in items:
            q.put(i)

        return items
