# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import re
import urlparse
from minion.plugins.base import ExternalProcessPlugin

import references

DEV = True
#DEV = False

class NIKTOPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "NIKTO"
    PLUGIN_VERSION = "0.2"
    PLUGIN_WEIGHT = "heavy"

    NIKTO_NAME = "nikto"
    ARGS = ""

    def _parse_output(self, output):
        issues = []
        vulns = {}
        
        #gather issues
        for line in output.split("\n"):
            match = re.match('^\+ OSVDB-(\d+): (.*?): (.*)$', line)
            if match is not None:
                name = "OSVDB-%s" % (match.group(1))
                url = '%s%s' % (self.configuration['target'], match.group(2))
                logging.debug("parsing: %s\t%s" % (name, url))

                if name in vulns:
                    vulns[name]['URLs'].append({'URL': url, 'Extra': match.group(3)})
                else:
                    vulns[name] = {}
                    vulns[name]['URLs'] = [{'URL': url, 'Extra': match.group(3)}]
                    vulns[name]['Severity'] = 'Low'
                    vulns[name]['Summary'] = "%s" % (match.group(3))
                    vulns[name]['FurtherInfo'] = [{
                                    'URL': "http://osvdb.org/%s" % (match.group(1)),
                                    'Title':"OSVDB-%s" % (match.group(1)) }]

                continue

            match = re.match('^\+ (.*?) appears to be outdated (.*)$', line)
            if match is not None:
                name = "Outdated software"
                extra = '%s appears to be outdated %s' % (match.group(1), match.group(2))
                logging.debug("parsing: %s\t%s" % (name, extra))

                if name in vulns:
                    vulns[name]['Description'] += "<br>%s" % (extra)
                else:
                    vulns[name] = {}
                    vulns[name]['Severity'] = 'Medium'
                    vulns[name]['Summary'] = "Software appears to be outdated"
                    vulns[name]['Description'] = "<br>%s" % (extra)

                continue

            match = re.match('^\+ (/.*?): (.*)$', line)
            if match is not None:
                name = "%s" % (match.group(2))
                url = '%s%s' % (self.configuration['target'], match.group(1))
                logging.debug("parsing: %s\t%s" % (name, url))

                if name in vulns:
                    vulns[name]['URLs'].append({'URL': url})
                else:
                    vulns[name] = {}
                    vulns[name]['URLs'] = [{'URL': url}]
                    vulns[name]['Severity'] = 'Low'
                    vulns[name]['Summary'] = "%s" % (match.group(2))
                    vulns[name]['FurtherInfo'] = []

                continue

            logging.info("no match: %s" % (line))

        for vuln in vulns:
            issues.append(vulns[vuln])

        return issues

    def do_start(self):
        nikto_path = self.locate_program(self.NIKTO_NAME)
        if nikto_path is None:
            raise Exception("Cannot find nikto in path")
        self.nikto_stdout = ""
        self.nikto_stderr = ""

        logdir = "reports"
        logging.debug(os.getcwd())
        os.mkdir(logdir)

        u = urlparse.urlparse(self.configuration['target'])
        args = []
        args += ["-C", "all"]
        args += ["-nointeractive"]
        #args += ["-Format", "xml"]
        #args += ["-Format", "csv"]
        args += ["-Format", "txt"]
        args += ["-output", "./%s/nikto_%s_80.txt" % (logdir, u.hostname)]   #ERROR: Unable to open '.' for write
        args += ["-port", "80"]
        args += ["-config", "/etc/nikto/config.txt"]
        args += ["-host", u.hostname]

        if DEV:
            args += ["-H", u.hostname]

        self.spawn(nikto_path, args)

    def do_process_stdout(self, data):
        self.nikto_stdout += data

    def do_process_stderr(self, data):
        self.nikto_stderr += data

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            with open("nikto.stdout.txt", "w") as f:
                f.write(self.nikto_stdout)
            with open("nikto.stderr.txt", "w") as f:
                f.write(self.nikto_stderr)
            self.report_artifacts("NIKTO Output", ["nikto.stdout.txt", "nikto.stderr.txt"])
            #services = parse_nikto_output(self.nikto_stdout)
            #issues = services_to_issues(services)
            issues = [{'Summary': "TEST",
                'Description': self.nikto_stdout + self.ARGS,
                'Severity': "Info",
                "URLs": [ {"URL": None, "Extra": None} ],
                "FurtherInfo": None}]

            if DEV:
                with open('/tmp/94decce9-b6f1-4b33-98a2-19f21c9bc867/nikto.stdout.txt','r') as f:
                    output = f.readlines()
                    issues = self._parse_output("".join(output))
            else:
                issues = self._parse_output(self.nikto_stdout)

            self.report_issues(issues)
            self.report_finish()
        else:
            self.report_finish("FAILED")

