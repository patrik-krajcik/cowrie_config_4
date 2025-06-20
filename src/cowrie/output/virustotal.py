# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

"""
Send SSH logins to Virustotal
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any
from urllib.parse import urlencode, urlparse

from zope.interface import implementer

from twisted.internet import defer
from twisted.internet import reactor
from twisted.python import log
from twisted.web import client, http_headers
from twisted.web.iweb import IBodyProducer

import cowrie.core.output
from cowrie.core.config import CowrieConfig

COWRIE_USER_AGENT = "Cowrie Honeypot"
VTAPI_URL = "https://www.virustotal.com/vtapi/v2/"
COMMENT = "First seen by #Cowrie SSH/telnet Honeypot http://github.com/cowrie/cowrie"
TIME_SINCE_FIRST_DOWNLOAD = datetime.timedelta(minutes=1)


class Output(cowrie.core.output.Output):
    """
    virustotal output
    """

    apiKey: str
    debug: bool = False
    commenttext: str
    agent: Any
    scan_url: bool
    scan_file: bool
    url_cache: dict[str, datetime.datetime]  # url and last time succesfully submitted

    def start(self) -> None:
        """
        Start output plugin
        """
        self.url_cache = {}

        self.apiKey = CowrieConfig.get("output_virustotal", "api_key")
        self.debug = CowrieConfig.getboolean(
            "output_virustotal", "debug", fallback=False
        )
        self.upload = CowrieConfig.getboolean(
            "output_virustotal", "upload", fallback=True
        )
        self.comment = CowrieConfig.getboolean(
            "output_virustotal", "comment", fallback=True
        )
        self.scan_file = CowrieConfig.getboolean(
            "output_virustotal", "scan_file", fallback=True
        )
        self.scan_url = CowrieConfig.getboolean(
            "output_virustotal", "scan_url", fallback=False
        )
        self.commenttext = CowrieConfig.get(
            "output_virustotal", "commenttext", fallback=COMMENT
        )
        self.agent = client.Agent(reactor)

        fn = CowrieConfig.get("output_jsonlog", "logfile", fallback="cowrie.json")
        dirs = os.path.dirname(fn)
        base = os.path.basename(fn)

        # Create VirusTotal-specific filename while keeping original variables unchanged
        vt_base = base.replace('.json', '.json.virustotal') if '.json' in base else f"{base}.json.virustotal"
        self.vt_outfile = cowrie.python.logfile.CowrieDailyLogFile(
            vt_base,  # Uses the modified filename
            dirs,     # Same directory as main log
            defaultMode=0o664
        )

    def stop(self) -> None:
        """
        Stop output plugin
        """

    def write(self, event: dict[str, Any]) -> None:
        if event["eventid"] == "cowrie.session.file_download":
            if self.scan_url and "url" in event:
                log.msg("Checking url scan report at VT")
                self.scanurl(event)
            if self._is_new_shasum(event["shasum"], event) and self.scan_file:
            #if True : 
                log.msg("Checking file scan report at VT")
                self.scanfile(event)

        elif event["eventid"] == "cowrie.session.file_upload":
            if self._is_new_shasum(event["shasum"], event) and self.scan_file:
                log.msg("Checking file scan report at VT")
                self.scanfile(event)

    def _is_new_shasum(self, shasum: str, event) -> bool:
        """
        Recursively checks if a file with the given shasum exists in the
        filesystems directory and whether it's new enough to be scanned again.
        """
        base_path = os.path.join(CowrieConfig.get("honeypot", "state_path"))

        for root, dirs, files in os.walk(base_path):
            if shasum in files:
                full_path = os.path.join(root, shasum)
                try:
                    file_mod_time = datetime.datetime.fromtimestamp(os.stat(full_path).st_mtime)
                    if file_mod_time < datetime.datetime.now() - TIME_SINCE_FIRST_DOWNLOAD:
                        log.msg(f"File with shasum '{shasum}' found at '{full_path}' and is older than threshold")
                        
                        vt_event = {
                            "eventid": "cowrie.virustotal.scanfile",
                            "message": f"VT: File {shasum} already scanned previously (older than threshold)",
                            "session": event["session"],
                            "sha256": shasum,
                            "is_new": "false"
                        }

                        self.write_to_json(vt_event)
                        return False
                    else:
                        log.msg(f"File with shasum '{shasum}' found at '{full_path}' and is new enough")
                        return True
                except Exception as e:
                    log.err(f"Error checking file time for {full_path}: {e}")
                    return False

        # If the file wasn't found at all, we assume it's new and should be scanned
        log.msg(f"File with shasum '{shasum}' not found in any subdirectory of {base_path}")
        return True
    

    def scanfile(self, event):
        """
        Check file scan report for a hash
        Argument is full event so we can access full file later on
        """
        vtUrl = f"{VTAPI_URL}file/report".encode()
        headers = http_headers.Headers({"User-Agent": [COWRIE_USER_AGENT]})

        fields = {"apikey": self.apiKey, "resource": event["shasum"], "allinfo": 1}
        body = StringProducer(urlencode(fields).encode("utf-8"))
        d = self.agent.request(b"POST", vtUrl, headers, body)

        def cbResponse(response):
            """
            Main response callback, check HTTP response code
            """
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                return d
            else:
                log.msg(f"VT scanfile failed: {response.code} {response.phrase}")

        def cbBody(body):
            """
            Received body
            """
            return processResult(body)

        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)

        def cbError(failure):
            log.msg("VT: Error in scanfile")
            failure.printTraceback()

        def processResult(result):
            """
            Extract the information we need from the body
            """
            if self.debug:
                log.msg(f"VT scanfile result: {result}")
            result = result.decode("utf8")
            j = json.loads(result)
            log.msg("VT: {}".format(j["verbose_msg"]))
            if j["response_code"] == 0:
                log.msg(
                    eventid="cowrie.virustotal.scanfile",
                    format="VT: New file %(sha256)s",
                    session=event["session"],
                    sha256=j["resource"],
                    is_new="true",
                )

                vt_event = {
                    "eventid": "cowrie.virustotal.scanfile",
                    "session": event["session"],
                    "sha256": j["resource"],
                    "is_new": "true",
                    "message": f"VT: New file {j['resource']}"
                }

                self.write_to_json(vt_event)

                try:
                    b = os.path.basename(urlparse(event["url"]).path)
                    if b == "":
                        fileName = event["shasum"]
                    else:
                        fileName = b
                except KeyError:
                    fileName = event["shasum"]

                if self.upload is True:
                    return self.postfile(event["outfile"], fileName)
                else:
                    return
            elif j["response_code"] == 1:
                log.msg("VT: response=1: this has been scanned before")
                # Add detailed report to json log
                scans_summary: dict[str, dict[str, str]] = {}
                for feed, info in j["scans"].items():
                    feed_key = feed.lower()
                    scans_summary[feed_key] = {}
                    scans_summary[feed_key]["detected"] = str(info["detected"]).lower()
                    scans_summary[feed_key]["result"] = str(info["result"]).lower()
                log.msg(
                    eventid="cowrie.virustotal.scanfile",
                    format="VT: Binary file with sha256 %(sha256)s was found malicious "
                    "by %(positives)s out of %(total)s feeds (scanned on %(scan_date)s)",
                    session=event["session"],
                    positives=j["positives"],
                    total=j["total"],
                    scan_date=j["scan_date"],
                    sha256=j["resource"],
                    scans=scans_summary,
                    is_new="false",
                )
                vt_event = {
                    "eventid": "cowrie.virustotal.scanfile",
                    "session": event["session"],
                    "positives": j["positives"],
                    "total": j["total"],
                    "scan_date": j["scan_date"],
                    "sha256": j["resource"],
                    "scans": scans_summary,
                    "is_new": "false",
                    "message": "VT: Binary file with sha256 {} was found malicious by {} out of {} feeds (scanned on {})".format(
                        j["resource"], j["positives"], j["total"], j["scan_date"]
                    )
                }
                self.write_to_json(vt_event)

                log.msg("VT: permalink: {}".format(j["permalink"]))
            elif j["response_code"] == -2:
                log.msg("VT: response=-2: this has been queued for analysis already")
            else:
                log.msg("VT: unexpected response code: {}".format(j["response_code"]))

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d

    def postfile(self, artifact, fileName):
        """
        Send a file to VirusTotal
        """
        vtUrl = f"{VTAPI_URL}file/scan".encode()
        fields = {("apikey", self.apiKey)}
        files = {("file", fileName, open(artifact, "rb"))}
        if self.debug:
            log.msg(f"submitting to VT: {files!r}")
        contentType, body = encode_multipart_formdata(fields, files)
        producer = StringProducer(body)
        headers = http_headers.Headers(
            {
                "User-Agent": [COWRIE_USER_AGENT],
                "Accept": ["*/*"],
                "Content-Type": [contentType],
            }
        )

        d = self.agent.request(b"POST", vtUrl, headers, producer)

        def cbBody(body):
            return processResult(body)

        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)

        def cbResponse(response):
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                d.addErrback(cbPartial)
                return d
            else:
                log.msg(f"VT postfile failed: {response.code} {response.phrase}")

        def cbError(failure):
            failure.printTraceback()

        def processResult(result):
            if self.debug:
                log.msg(f"VT postfile result: {result}")
            result = result.decode("utf8")
            j = json.loads(result)
            # This is always a new resource, since we did the scan before
            # so always create the comment
            log.msg("response=0: posting comment")
            if self.comment is True:
                return self.postcomment(j["resource"])
            else:
                return

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d

    def scanurl(self, event):
        """
        Check url scan report for a hash
        """
        if event["url"] in self.url_cache:
            log.msg(
                "output_virustotal: url {} was already successfully submitted".format(
                    event["url"]
                )
            )
            return

        vtUrl = f"{VTAPI_URL}url/report".encode()
        headers = http_headers.Headers({"User-Agent": [COWRIE_USER_AGENT]})
        fields = {
            "apikey": self.apiKey,
            "resource": event["url"],
            "scan": 1,
            "allinfo": 1,
        }
        body = StringProducer(urlencode(fields).encode("utf-8"))
        d = self.agent.request(b"POST", vtUrl, headers, body)

        def cbResponse(response):
            """
            Main response callback, checks HTTP response code
            """
            if response.code == 200:
                log.msg(f"VT scanurl successful: {response.code} {response.phrase}")
                d = client.readBody(response)
                d.addCallback(cbBody)
                return d
            else:
                log.msg(f"VT scanurl failed: {response.code} {response.phrase}")

        def cbBody(body):
            """
            Received body
            """
            return processResult(body)

        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)

        def cbError(failure):
            log.msg("cbError")
            failure.printTraceback()

        def processResult(result):
            """
            Extract the information we need from the body
            """
            if self.debug:
                log.msg(f"VT scanurl result: {result}")
            if result == b"[]\n":
                log.err(f"VT scanurl did not return results: {result}")
                return
            result = result.decode("utf8")
            j = json.loads(result)

            # we got a status=200 assume it was successfully submitted
            self.url_cache[event["url"]] = datetime.datetime.now()

            if j["response_code"] == 0:
                log.msg(
                    eventid="cowrie.virustotal.scanurl",
                    format="VT: New URL %(url)s",
                    session=event["session"],
                    url=event["url"],
                    is_new="true",
                )

                vt_event = {
                    "eventid": "cowrie.virustotal.scanurl",
                    "session": event["session"],
                    "url": event["url"],
                    "is_new": "true",
                    "message": f"VT: New URL {event['url']}"

                }
                self.write_to_json(vt_event)

                return d
            elif j["response_code"] == 1 and "scans" not in j:
                log.msg(
                    "VT: response=1: this was submitted before but has not yet been scanned."
                )
            elif j["response_code"] == 1 and "scans" in j:
                log.msg("VT: response=1: this has been scanned before")
                # Add detailed report to json log
                scans_summary: dict[str, dict[str, str]] = {}
                for feed, info in j["scans"].items():
                    feed_key = feed.lower()
                    scans_summary[feed_key] = {}
                    scans_summary[feed_key]["detected"] = str(info["detected"]).lower()
                    scans_summary[feed_key]["result"] = str(info["result"]).lower()
                log.msg(
                    eventid="cowrie.virustotal.scanurl",
                    format="VT: URL %(url)s was found malicious by "
                    "%(positives)s out of %(total)s feeds (scanned on %(scan_date)s)",
                    session=event["session"],
                    positives=j["positives"],
                    total=j["total"],
                    scan_date=j["scan_date"],
                    url=j["url"],
                    scans=scans_summary,
                    is_new="false",
                )
                
                vt_event = {
                    "eventid": "cowrie.virustotal.scanurl",
                    "session": event["session"],
                    "positives": j["positives"],
                    "total": j["total"],
                    "scan_date": j["scan_date"],
                    "url": j["url"],
                    "scans": scans_summary,
                    "is_new": "false",
                    "message": f"VT: URL {j['url']} was found malicious by {j['positives']} out of {j['total']} feeds (scanned on {j['scan_date']})"
                }
                self.write_to_json(vt_event)

                log.msg("VT: permalink: {}".format(j["permalink"]))
            elif j["response_code"] == -2:
                log.msg("VT: response=-2: this has been queued for analysis already")
                log.msg("VT: permalink: {}".format(j["permalink"]))
            else:
                log.msg("VT: unexpected response code: {}".format(j["response_code"]))

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d

    def postcomment(self, resource):
        """
        Send a comment to VirusTotal with Twisted
        """
        vtUrl = f"{VTAPI_URL}comments/put".encode()
        parameters = {
            "resource": resource,
            "comment": self.commenttext,
            "apikey": self.apiKey,
        }
        headers = http_headers.Headers({"User-Agent": [COWRIE_USER_AGENT]})
        body = StringProducer(urlencode(parameters).encode("utf-8"))
        d = self.agent.request(b"POST", vtUrl, headers, body)

        def cbBody(body):
            return processResult(body)

        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)

        def cbResponse(response):
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                d.addErrback(cbPartial)
                return d
            else:
                log.msg(f"VT postcomment failed: {response.code} {response.phrase}")

        def cbError(failure):
            failure.printTraceback()

        def processResult(result):
            if self.debug:
                log.msg(f"VT postcomment result: {result}")
            result = result.decode("utf8")
            j = json.loads(result)
            return j["response_code"]

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d
    

    def write_to_json(self, event):
            """Custom JSON writer that handles both regular and VT events"""
            try:
                # Clean the event dictionary
                clean_event = {
                    k: v for k, v in event.items()
                    if not k.startswith("log_") and k not in ["time", "system"]
                }
                
                # Write to file
                json.dump(clean_event, self.vt_outfile, separators=(",", ":"))
                self.vt_outfile.write("\n")
                self.vt_outfile.flush()
            except (TypeError, KeyError) as e:
                log.err(f"jsonlog: Error writing event: {e}\nEvent: {repr(event)}")



@implementer(IBodyProducer)
class StringProducer:
    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def resumeProducing(self):
        pass

    def stopProducing(self):
        pass


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTPS instance
    """
    BOUNDARY = b"----------ThIs_Is_tHe_bouNdaRY_$"
    L = []
    for key, value in fields:
        L.append(b"--" + BOUNDARY)
        L.append(b'Content-Disposition: form-data; name="%s"' % key.encode())
        L.append(b"")
        L.append(value.encode())
    for key, filename, value in files:
        L.append(b"--" + BOUNDARY)
        L.append(
            b'Content-Disposition: form-data; name="%s"; filename="%s"'
            % (key.encode(), filename.encode())
        )
        L.append(b"Content-Type: application/octet-stream")
        L.append(b"")
        L.append(value.read())
    L.append(b"--" + BOUNDARY + b"--")
    L.append(b"")
    body = b"\r\n".join(L)
    content_type = b"multipart/form-data; boundary=%s" % BOUNDARY

    return content_type, body