#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2011-2015 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, unicode_literals
import app
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

from concurrent.futures import ThreadPoolExecutor
import sys
import time
import json
import logging
import logging.handlers
import requests
import re

import neustar_creds

URL_BASE = "https://webgwy.targusinfo.com/access/query"
URL_PARAMS = {
    "username": neustar_creds.username,
    "password": neustar_creds.password,
    "svcid": 9212800562,
    "output": "json",
    "elems": 3345,
    "key206": "ADDR,PHONE,EMAIL,NAME",
}

LOG_ROTATION_LOCATION = "/opt/splunk/var/log/splunk/neustar_command.log"
LOG_ROTATION_BYTES = 1 * 1024 * 1024
LOG_ROTATION_LIMIT = 5

logger = logging.getLogger("neustar")
logger.setLevel(logging.DEBUG)
handler = logging.handlers.RotatingFileHandler(LOG_ROTATION_LOCATION, maxBytes=LOG_ROTATION_BYTES, backupCount=LOG_ROTATION_LIMIT)
handler.setFormatter(logging.Formatter("[%(levelname)s] (%(threadName)-10s) %(message)s"))
logger.addHandler(handler)

@Configuration()
class NeustarCommand(StreamingCommand):
    threads = Option(require=False, default=8, validate=validators.Integer())

    def stream(self, records):
        pool = ThreadPoolExecutor(self.threads)

        def neustar_query(record_dict):
            params = URL_PARAMS.copy()

            record = record_dict["record"]
            input_field = record_dict["field"]
            input_value = record[input_field].strip()

            logger.info("input_field: " + input_field)

            output_fields = {}
            output_fields[input_field + "_json"] = ""
            output_fields[input_field + "_time_ms"] = ""
            output_fields[input_field + "_msg"] = ""
            output_fields[input_field + "_name"] = ""
            output_fields[input_field + "_phone"] = ""
            output_fields[input_field + "_email"] = ""
            output_fields[input_field + "_address"] = ""

            if input_value:
                if "@" in input_value:
                    input_type = "email"
                    params.update({
                        "key572": input_value
                    })
                else:
                    input_type = "phone"
                    params.update({
                        "key1": input_value
                    })

                try:
                    start = time.time()
                    r = requests.get(URL_BASE, params=params)
                    output_fields[input_field + "_time_ms"] = (time.time() - start) * 1000

                    r.raise_for_status()
                    r_json = r.json()
                    errorcode = r_json["errorcode"]
                    output_fields[input_field + "_json"] = r.text

                    logger.info("url: " + r.url)

                    if errorcode == "0":
                        # |1,5034426116,1,450^SE^5TH^AVE^^APT^2^HILLSBORO^OR^97123,1,lovemychildrendo2@yahoo.com,1,LAKEY^SHERRY|
                        values = r_json["response"][0]["result"][0]["value"].split(",")

                        output_fields[input_field + "_address"] = re.sub(r"\^", " ", values[3])
                        output_fields[input_field + "_email"] = values[5]
                        output_fields[input_field + "_name"] = re.sub(r"([^^]+)\^(.+)\|", r"\2 \1", values[7])
                        output_fields[input_field + "_msg"] = "Matched on " + input_type + "."
                    elif errorcode == "6":
                        output_fields[input_field + "_msg"] = "Error code 6. No match."
                    else:
                        output_fields[input_field + "_msg"] = "Error code " + errorcode + "."

                except requests.exceptions.HTTPError as err:
                    output_fields[input_field + "_msg"] = err
                    pass
                except requests.exceptions.RequestException as e:
                    output_fields[input_field + "_msg"] = e
                    pass

            record.update(output_fields)
            logger.info("new record:")
            logger.debug(record)

            return record

        def thread(records):
            chunk = []
            for record in records:
                for field in self.fieldnames:
                    chunk.append(pool.submit(neustar_query, {"record": record, "field": field}))

                if len(chunk) == self.threads:
                    yield chunk
                    chunk = []

            if chunk:
                yield chunk

        def unchunk(chunk_gen):
            """Flattens a generator of Future chunks into a generator of Future results."""
            for chunk in chunk_gen:
                for f in chunk:
                    yield f.result() # get result from Future

        # Now iterate over all results in same order as records
        for i, result in enumerate(unchunk(thread(records))):
            if (i + 1) % len(self.fieldnames) == 0:
                yield result

        logger.debug("DONE\n\n\n")

dispatch(NeustarCommand, sys.argv, sys.stdin, sys.stdout, __name__)
