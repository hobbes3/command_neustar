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

LOG_ERROR_LOCATION = "/opt/splunk/var/log/splunk/neustar_error.log"
LOG_ROTATION_LOCATION = "/opt/splunk/var/log/splunk/neustar.log"
LOG_ROTATION_BYTES = 1 * 1024 * 1024
LOG_ROTATION_LIMIT = 10

THREADS = 16

logger = logging.getLogger("neustar")
logger.setLevel(logging.DEBUG)
handler = logging.handlers.RotatingFileHandler(LOG_ROTATION_LOCATION, maxBytes=LOG_ROTATION_BYTES, backupCount=LOG_ROTATION_LIMIT)
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s"))
logger.addHandler(handler)

pool = ThreadPoolExecutor(THREADS)

def neustar_lookup(input_field):
    params = URL_PARAMS.copy()
    output = {}

    if "@" in input_field:
        input_type = "email"
        params.update({
            "key572": input_field
        })
    else:
        input_type = "phone"
        params.update({
            "key1": input_field
        })

    try:
        start = time.time()
        r = requests.get(URL_BASE, params=params)
        output["neustar_ms"] = (time.time() - start)*1000

        r.raise_for_status()
        r_json = r.json()
        errorcode = r_json["errorcode"]

        logger.info("url: " + r.url)
        logger.debug("response: " + r.text)
        logger.debug("errorcode: " + errorcode)

        if errorcode == "0":
            # |1,5034426116,1,450^SE^5TH^AVE^^APT^2^HILLSBORO^OR^97123,1,lovemychildrendo2@yahoo.com,1,LAKEY^SHERRY|
            logger.debug("response count: " + str(len(r_json["response"])))
            values = r_json["response"][0]["result"][0]["value"].split(",")

            output["neustar_address"] = re.sub(r"\^", " ", values[3])
            output["neustar_email"] = values[5]
            output["neustar_name"] = re.sub(r"([^^]+)\^(.+)\|", r"\2 \1", values[7])
            output["neustar_json"] = r.text
            output["neustar_msg"] = "OK. Matched on " + input_type
        elif errorcode == "6":
            output["neustar_msg"] = "OK. No match."
            output["neustar_json"] = r.text
    except requests.exceptions.HTTPError as err:
        output["neustar_msg"] = err
        pass
    except requests.exceptions.RequestException as e:
        output["neustar_msg"] = e
        pass

    return output

@Configuration()
class NeustarCommand(StreamingCommand):
    input_field = Option(
        doc='''
        **Syntax:** **input_field=***string*
        **Description:** Destination of new message field ''',
        require=True,default="contact",)

    sort_mv = Option(
        doc='''
        **Syntax:** **sort_mv=***<boolean>*
        **Description:** sort and dedup mv fields''',
        require=False,default=True, validate=validators.Boolean())

    def stream(self, records):
        def thread(records):
            def update_fun(record):
                output = neustar_lookup(record["data"])
                record.update(output)
                return record

            chunk = []
            for record in records:
                # submit update_fun(record) into pool, keep resulting Future
                chunk.append(pool.submit(update_fun, record))
                if len(chunk) == THREADS:
                    yield chunk
                    chunk = []

            if chunk:
                yield chunk

        def unchunk(chunk_gen):
            """Flattens a generator of Future chunks into a generator of Future results."""
            for chunk in chunk_gen:
                for f in chunk:
                    yield f.result() # get result from Future

        for result in unchunk(thread(records)):
            yield result

        # Normal (non-threaded) method:
        #for record in records:
        #    output = neustar_lookup(record[self.input_field])

        #    record.update(output)
        #    yield record

dispatch(NeustarCommand, sys.argv, sys.stdin, sys.stdout, __name__)
