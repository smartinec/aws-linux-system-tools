#!/usr/bin/env python
#
# AWS CloudWatch Linux Metrics
# Copyright 2014 Birdback Ltd. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import traceback

from os import environ, statvfs
from sys import stderr, version
from json import loads
from hmac import new as hmac
from datetime import datetime
from hashlib import sha256
from binascii import hexlify

try:
    from httplib import HTTPConnection, HTTPSConnection
except ImportError:
    from http.client import HTTPConnection, HTTPSConnection

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode


aws_metadata_host = "169.254.169.254"
canonical_date_format = "%Y%m%d"
canonical_time_format = "%Y%m%dT%H%M%SZ"
encoding = "utf-8"
method = "POST"
path = "/"
service = "monitoring"
auth_type = "aws4_request"
now = datetime.utcnow()
namespace = "System/Linux"
metric_name_regex = re.compile(r'(?:^|_)([a-z])')
meminfo_regex = re.compile(r'([A-Z][A-Za-z()_]+):\s+(\d+)(?: ([km]B))')


if version[0] == '3':
    def bytes(s, str=str):
        if isinstance(s, str):
            s = s.encode(encoding)
        return s

    def str(s):
        return s.decode(encoding)


def cached(f):
    cache = {}

    def decorator(*args, **kwargs):
        key = args, tuple(sorted(kwargs.items()))
        try:
            return cache[key]
        except KeyError:
            return cache.setdefault(key, f(*args))

    return decorator


def log(message, stream=stderr):
    return stream.write("Error: " + message.__str__() + '\n')


def pick(iterable, g, *args):
    vs = list(args)
    for i, arg in enumerate(args):
        for item in iterable:
            v = g(item, arg)
            if v is not None:
                vs[i] = v
                break

    return vs


def get_canonical(body, headers):
    digest = get_digest(body)
    items = [method, path, ""]

    names = []
    for name, value in sorted(headers.items()):
        name = name.lower()
        items.append("%s:%s" % (name, value))
        names.append(name)

    signed_headers = ";".join(names)

    items.append("")
    items.append(signed_headers)
    items.append(digest)

    return "\n".join(items), signed_headers


def get_digest(string):
    return sha256(bytes(string)).hexdigest().__str__()


def get_string_to_sign(canonical):
    digest = get_digest(canonical)
    return "\n".join((
        "AWS4-HMAC-SHA256",
        now.strftime(canonical_time_format),
        "/".join((
            now.strftime(canonical_date_format),
            region,
            service,
            auth_type,
        )),
        digest,
    ))


def get_signature(*args):
    s = bytes("AWS4" + secret_key)
    for arg in args:
        s = hmac(s, bytes(arg), digestmod=sha256).digest()
    return str(hexlify(s))


def make_request(conn, body):
    headers = {
        "Content-type": "application/x-www-form-urlencoded; charset=%s" % (
            encoding,
        ),
        "Host": host,
        "X-amz-date": now.strftime(canonical_time_format),
    }

    if security_token is not None:
        headers["X-amz-security-token"] = security_token

    canonical, signed_headers = get_canonical(body, headers)

    signature = get_signature(
        now.strftime(canonical_date_format),
        region,
        service,
        auth_type,
        get_string_to_sign(canonical),
    )

    headers.update({
        "Authorization": "AWS4-HMAC-SHA256 " + ", ".join((
            "Credential=%s" % "/".join((
                access_key,
                now.strftime(canonical_date_format),
                region,
                service,
                auth_type,
            )),
            "SignedHeaders=%s" % signed_headers,
            "Signature=%s" % signature,
        )),
    })

    try:
        conn.request(method, path, body, headers)
        r = conn.getresponse()
    except IOError:
        log("Error making request.")
        raise

    return get_response_body(r)


def get_response_body(r):
    body = str(r.read())

    if r.status != 200:
        log("Got status %d: %s." % (r.status, r.reason))
        raise ValueError(body)

    return body


@cached
def request_metadata(path, converter=None):
    try:
        conn = HTTPConnection(aws_metadata_host, timeout=1)
        conn.request('GET', "/latest/meta-data/%s" % path)
        r = conn.getresponse()
    except IOError:
        log("Unable to request metadata: %s." % path)
        raise

    body = get_response_body(r)
    if converter is not None:
        return converter(body)

    return body


def request_access_key():
    return request_security_credential('AccessKeyId')


def request_secret_key():
    try:
        return request_security_credential('SecretAccessKey')
    finally:
        global security_token
        security_token = request_security_credential('Token')


def request_security_credential(key):
    for name in request_metadata('iam/security-credentials/').split('\n'):
        return request_metadata(
            'iam/security-credentials/%s' % name,
            loads
        )[key]


def request_instance_id():
    return request_metadata('instance-id')


def request_region():
    return request_metadata('placement/availability-zone')[:-1]


def get_proxy(name):
    value = environ.get(name) or environ.get(name.upper())
    if value is None:
        return

    value = value.split('//', 1)[1]
    if ':' in value:
        return value.split(':', 1)

    return value, 443 if name[-1] == 's' else 80


def get_secure_connection(host, **options):
    try:
        http_proxy = get_proxy('http_proxy')
        if http_proxy:
            conn = HTTPConnection(*http_proxy, **options)
            conn.set_tunnel(host, 443)
        else:
            https_proxy = get_proxy('https_proxy')
            if https_proxy:
                conn = HTTPSConnection(*https_proxy, **options)
                conn.set_tunnel(host, 443)
            else:
                conn = HTTPSConnection(host, timeout=5)
    except IOError:
        log("Unable to connect to https://%s." % host)
        raise

    return conn


def submit_metrics(data):
    conn = get_secure_connection(host, timeout=5)

    query = {
        "Action": "PutMetricData",
        "Version": "2010-08-01",
        "Namespace": namespace,
    }

    i = 0
    for name, (value, unit, dimensions) in data:
        i += 1
        prefix = 'MetricData.member.%d.' % i
        query[prefix + 'MetricName'] = name
        query[prefix + 'Unit'] = unit
        query[prefix + 'Value'] = value
        query[prefix + 'Dimensions.member.1.Name'] = 'InstanceId'
        query[prefix + 'Dimensions.member.1.Value'] = instance_id

        for j, (name, value) in enumerate(dimensions):
            dimension = prefix + 'Dimensions.member.%d.' % (j + 2)
            query[dimension + 'Name'] = name
            query[dimension + 'Value'] = value

    body = urlencode(query)
    return make_request(conn, body)


def collect_metrics():
    data = []

    def collect(f):
        name = metric_name_regex.sub(lambda s: s.group(1).upper(), f.__name__)
        for value in f():
            data.append((name, value))

    @collect
    def memory_utilization():
        with open('/proc/meminfo') as f:
            def match(line, item):
                name, amount, unit = meminfo_regex.match(line).groups()
                if name == item:
                    assert unit == 'kB'
                    return int(amount)

            memtotal, memfree, buffers, cached = pick(
                f, match, 'MemTotal', 'MemFree', 'Buffers', 'Cached'
            )

            inactive = (memfree + buffers + cached) / float(memtotal)
            yield round(100 * (1 - inactive), 1), "Percent", []

    @collect
    def disk_space_utilization():
        with open('/proc/mounts') as f:
            for line in f:
                if not line.startswith('/'):
                    continue

                device, path, filesystem, options = line.split(' ', 3)
                result = statvfs(path)

                free = result.f_bfree / float(result.f_blocks)
                yield round(100 * (1 - free), 1), "Percent", [
                    ("Filesystem", filesystem),
                    ("MountPath", path)
                ]

    @collect
    def load_average():
        with open('/proc/loadavg') as f:
            line = f.read()
            load = float(line.split(' ', 1)[0])
            yield round(100 * load, 1), "Percent", []

    @collect
    def network_connections():
        with open('/proc/net/tcp') as f:
            for i, line in enumerate(f):
                pass

        yield i, "Count", [("Protocol", "TCP")]

        with open('/proc/net/udp') as f:
            for i, line in enumerate(f):
                pass

        yield i, "Count", [("Protocol", "UDP")]

    return data


try:
    security_token = None
    access_key = environ.get('AWS_ACCESS_KEY_ID') or request_access_key()
    secret_key = environ.get('AWS_SECRET_ACCESS_KEY') or request_secret_key()
    instance_id = environ.get('AWS_INSTANCE_ID') or request_instance_id()
    region = environ.get('AWS_REGION') or request_region()
    host = "%s.%s.amazonaws.com" % (service, region)

    data = collect_metrics()
    submit_metrics(data)
except BaseException:
    log(traceback.format_exc())
    raise SystemExit(1)
