#!/usr/bin/env python
#
# AWS Linux System Tools
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

import os
import re
import argparse
import platform
import traceback

from operator import sub
from sys import stderr, version
from time import time
from json import loads
from hmac import new as hmac
from datetime import datetime
from hashlib import sha256
from binascii import hexlify
from xml.etree import ElementTree

try:
    from httplib import HTTPConnection, HTTPSConnection
except ImportError:
    from http.client import HTTPConnection, HTTPSConnection

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode


user_agent = 'aws-system-tools/1.0 Python/%s %s/%s' % (
    platform.python_version(),
    platform.system(),
    platform.release()
)

aws_metadata_host = "169.254.169.254"
canonical_date_format = "%Y%m%d"
canonical_time_format = "%Y%m%dT%H%M%SZ"
encoding = "UTF-8"
method = "POST"
path = "/"
auth_type = "aws4_request"
now = datetime.utcnow()
camelcase_regex = re.compile(r'(?:^|_)([a-z])')
meminfo_regex = re.compile(r'([A-Z][A-Za-z()_]+):\s+(\d+)(?: ([km]B))')
snapshot_regex = re.compile(r'<snapshotId>(snap-[0-9a-f]+)</snapshotId>')
volumes_regex = re.compile(
    r'<volumeId>(vol-[0-9a-f]+)</volumeId>\s*'
    r'<instanceId>(i-[0-9a-f]+)</instanceId>\s*'
    r'<device>((?:/[a-z]\w+)+)</device>\s*'
    r'<status>attached</status>'
)

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


def log(message, status="error", stream=stderr):
    return stream.write(
        "%s: %s\n" % (status.capitalize(), message.__str__())
    )


def pick(iterable, g, *args):
    vs = list(args)
    for i, arg in enumerate(args):
        for item in iterable:
            v = g(item, arg)
            if v is not None:
                vs[i] = v
                break

    return vs


def camelcase(name):
    return camelcase_regex.sub(lambda s: s.group(1).upper(), name)


def get_canonical(body, headers):
    items = [method, path, ""]

    names = []
    canonical_headers = []
    for name, value in sorted(headers.items()):
        name = name.lower().strip()
        if name.startswith('x-amz') or name == 'host':
            canonical_headers.append(
                "%s:%s" % (name, ' '.join(value.strip().split(' ')))
            )
            names.append(name)

    signed_headers = ";".join(names)

    items.append("\n".join(canonical_headers))
    items.append("")
    items.append(signed_headers)

    digest = get_digest(body)
    items.append(digest)

    return "\n".join(items), signed_headers


def get_digest(string):
    return sha256(bytes(string)).hexdigest().__str__()


def get_string_to_sign(service, canonical):
    digest = get_digest(canonical)
    return "\n".join((
        "AWS4-HMAC-SHA256",
        now.strftime(canonical_time_format),
        "/".join((
            now.strftime(canonical_date_format),
            g['AWS_REGION'],
            service,
            auth_type,
        )),
        digest,
    ))


def get_signature(*args):
    s = bytes("AWS4" + g['AWS_SECRET_ACCESS_KEY'])
    for arg in args:
        s = hmac(s, bytes(arg), digestmod=sha256).digest()
    return str(hexlify(s))


def make_request(service, body):
    host = "%s.%s.amazonaws.com" % (service, g['AWS_REGION'])
    conn = get_secure_connection(host, timeout=5)

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=%s" % (
            encoding,
        ),
        "Content-Length": str(len(body)),
        "Host": host,
        "X-Amz-Date": now.strftime(canonical_time_format),
    }

    if security_token is not None:
        headers["X-Amz-Security-Token"] = security_token

    canonical, signed_headers = get_canonical(body, headers)
    signature = get_signature(
        now.strftime(canonical_date_format),
        g['AWS_REGION'],
        service,
        auth_type,
        get_string_to_sign(service, canonical),
    )

    headers.update({
        "User-Agent": user_agent,
        "Authorization": "AWS4-HMAC-SHA256 " + ",".join((
            "Credential=%s" % "/".join((
                g['AWS_ACCESS_KEY_ID'],
                now.strftime(canonical_date_format),
                g['AWS_REGION'],
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


def make_request_helper(name, action, params, version):
    params = dict((camelcase(name), value) for (name, value) in params.items())
    params.update({"Action": action, "Version": version})
    return make_request(name, urlencode(params))


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


def request_ami_id():
    return request_metadata('ami-id')


def request_region():
    return request_metadata('placement/availability-zone')[:-1]


def get_proxy(name):
    value = os.environ.get(name) or os.environ.get(name.upper())
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


def ec2(action, **params):
    return make_request_helper("ec2", action, params, "2013-07-15")


def rds(action, **params):
    return make_request_helper("rds", action, params, "2013-09-09")


def read_stats(data):
    if not data:
        return
    return tuple(map(float, filter(None, re.split('\s+', data)[1:])))


def submit_metrics(data, namespace, *dimensions):
    query = {
        "Action": "PutMetricData",
        "Version": "2010-08-01",
        "Namespace": namespace,
    }

    i = 0
    for name, (value, unit, metric_dimensions) in data:
        i += 1
        prefix = 'MetricData.member.%d.' % i
        query[prefix + 'MetricName'] = name
        query[prefix + 'Unit'] = unit
        query[prefix + 'Value'] = value

        metric_dimensions = tuple(metric_dimensions)

        for j, (name, value) in enumerate(dimensions + metric_dimensions):
            dimension = prefix + 'Dimensions.member.%d.' % (j + 1)
            query[dimension + 'Name'] = name
            query[dimension + 'Value'] = value

    body = urlencode(query)
    return make_request("monitoring", body)


def touchopen(filename, *args, **kwargs):
    fd = os.open(filename, os.O_RDWR | os.O_CREAT)
    return os.fdopen(fd, *args, **kwargs)


def collect_metrics(statfile=None):
    data = []

    def collect(f):
        name = camelcase(f.__name__)
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
            yield round(100 * (1 - inactive), 1), "Percent", ()

    @collect
    def disk_space_utilization():
        with open('/proc/mounts') as f:
            for line in f:
                if not line.startswith('/'):
                    continue

                device, path, filesystem, options = line.split(' ', 3)
                result = os.statvfs(path)

                if result.f_blocks == 0:
                    continue

                free = result.f_bfree / float(result.f_blocks)
                yield round(100 * (1 - free), 1), "Percent", (
                    ("Filesystem", filesystem),
                    ("MountPath", path)
                )

    @collect
    def load_average():
        with open('/proc/loadavg') as f:
            line = f.read()
            load = float(line.split(' ', 1)[0])
            yield round(100 * load, 1), "Percent", ()

    if statfile is not None:
        with open('/proc/stat') as f:
            new = f.readline()

        with touchopen(statfile, 'r+') as g:
            old = g.readline()

            g.seek(0)
            g.write(new)
            g.truncate()

        new_stats = read_stats(new)[:8]
        old_stats = read_stats(old)[:8] or (0, ) * len(new_stats)

        total = sum(new_stats) - sum(old_stats)

        stats = tuple(
            round(100 * (value / total), 1)
            for value in map(sub, new_stats, old_stats)
        )

        @collect
        def user():
            yield stats[0], "Percent", ()

        @collect
        def nice():
            yield stats[1], "Percent", ()

        @collect
        def system():
            yield stats[2], "Percent", ()

        @collect
        def blocked():
            yield stats[4], "Percent", ()

        @collect
        def irq():
            yield stats[5], "Percent", ()

        @collect
        def soft_irq():
            yield stats[6], "Percent", ()

        # Not all kernels provide this column.
        if len(stats) > 7:
            @collect
            def steal():
                yield stats[7], "Percent", ()

    @collect
    def network_connections():
        with open('/proc/net/tcp') as f:
            for i, line in enumerate(f):
                pass

        yield i, "Count", (("Protocol", "TCP"), )

        with open('/proc/net/udp') as f:
            for i, line in enumerate(f):
                pass

        yield i, "Count", (("Protocol", "UDP"), )

    return data


def mean(values):
    values = list(values)
    if not values:
        return 0.0

    return sum(values) / float(len(values))


class Config(object):
    def __init__(self, verbosity):
        self.verbosity = verbosity
        self.__dict__.update(os.environ)

    def add(self, key, f):
        setattr(self, "_" + key, f)

    def __getitem__(self, key):
        d = self.__dict__

        try:
            value = d[key]
        except KeyError:
            f = d["_" + key]
            if self.verbosity:
                log("running '%s' ..." % f.__name__, "info")
            value = f()
            d[key] = value

        return value


security_token = None


def metrics(statfile=None, verbose=False):
    verbose and log("collecting metrics ...", "info")
    data = collect_metrics(statfile)
    verbose and log("%d metrics collected." % len(data), "info")
    dimensions = ('InstanceId', g['AWS_INSTANCE_ID']), ('ImageId', g['AWS_AMI_ID'])
    for dimension in dimensions:
        verbose and log(
            "submit metrics for dimension '%s' ..." % dimension[0], "info"
        )
        submit_metrics(data, "System/Linux", dimension)


def snapshot(verbose=False):
    verbose and log("getting list of logically attached volumes ...", "info")
    data = ec2("DescribeVolumes")

    for volume_id, instance_id, dev in volumes_regex.findall(data):
        if instance_id != g['AWS_INSTANCE_ID']:
            continue

        verbose and log("volume %s attached to device: %s." % (
            volume_id, dev), "info")

        data = ec2(
            "CreateSnapshot",
            volume_id=volume_id,
            description="Automated snapshot for %s from %s" % (
                instance_id, volume_id
            )
        )

        if verbose:
            for snapshot_id in snapshot_regex.findall(data):
                log("snapshot %s created." % snapshot_id, "info")


def rds_log_sync(path=None, metrics=False, verbose=False, **kwargs):
    data = rds("DescribeDBLogFiles", **kwargs)
    tree = ElementTree.fromstring(data)
    ns = tree.tag[1:].split('}', 1)[0]
    path = path or os.getcwd()
    verbose and log("log path '%s'." % path, "info")

    details = tuple(tree.findall(".//{%s}DescribeDBLogFilesDetails" % ns))
    downloads = []
    for detail in details:
        size = int(detail.find('{%s}Size' % ns).text)
        last_written = int(detail.find('{%s}LastWritten' % ns).text) / 1000
        date = datetime.utcfromtimestamp(last_written)
        log_file_name = detail.find('{%s}LogFileName' % ns).text
        relative_path, filename = os.path.split(log_file_name)

        verbose and log("log file '%s/%s' on %s (%d bytes)" % (
            relative_path,
            filename,
            date.ctime(),
            size
        ), "info")

        p = os.path.join(path, relative_path)
        if not os.path.exists(p):
            os.makedirs(p)
            verbose and log("log path '%s' created." % p, "info")

        dest = os.path.join(p, filename)
        dest_marker = dest + ".marker"

        if os.path.exists(dest_marker):
            if os.path.getsize(dest) == size:
                verbose and log("log file unchanged.", "info")
                continue

            with open(dest_marker, "rb") as f:
                marker = f.read()

            verbose and log("marker '%s'." % marker, "info")
        else:
            marker = '0'

        t = time()
        data = rds(
            "DownloadDBLogFilePortion",
            log_file_name=log_file_name,
            marker=marker,
            number_of_lines=1000,
            **kwargs
        )
        t = time() - t

        tree = ElementTree.fromstring(data)
        marker = tree.find(".//{%s}Marker" % ns).text
        with open(dest_marker, "wb") as f:
            f.write(marker)
            verbose and log("log marker '%s' written." % marker, "info")

        body = tree.find(".//{%s}LogFileData" % ns).text
        if body is None:
            verbose and log("no data returned.")

        downloads.append((len(body), t))

        with open(dest, "ab") as f:
            f.write(body)
            verbose and log("log data written (%d bytes)." % len(body), "info")

        os.utime(dest, (last_written, last_written))

    if metrics:
        verbose and log("submitting metrics ...", "info")
        d = (('DBInstanceId', kwargs['DBInstanceIdentifier']), )
        submit_metrics((
            ("DescribeDBLogFiles", (1, "Count", d)),
            ("DownloadDBLogFilePortionCount", (len(downloads), "Count", d)),
            ("DownloadDBLogFilePortionSize", (sum(d[0] for d in downloads), "Bytes", d)),
            ("DownloadDBLogFilePortionThroughput", (
                mean(d[0] / d[1] for d in downloads), "Bytes/Second", d
            )),
        ), "RDS/Logging")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--verbose', '-v', action='store_true')
    commands = parser.add_subparsers()

    # Metrics
    metrics_parser = commands.add_parser(
        'metrics', help='report system metrics'
    )
    metrics_parser.set_defaults(func=metrics)
    metrics_parser.add_argument('statfile', nargs='?', default=None)

    # EBS Snapshot
    commands.add_parser('snapshot', help='create snapshot').set_defaults(
        func=snapshot
    )

    # RDS Log Sync
    rds_log_sync_parser = commands.add_parser(
        'rds-log-sync', help='synchronize rds log files'
    )
    rds_log_sync_parser.set_defaults(func=rds_log_sync)
    rds_log_sync_parser.add_argument('DBInstanceIdentifier', metavar='id')
    rds_log_sync_parser.add_argument(
        'path', nargs='?', type=os.path.abspath, metavar='id'
    )
    rds_log_sync_parser.add_argument(
        'MaxRecords', metavar='limit', nargs='?', type=int, default=100
    )
    rds_log_sync_parser.add_argument(
        '-m', '--metrics', action='store_const', const=True, default=False,
        help='report metrics'
    )

    args = parser.parse_args()
    data = args.__dict__
    func = data.pop('func')
    args.verbose and log("command '%s' ..." % func.__name__, "info")

    global g
    g = Config(args.verbose)

    # The following configuration is pulled from machine metadata if
    # not provided.
    g.add('AWS_ACCESS_KEY_ID', request_access_key)
    g.add('AWS_SECRET_ACCESS_KEY', request_secret_key)
    g.add('AWS_REGION', request_region)
    g.add('AWS_INSTANCE_ID', request_instance_id)
    g.add('AWS_AMI_ID', request_ami_id)

    try:
        func(**data)
    except BaseException:
        log(traceback.format_exc())
        raise SystemExit(1)
    else:
        args.verbose and log("done.", "info")
