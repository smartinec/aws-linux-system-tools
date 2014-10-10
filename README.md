AWS Linux System Tools
======================

This is a collection of Amazon EC2 system tools for Linux.

The implementation is a single Python script with no package
dependencies except the standard library.

It runs on both Python 2.x and 3.x.


Configuration
-------------

To authenticate, either provide machines with an IAM role or set
environment variables ``AWS_ACCESS_KEY_ID`` and
``AWS_SECRET_ACCESS_KEY``. If an IAM role is provided, usually no
further configuration is needed.

The script automatically pulls down region and instance id, unless
provided in the environment variables ``AWS_REGION`` and
``AWS_INSTANCE_ID``.


System Metrics
--------------

The ``metrics`` command posts system metrics to `AWS CloudWatch
<https://aws.amazon.com/cloudwatch/>`_:

    $ python aws-system-tools.py metrics /tmp/stats

Metrics:

  - MemoryUtilization
  - DiskSpaceUtilization
  - LoadAverage
  - NetworkConnections

If the ``statfile`` argument is provided, an additional set of metrics
are reported:

  - User:    Normal processes executing in user mode
  - Nice:    Niced processes executing in user mode
  - System:  Processes executing in kernel mode
  - Blocked: Waiting for I/O to complete
  - Irq:     Servicing interrupts
  - SoftIrq: Servicing softirqs
  - Steal:   Virtual CPU steal

Each metric is reported with respect to both the instance id and the
image id, the latter providing aggregate numbers for all instances
running that image (e.g. auto-scale groups).


EBS Snapshots
-------------

The ``snapshot`` command requests an EBS snapshot of those volumes
currently attached logically to the machine.

    $ python aws-system-tools.py snapshot


RDS Log Sync
------------

The ``rds-log-sync`` command synchronizes log files from an RDS
instance to a local directory.

    $ python aws-system-tools.py rds-log-sync <db-instance-id> <path>

The ``path`` argument is optional and defaults to the working
directory.

If ``--metrics`` is given then the script submits CloudWatch metrics
with statistics on how frequently the script has run (without failure)
and how much it has downloaded (number of requests, bytes and
throughput).
