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

    $ python aws-system-tools.py metrics

Metrics:

  - MemoryUtilization
  - DiskSpaceUtilization
  - LoadAverage
  - NetworkConnections

Each metric is reported with respect to both the instance id and the
image id, the latter providing aggregate numbers for all instances
running that image (e.g. auto-scale groups).
