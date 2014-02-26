AWS CloudWatch Linux Metrics
============================

Use this Python script to post system metrics to AWS CloudWatch.

Metrics:

  - MemoryUtilization
  - DiskSpaceUtilization
  - LoadAverage
  - NetworkConnections

To authenticate, either provide machines with an IAM role or set
environment variables ``AWS_ACCESS_KEY_ID`` and
``AWS_SECRET_ACCESS_KEY``. If an IAM role is provided, usually no
further configuration is needed.

The script automatically pulls down region and instance id, unless
provided in the environment variables ``AWS_REGION`` and
``AWS_INSTANCE_ID``.

Platform
--------

Use with Python 2.6+ or Python 3.1+. No package dependencies.
