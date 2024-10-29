#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

from os import environ
from types import SimpleNamespace

from partition_s3_logs import lambda_handler

context = SimpleNamespace(**{
    'function_name': 'foo',
    'memory_limit_in_mb': '512',
    'invoked_function_arn': ':::invoked_function_arn',
    'log_group_name': 'log_group_name',
    'log_stream_name': 'log_stream_name',
    'aws_request_id': 'baz'
})

def test_partition_s3_cloudfront_log(partition_s3_cloudfront_log_test_event_setup):
    try: 
        event = partition_s3_cloudfront_log_test_event_setup
        result = False
        lambda_handler(event, context)
        result = True
        environ.pop('KEEP_ORIGINAL_DATA')
        environ.pop('ENDPOINT')
    except Exception:
        raise
    assert result == True


def test_partition_s3_alb_log(partition_s3_alb_log_test_event_setup):
    try: 
        event = partition_s3_alb_log_test_event_setup
        result = False
        lambda_handler(event, context)
        result = True
        environ.pop('KEEP_ORIGINAL_DATA')
        environ.pop('ENDPOINT')
    except Exception:
        raise
    assert result == True