#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

from add_athena_partitions import lambda_handler

context = SimpleNamespace(**{
    'function_name': 'foo',
    'memory_limit_in_mb': '512',
    'invoked_function_arn': ':::invoked_function_arn',
    'log_group_name': 'log_group_name',
    'log_stream_name': 'log_stream_name',
    'aws_request_id': 'baz'
})

def test_add_athena_partitions(athena_partitions_test_event_setup):
    try: 
        event = athena_partitions_test_event_setup
        result = False
        lambda_handler(event, context)
        result = True
    except Exception:
        raise
    assert result == True


def test_add_athena_partitions(athena_partitions_non_existent_work_group_test_event_setup):
    try: 
        event = athena_partitions_non_existent_work_group_test_event_setup
        result = False
        lambda_handler(event, context)
        result = True
    except Exception:
        assert result == False
