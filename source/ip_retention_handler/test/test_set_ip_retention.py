#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

from os import environ
from types import SimpleNamespace

from set_ip_retention import lambda_handler

context = SimpleNamespace(**{
    'function_name': 'foo',
    'memory_limit_in_mb': '512',
    'invoked_function_arn': ':::invoked_function_arn',
    'log_group_name': 'log_group_name',
    'log_stream_name': 'log_stream_name',
    'aws_request_id': 'baz'
})

SKIP_PROCESS_MESSAGE = "The event for UpdateIPSet API call was made by RemoveExpiredIP lambda instead of user. Skip."


def test_set_ip_retention(set_ip_retention_test_event_setup):
    environ['REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME'] = 'some_role'
    environ['IP_RETENTION_PERIOD_ALLOWED_MINUTE'] = '60'
    environ['IP_RETENTION_PERIOD_DENIED_MINUTE'] = '60'
    environ['TABLE_NAME'] = "test_table"
    event = set_ip_retention_test_event_setup
    result = lambda_handler(event, context)
    assert result is None


def test_ip_retention_not_activated(set_ip_retention_test_event_setup):
    environ['REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME'] = 'some_role'
    environ['IP_RETENTION_PERIOD_ALLOWED_MINUTE'] = '-1'
    environ['IP_RETENTION_PERIOD_DENIED_MINUTE'] = '-1'
    event = set_ip_retention_test_event_setup
    result = lambda_handler(event, context)
    assert result is not None

def test_missing_request_parameters_in_event(missing_request_parameters_test_event_setup):
	environ['REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME'] = 'some_role'
	environ['IP_RETENTION_PERIOD_ALLOWED_MINUTE'] = '60'
	environ['IP_RETENTION_PERIOD_DENIED_MINUTE'] = '60'
	event = missing_request_parameters_test_event_setup
	result = lambda_handler(event, context)
	assert result is None
        

def test_skip_process(set_ip_retention_test_event_setup):
	environ['REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME'] = 'fake-arn'
	event = set_ip_retention_test_event_setup
	result = {"Message": SKIP_PROCESS_MESSAGE}
	assert result == lambda_handler(event, context)
        

def test_put_item_exception(set_ip_retention_test_event_setup):
    try:
        environ['REMOVE_EXPIRED_IP_LAMBDA_ROLE_NAME'] = 'some_role'
        environ['IP_RETENTION_PERIOD_ALLOWED_MINUTE'] = '-1'
        environ['IP_RETENTION_PERIOD_DENIED_MINUTE'] = '60'
        environ.pop('TABLE_NAME')
        event = set_ip_retention_test_event_setup
        result = False
        lambda_handler(event, context)
        result = True
    except Exception as e:
        assert result == False