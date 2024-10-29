#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import logging
from types import SimpleNamespace

from aws_lambda_powertools.utilities.typing import LambdaContext

from access_handler.access_handler import *
import os


log_level = 'DEBUG'
logging.getLogger().setLevel(log_level)
log = logging.getLogger('test_access_handler')

context = SimpleNamespace(**{
    'function_name': 'foo',
    'memory_limit_in_mb': '512',
    'invoked_function_arn': 'bar',
    'aws_request_id': 'baz'
})

def test_access_handler_error(ipset_env_var_setup, badbot_event, expected_exception_access_handler_error):
    try:
        lambda_handler(badbot_event, context)
    except Exception as e:
        expected = expected_exception_access_handler_error
        assert str(e) == expected

def test_initialize_usage_data():
    os.environ['LOG_TYPE'] = 'LOG_TYPE'
    result = initialize_usage_data()
    expected = {
        "data_type": "bad_bot",
        "bad_bot_ip_set_size": 0,
        "allowed_requests": 0,
        "blocked_requests_all": 0,
        "blocked_requests_bad_bot": 0,
        "waf_type": 'LOG_TYPE',
        "provisioner": "cfn"
    }
    assert result == expected

def test_send_anonymized_usage_data(cloudwatch_client, expected_cw_resp):
    result = send_anonymized_usage_data(
        scope='ALB',
        ipset_name_v4='ipset_name_v4',
        ipset_arn_v4='ipset_arn_v4',
        ipset_name_v6='ipset_name_v6',
        ipset_arn_v6='ipset_arn_v6'
    )
    assert result == expected_cw_resp
