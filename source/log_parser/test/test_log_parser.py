#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

from os import environ
from types import SimpleNamespace

from log_parser import log_parser

context = SimpleNamespace(**{
    'function_name': 'foo',
    'memory_limit_in_mb': '512',
    'invoked_function_arn': ':::invoked_function_arn',
    'log_group_name': 'log_group_name',
    'log_stream_name': 'log_stream_name',
    'aws_request_id': 'baz'
})


UNDEFINED_HANDLER_MESSAGE = "[lambda_handler] undefined handler for this type of event"
ATHENA_LOG_PARSER_PROCESSED_MESSAGE = "[lambda_handler] Athena scheduler event processed."
ATHENA_APP_LOG_QUERY_RESULT_PROCESSED_MESSAGE = "[lambda_handler] Athena app log query result processed."
ATHENA_WAF_LOG_QUERY_RESULT_PROCESSED_MESSAGE = "[lambda_handler] Athena AWS WAF log query result processed."
APP_LOG_LAMBDA_PARSER_PROCESSED_MESSAGE = "[lambda_handler] App access log file processed."
WAF_LOG_LAMBDA_PARSER_PROCESSED_MESSAGE = "[lambda_handler] AWS WAF access log file processed."
TYPE_ERROR_MESSAGE = "TypeError: string indices must be integers"


def test_undefined_handler_event():
    event = {"test": "value"}
    result = {"message": UNDEFINED_HANDLER_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)


def test_undefined_handler_records(cloudfront_log_lambda_parser_test_event_setup):
    event = cloudfront_log_lambda_parser_test_event_setup
    UNDEFINED_HANDLER_MESSAGE = "[lambda_handler] undefined handler for bucket %s" % environ["APP_ACCESS_LOG_BUCKET"]
    environ.pop('APP_ACCESS_LOG_BUCKET')
    result = {"message": UNDEFINED_HANDLER_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)


def test_cloudfront_log_athena_parser(app_log_athena_parser_test_event_setup):
    environ['LOG_TYPE'] = "CLOUDFRONT"
    event = app_log_athena_parser_test_event_setup
    result = {"message": ATHENA_LOG_PARSER_PROCESSED_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)
    environ.pop('LOG_TYPE')


def test_alb_log_athena_parser(app_log_athena_parser_test_event_setup):
    environ['LOG_TYPE'] = "ALB"
    event = app_log_athena_parser_test_event_setup
    result = {"message": ATHENA_LOG_PARSER_PROCESSED_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)
    environ.pop('LOG_TYPE')


def test_waf_log_athena_parser(waf_log_athena_parser_test_event_setup):
    environ['LOG_TYPE'] = "WAF"
    event = waf_log_athena_parser_test_event_setup
    result = {"message": ATHENA_LOG_PARSER_PROCESSED_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)
    environ.pop('LOG_TYPE')


def test_app_log_athena_result_processor(app_log_athena_query_result_test_event_setup):
    event = app_log_athena_query_result_test_event_setup
    result = {"message": ATHENA_APP_LOG_QUERY_RESULT_PROCESSED_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)
    environ.pop('APP_ACCESS_LOG_BUCKET')


def test_waf_log_athena_result_processor(waf_log_athena_query_result_test_event_setup):
    event = waf_log_athena_query_result_test_event_setup
    result = {"message": ATHENA_WAF_LOG_QUERY_RESULT_PROCESSED_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)
    environ.pop('WAF_ACCESS_LOG_BUCKET')
    

def test_cloudfront_log_lambda_parser(cloudfront_log_lambda_parser_test_event_setup):
    environ['LOG_TYPE'] = "cloudfront"
    event = cloudfront_log_lambda_parser_test_event_setup
    result = {"message": APP_LOG_LAMBDA_PARSER_PROCESSED_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)
    environ.pop('APP_ACCESS_LOG_BUCKET')
    environ.pop('LOG_TYPE')


def test_alb_log_lambda_parser(alb_log_lambda_parser_test_event_setup):
    environ['LOG_TYPE'] = "alb"
    event = alb_log_lambda_parser_test_event_setup
    result = {"message": APP_LOG_LAMBDA_PARSER_PROCESSED_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)
    environ.pop('APP_ACCESS_LOG_BUCKET')
    environ.pop('LOG_TYPE')

def test_alb_log_lambda_parser_over_ip_range_limit(alb_log_lambda_parser_test_event_setup):
    environ['LOG_TYPE'] = "alb"
    environ['LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION'] = '1'
    event = alb_log_lambda_parser_test_event_setup
    result = {"message": APP_LOG_LAMBDA_PARSER_PROCESSED_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)
    environ.pop('APP_ACCESS_LOG_BUCKET')
    environ.pop('LOG_TYPE')
    environ.pop('LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION')


def test_waf_lambda_parser(waf_log_lambda_parser_test_event_setup):
    environ['LOG_TYPE'] = "waf"
    event = waf_log_lambda_parser_test_event_setup
    result = {"message": WAF_LOG_LAMBDA_PARSER_PROCESSED_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)
    environ.pop('WAF_ACCESS_LOG_BUCKET')
    environ.pop('LOG_TYPE')


def test_waf_lambda_parser_over_ip_range_limit(waf_log_lambda_parser_test_event_setup):
    environ['LOG_TYPE'] = "waf"
    environ['LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION'] = '1'
    event = waf_log_lambda_parser_test_event_setup
    result = {"message": WAF_LOG_LAMBDA_PARSER_PROCESSED_MESSAGE}
    assert result == log_parser.lambda_handler(event, context)
    environ.pop('WAF_ACCESS_LOG_BUCKET')
    environ.pop('LOG_TYPE')
    environ.pop('LIMIT_IP_ADDRESS_RANGES_PER_IP_MATCH_CONDITION')


def test_lambda_parser_unsupported_log_type(cloudfront_log_lambda_parser_test_event_setup):
    try:
        environ['LOG_TYPE'] = "unsupported"
        event = cloudfront_log_lambda_parser_test_event_setup
    except Exception as e:
        assert str(e) == TYPE_ERROR_MESSAGE
    finally:
        environ.pop('APP_ACCESS_LOG_BUCKET')
        environ.pop('LOG_TYPE')