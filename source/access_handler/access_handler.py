#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: Apache-2.0

import os
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from ipaddress import ip_address
from os import environ

from aws_lambda_powertools import Logger

from lib.cw_metrics_util import WAFCloudWatchMetrics
from lib.solution_metrics import send_metrics
from lib.waflibv2 import WAFLIBv2

logger = Logger(
    level=os.getenv('LOG_LEVEL')
)

waflib = WAFLIBv2()
CW_METRIC_PERIOD_SECONDS = 12 * 3600    # Twelve hours in seconds

def initialize_usage_data():
    usage_data = {
        "data_type": "bad_bot",
        "bad_bot_ip_set_size": 0,
        "allowed_requests": 0,
        "blocked_requests_all": 0,
        "blocked_requests_bad_bot": 0,
        "waf_type": os.getenv('LOG_TYPE'),
        "provisioner": os.getenv('provisioner') if "provisioner" in environ else "cfn"

    }
    return usage_data


def get_bad_bot_usage_data(scope, cw, ipset_name_v4, ipset_arn_v4, ipset_name_v6, ipset_arn_v6, usage_data):
    logger.info("[get_bad_bot_usage_data] Get bad bot data")

    if 'IP_SET_ID_BAD_BOTV4' in environ or 'IP_SET_ID_BAD_BOTV6' in environ:
        # Get the count of ipv4 and ipv6 in bad bot ip sets
        ipv4_count = waflib.get_ip_address_count(logger, scope, ipset_name_v4, ipset_arn_v4)
        ipv6_count = waflib.get_ip_address_count(logger, scope, ipset_name_v6, ipset_arn_v6)
        usage_data['bad_bot_ip_set_size'] = str(ipv4_count + ipv6_count)

        # Get the count of blocked requests for the bad bot rule from cloudwatch metrics
        usage_data = cw.add_waf_cw_metric_to_usage_data(
            'BlockedRequests',
            CW_METRIC_PERIOD_SECONDS,
            os.getenv('METRIC_NAME_PREFIX') + 'BadBotRule',
            usage_data,
            'blocked_requests_bad_bot',
            0
        )
    return usage_data


def send_anonymized_usage_data(scope, ipset_name_v4, ipset_arn_v4, ipset_name_v6, ipset_arn_v6):
    try:
        if 'SEND_ANONYMIZED_USAGE_DATA' not in environ or os.getenv('SEND_ANONYMIZED_USAGE_DATA').lower() != 'yes':
            return

        logger.info("[send_anonymized_usage_data] Start")

        cw = WAFCloudWatchMetrics(logger)
        usage_data = initialize_usage_data()

        # Get the count of allowed requests for all the waf rules from cloudwatch metrics
        usage_data = cw.add_waf_cw_metric_to_usage_data(
            'AllowedRequests',
            CW_METRIC_PERIOD_SECONDS,
            'ALL',
            usage_data,
            'allowed_requests',
            0
        )

        # Get the count of blocked requests for all the waf rules from cloudwatch metrics
        usage_data = cw.add_waf_cw_metric_to_usage_data(
            'BlockedRequests',
            CW_METRIC_PERIOD_SECONDS,
            'ALL',
            usage_data,
            'blocked_requests_all',
            0
        )

        # Get bad bot specific usage data
        usage_data = get_bad_bot_usage_data(scope, cw, ipset_name_v4, ipset_arn_v4, ipset_name_v6, ipset_arn_v6,
                                            usage_data)

        # Send usage data
        logger.info('[send_anonymized_usage_data] Send usage data: \n{}'.format(usage_data))
        response = send_metrics(data=usage_data)
        response_code = response.status_code
        logger.info('[send_anonymized_usage_data] Response Code: {}'.format(response_code))
        logger.info("[send_anonymized_usage_data] End")

    except Exception as error:
        logger.info("[send_anonymized_usage_data] Failed to Send Data")
        logger.error(str(error))


def add_ip_to_ip_set(scope, ip_type, source_ip, ipset_name, ipset_arn):
    new_address = []
    output = None
    
    if ip_type == "IPV4":
        new_address.append(IPv4Network(source_ip).with_prefixlen)
    elif ip_type == "IPV6":
        new_address.append(IPv6Network(source_ip).with_prefixlen)
    
    ipset = waflib.get_ip_set(logger, scope, ipset_name, ipset_arn)
    # merge old addresses with this one
    logger.info(ipset)
    current_list = ipset["IPSet"]["Addresses"]
    logger.info(current_list)
    new_list = list(set(current_list) | set(new_address))
    logger.info(new_list)
    output = waflib.update_ip_set(logger, scope, ipset_name, ipset_arn, new_list)

    return output


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
@logger.inject_lambda_context
def lambda_handler(event, _):
    logger.info('[lambda_handler] Start')

    # ----------------------------------------------------------
    # Read inputs parameters
    # ----------------------------------------------------------
    try:
        scope = os.getenv('SCOPE')
        ipset_name_v4 = os.getenv('IP_SET_NAME_BAD_BOTV4')
        ipset_name_v6 = os.getenv('IP_SET_NAME_BAD_BOTV6')
        ipset_arn_v4 = os.getenv('IP_SET_ID_BAD_BOTV4')
        ipset_arn_v6 = os.getenv('IP_SET_ID_BAD_BOTV6')

        # Fixed as old line had security exposure based on user supplied IP address
        logger.info("Event->%s<-", str(event))
        if event['requestContext']['identity']['userAgent'] == 'Amazon CloudFront':
            source_ip = str(event['headers']['X-Forwarded-For'].split(',')[0].strip())
        else:
            source_ip = str(event['requestContext']['identity']['sourceIp'])

        logger.info("scope = %s", scope)
        logger.info("ipset_name_v4 = %s", ipset_name_v4)
        logger.info("ipset_name_v6 = %s", ipset_name_v6)
        logger.info("IPARNV4 = %s", ipset_arn_v4)
        logger.info("IPARNV6 = %s", ipset_arn_v6)
        logger.info("source_ip = %s", source_ip)

        ip_type = "IPV%s" % ip_address(source_ip).version
        output = None
        if ip_type == "IPV4":
            output = add_ip_to_ip_set(scope, ip_type, source_ip, ipset_name_v4, ipset_arn_v4)
        elif ip_type == "IPV6":
            output = add_ip_to_ip_set(scope, ip_type, source_ip, ipset_name_v6, ipset_arn_v6)
    except Exception as e:
        logger.error(e)
        raise
    finally:
        logger.info("Output->%s<-", output)
        message = "message: [%s] Thanks for the visit." % source_ip
        response = {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': message
        }

    if output is not None:
        send_anonymized_usage_data(scope, ipset_name_v4, ipset_arn_v4, ipset_name_v6, ipset_arn_v6)
    logger.info('[lambda_handler] End')

    return response
