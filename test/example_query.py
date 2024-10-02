#!/usr/bin/env python3
"""Example code showing the usage of paged queries in the Adnuntius API."""

__copyright__ = "Copyright (c) 2024 Adnuntius AS.  All rights reserved."

import argparse
import getpass
from datetime import timedelta, datetime

from adnuntius.api import Api
from adnuntius.util import date_to_string, half_hour, half_hour_round_up


def query_order_example(api):
    """
       Example of querying orders
    """
    api.defaultArgs['context'] = args.network
    page = 1
    page_size = 25
    total_count = None
    processed_count = 0
    while total_count is None or (page - 1) * page_size < total_count:
        query_result = api.orders.query({'page': page, 'pageSize': page_size})
        if total_count is None:
            total_count = query_result['totalCount']
            print(f"Total items to process: {total_count}")
        for order in query_result['results']:
            processed_count += 1
            # Query daily stats for the order for the last 7 days in NOK
            stats = api.stats.query(args={'orderId': order['id'],
                                          'startDate': date_to_string(half_hour(datetime.utcnow() - timedelta(days=7))),
                                          'endDate': date_to_string(half_hour_round_up(datetime.utcnow())),
                                          'currency': 'NOK',
                                          'groupBy': 'daily'})
            print(f"Item {processed_count}/{total_count} "
                  f"order {order['id']} had {stats['totals']['impressions']} impressions")
        page += 1
        print(f"Moving to page {page}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adnuntius API example which queries orders")
    parser.add_argument('--api', dest='api_url', default='https://api.adnuntius.com/api')
    parser.add_argument('--network', dest='network', required=True)
    parser.add_argument('--user', dest='user', required=False)
    parser.add_argument('--password', dest='password', required=False)
    parser.add_argument('--api_key', dest='api_key', required=False)
    parser.add_argument('--masquerade', dest='masquerade', required=False)
    args = parser.parse_args()

    api_key = args.api_key
    if api_key is None and args.user is None:
        api_key = getpass.getpass('Enter API key: ')
    if api_key is None:
        password = args.password
        if password is None:
            password = getpass.getpass('Enter password: ')
        api = Api(args.user, password, args.api_url,
                  context=args.network, masquerade_user=args.masquerade)
    else:
        api = Api(None, None, args.api_url,
                  api_key=api_key, context=args.network, masquerade_user=args.masquerade)

    query_order_example(api)
