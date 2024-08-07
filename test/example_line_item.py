#!/usr/bin/env python3
"""Example code showing the usage of the Adnuntius API to update line items."""

__copyright__ = "Copyright (c) 2022 Adnuntius AS.  All rights reserved."

import json
import argparse
import getpass
import os
import datetime

from adnuntius.api import Api
from adnuntius.util import generate_alphanum_id, date_to_string, id_reference


def create_line_item_example(api):
    """
       Example of creating a line item.
       Note: this line item will still need an order and tier in order to run.
    """

    # Asset to attach to the line item
    asset_file = os.path.dirname(os.path.realpath(__file__)) + '/example_asset.png'
    asset_width = 728
    asset_height = 90

    # Create a line item
    print('Creating line item...')
    lineitem = api.line_items.update({
        'id': generate_alphanum_id(),
        'name': 'Example Line Item 2',
        'userState': 'APPROVED',
        'startDate': date_to_string(datetime.date.today()),
        'endDate': date_to_string(datetime.date.today() + datetime.timedelta(weeks=1)),
        'objectives': {
            'IMPRESSION': 1000000
        },
        'bidSpecification': {
            "cpm": {
                "currency": "AUD",
                "amount": 10.0
            }
        },
        'smoothed': True
    })

    # Query all layouts and select the 'Leaderboard - single image' one
    print('Finding Leaderboard layout...')
    layouts = api.layouts.query()['results']
    layout_names = [layout['name'] for layout in layouts]
    layout = layouts[layout_names.index('Image')]

    # Create creative
    print('Creating creative...')
    creative = api.creatives.update({
        'id': generate_alphanum_id(),
        'name': 'Creative for Example 2',
        'lineItem': id_reference(lineitem),
        'constraintsToUrls': {
            'destination': 'www.example.com/board'
        },
        'layout': id_reference(layout),
        'width': asset_width,
        'height': asset_height
    })

    # Upload asset
    print('Uploading asset...')
    asset = api.assets.upload_resource(creative['id'], generate_alphanum_id(), asset_file, 'image/png')

    # Link the asset to the creative
    print('Linking asset to creative...')
    creative = api.creatives.update({
        'id': creative['id'],
        'lineItem': id_reference(lineitem),
        'constraintsToAssets': {
            layout['assetConstraints'][0]['tag']: asset['id']
        }
    })


def list_line_items_example(api):
    """
       Example of querying and printing results.
    """

    # Retrieve all line items for this network
    print('Querying all Line Items...')
    line_items = api.line_items.query()['results']
    for line_item in line_items:
        print('Name: ', line_item['name'])
        print('Id: ', line_item['id'])
        print('JSON:\n', json.dumps(line_item, indent=4))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adnuntius API example which creates and updates a line item")
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

    create_line_item_example(api)
    list_line_items_example(api)
