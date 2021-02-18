__copyright__ = "Copyright (c) 2021 Adnuntius AS.  All rights reserved."

import datetime
import json
import unittest
from dateutil.tz import tzutc
from adnuntius.util import date_to_string, generate_id, id_reference, str_to_date
from test.test_helpers import MockAPI, MockAdServer, MockDataServer


class ApiTests(unittest.TestCase):

    def setUp(self):
        self.api = MockAPI()

    def test_update_and_get(self):
        self.api.lineitems.update({
            'id': 'F.G. Superman',
            'name': "Bicycle Repair Man"
        })
        self.assertEqual(self.api.lineitems.get('F.G. Superman')['name'], 'Bicycle Repair Man')

    def test_update_and_query(self):
        self.api.segments.update(
            {
                'id': generate_id(),
                'name': 'Axe',
                'description': 'Herring',
            }
        )
        self.assertEqual(self.api.segments.query()['description'], 'Herring')


class AdServerTests(unittest.TestCase):

    def setUp(self):
        self.adServer = MockAdServer()

    def test_request_ad_unit(self):
        ad_unit_tag_id = generate_id()
        self.assertEqual(self.adServer.request_ad_unit(ad_unit_tag_id,
                                                       extra_params={'parrot': 'Norwegian Blue'}).status_code, 200)
        self.assertEqual(self.adServer.session.args['params']['auId'], ad_unit_tag_id)
        self.assertEqual(self.adServer.session.args['params']['parrot'], 'Norwegian Blue')

    def test_set_and_get_consent(self):
        network_id = generate_id()
        self.assertEqual(self.adServer.set_consent(network_id, consent='PROFILE').status_code, 200)
        self.assertEqual(json.loads(self.adServer.get_consent(network_id).json_data)['consent'], ['PROFILE'])


class DataServerTests(unittest.TestCase):

    def setUp(self):
        self.dataServer = MockDataServer()

    def test_page(self):
        self.assertEqual(self.dataServer.page('green-midget-cafe.com', folder=generate_id(),
                                              browser='Mr Bun', keywords=['spam']).status_code, 200)


class UtilTests(unittest.TestCase):

    def test_date_to_string(self):
        self.assertEqual(date_to_string(datetime.datetime(year=2016, month=4, day=7, tzinfo=tzutc())),
                         '2016-04-07T00:00:00Z')
        self.assertEqual(date_to_string(datetime.date(year=2016, month=4, day=7)), '2016-04-07T00:00:00Z')

    def test_id_reference(self):
        self.assertEqual(id_reference("Whizzo"), {'id': "Whizzo"})
        self.assertEqual(id_reference({'id': "Whizzo", 'taste': 'Dead Crab'}), {'id': "Whizzo"})

    def test_str_to_date(self):
        self.assertEqual(str_to_date('2016-04-07T00:00:00Z'),
                         datetime.datetime(year=2016, month=4, day=7, tzinfo=tzutc()))
        self.assertEqual(str_to_date('2016-04-07'),
                         datetime.datetime(year=2016, month=4, day=7, hour=0, minute=0))


if __name__ == '__main__':
    unittest.main()
