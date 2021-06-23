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
        self.api.line_items.update({
            'id': 'F.G. Superman',
            'name': "Bicycle Repair Man"
        })
        self.assertEqual(self.api.line_items.get('F.G. Superman')['name'], 'Bicycle Repair Man')

    def test_update_and_query(self):
        self.api.segments.update(
            {
                'id': generate_id(),
                'name': 'Axe',
                'description': 'Herring',
            }
        )
        self.assertEqual(self.api.segments.query()['description'], 'Herring')

    def test_post_and_exists(self):
        bruce_id = generate_id()
        self.assertEqual(self.api.users.post(bruce_id, data={'id': bruce_id, 'name': 'Bruce'})['name'], 'Bruce')
        self.assertTrue(self.api.users.exists(bruce_id))
        self.assertEqual(self.api.users.post(bruce_id, data={'id': bruce_id, 'name': 'New Bruce'})['name'], 'New Bruce')
        self.assertTrue(self.api.users.exists(bruce_id))


class AdServerTests(unittest.TestCase):

    def setUp(self):
        self.adServer = MockAdServer()

    def test_request_ad_unit(self):
        ad_unit_tag_id = generate_id()
        self.assertEqual(self.adServer.request_ad_unit(ad_unit_tag_id,
                                                       extra_params={'parrot': 'Norwegian Blue'}).status_code, 200)
        self.assertEqual(self.adServer.session.args['params']['auId'], ad_unit_tag_id)
        self.assertEqual(self.adServer.session.args['params']['parrot'], 'Norwegian Blue')

    def test_request_ad_units(self):
        ad_unit_tag_id = generate_id()
        network_1_id = generate_id()
        network_2_id = generate_id()
        self.assertEqual(self.adServer.request_ad_units([ad_unit_tag_id], extra_params={'contest': 'Europolice'},
                                                        cookies={network_1_id + '!Inspector': 'Zatapathique',
                                                                 network_2_id + '!Inspector': 'Muffin'})
                         .status_code, 200)
        self.assertEqual(self.adServer.session.args['params']['tt'], 'composed')
        self.assertEqual(json.loads(self.adServer.session.data)['contest'], 'Europolice')
        self.assertEqual(len(json.loads(self.adServer.session.data)['adUnits']), 1)
        self.assertEqual(self.adServer.session.args['cookies'][network_1_id + '!Inspector'], 'Zatapathique')
        self.assertEqual(self.adServer.session.args['cookies'][network_2_id + '!Inspector'], 'Muffin')

    def test_request_ad_unit_objects(self):
        ad_unit_tag_id = generate_id()
        self.assertEqual(self.adServer.request_ad_units([
            {'auId': ad_unit_tag_id, 'targetId': 'one', 'auml': 'label'},
            {'auId': ad_unit_tag_id, 'targetId': 'two', 'auml': 'label'}
        ])
                         .status_code, 200)
        self.assertEqual(self.adServer.session.args['params']['tt'], 'composed')
        self.assertEqual(len(json.loads(self.adServer.session.data)['adUnits']), 2)
        self.assertEqual(json.loads(self.adServer.session.data)['adUnits'][0]['auId'], ad_unit_tag_id)
        self.assertEqual(json.loads(self.adServer.session.data)['adUnits'][0]['targetId'], 'one')
        self.assertEqual(json.loads(self.adServer.session.data)['adUnits'][0]['auml'], 'label')
        self.assertEqual(json.loads(self.adServer.session.data)['adUnits'][1]['auId'], ad_unit_tag_id)
        self.assertEqual(json.loads(self.adServer.session.data)['adUnits'][1]['targetId'], 'two')
        self.assertEqual(json.loads(self.adServer.session.data)['adUnits'][1]['auml'], 'label')

    def test_set_and_get_consent(self):
        network_id = generate_id()
        self.assertEqual(self.adServer.set_consent(network_id, consent='PROFILE').status_code, 200)
        self.assertEqual(json.loads(self.adServer.get_consent(network_id).json_data)['consent'], ['PROFILE'])


class DataServerTests(unittest.TestCase):

    def setUp(self):
        self.dataServer = MockDataServer()

    def test_visitor(self):
        self.assertEqual(self.dataServer.visitor(folder=generate_id(), browser='Ernest Scribbler',
                                                 profile_values={'Wenn ist das Nunstück git und Slotermeyer?':
                                                                 'Ja! Beiherhund das Oder die Flipperwaldt gersput'})
                         .status_code, 200)

    def test_page(self):
        self.assertEqual(self.dataServer.page('green-midget-cafe.com', folder=generate_id(),
                                              browser='Mr Bun', keywords=['spam']).status_code, 200)

    def test_sync(self):
        self.assertEqual(self.dataServer.sync(user_id='Cardinal Fang', browser='Marjorie Wilde',
                                              folder='Spanish Inquisition').status_code, 200)


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
