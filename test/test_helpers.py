__copyright__ = "Copyright (c) 2021 Adnuntius AS.  All rights reserved."

import json
from requests import Response, Session
from adnuntius.api import Api, ApiClient, AdServer, DataServer


class MockResponse(Response):
    def __init__(self, json_data, status_code):
        super().__init__()
        if json_data is None:
            self.json_data = '{}'
        else:
            self.json_data = str(json_data).replace("\'", "\"")
        self.status_code = status_code
        self._content = str.encode(self.json_data)

    def json(self):
        return json.loads(self.json_data)


class MockSession(Session):

    def __init__(self):
        super().__init__()
        self.data = None
        self.args = {}

    def get(self, url, **kwargs):
        self.args = kwargs
        return MockResponse(self.data, 200)

    def post(self, url, data=None, json=None, **kwargs):
        self.args = kwargs
        self.data = data
        return MockResponse(self.data, 200)

    def head(self, url, **kwargs):
        return MockResponse(self.data, 200)


class MockApiClient(ApiClient):

    def __init__(self, resource, api_context):
        super().__init__(resource, api_context, session=MockSession())


class MockAPI(Api):

    def __init__(self):
        super().__init__(None, None, 'http://localhost:33333/api',
                         api_client=lambda resource: MockApiClient(resource, self))


class MockAdServer(AdServer):

    def __init__(self):
        super().__init__('http://localhost:33333', session=MockSession())


class MockDataServer(DataServer):

    def __init__(self):
        super().__init__('http://localhost:33333', session=MockSession())
