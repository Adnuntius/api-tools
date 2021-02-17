__copyright__ = "Copyright (c) 2021 Adnuntius AS.  All rights reserved."

import json
from requests import Response, Session
from adnuntius.api import Api, ApiClient


class MockResponse(Response):
    def __init__(self, json_data, status_code):
        super().__init__()
        self.json_data = json_data
        self.status_code = status_code
        self._content = str.encode(json_data)

    def json(self):
        return json.loads(self.json_data)


class MockSession(Session):

    def __init__(self):
        super().__init__()
        self.data = None

    def get(self, url, **kwargs):
        return MockResponse(self.data, 200)

    def post(self, url, data=None, json=None, **kwargs):
        self.data = data
        return MockResponse(self.data, 200)


class MockApiClient(ApiClient):

    def __init__(self, resource, api_context):
        super().__init__(resource, api_context, session=MockSession())


class MockAPI(Api):

    def __init__(self):
        super().__init__(None, None, 'http://localhost:3333/api',
                         api_client=lambda resource: MockApiClient(resource, self))