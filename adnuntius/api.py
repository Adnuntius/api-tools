"""Api client code for the Adnuntius APIs."""

__copyright__ = "Copyright (c) 2019 Adnuntius AS.  All rights reserved."

import json
import os
import requests
import requests.exceptions
from requests_toolbelt.multipart.encoder import MultipartEncoder

from compare_json import compare_api_json_equal
from util import *


class Api:
    """
    Allows access to the Adnuntius public APIs.
    """

    def __init__(self, username, password, location, context=None, verify=False, apiKey=None, masquerade_user=None):
        """
        Constructs the Api class. Use this to access the various API endpoints.

        :param username: API username
        :param password: API password
        :param location: URL for the api including the path, eg "https://api.adnuntius.com/api"
        :param context: the network context to use for API calls
        :param verify: verify the response from the api by comparing json packets
        """

        self.defaultAuthArgs = {}
        self.defaultArgs = {}
        if context:
            self.defaultArgs['context'] = context

        self.location = location
        self.username = username
        self.password = password
        self.masquerade_user = masquerade_user
        self.apiKey = apiKey
        self.verify = verify
        self.defaultIgnore = {'url', 'objectState', 'validationWarnings', 'createUser', 'createTime', 'updateUser', 'updateTime'}

        self.adunits = ApiClient("adunits", self)
        self.adunittags = ApiClient("adunittags", self)
        self.advertisers = ApiClient("advertisers", self)
        self.allocationreport = ApiClient("allocationreport", self)
        self.apikeys = ApiClient("apikeys", self)
        self.assets = ApiClient("assets", self)
        self.burnrates = ApiClient("burnrates", self)
        self.categories = ApiClient("categories", self)
        self.categoriesupload = ApiClient("categories/upload", self)
        self.cdnassets = ApiClient("cdnassets", self)
        self.contextserviceconnections = ApiClient("contextserviceconnections", self);
        self.creatives = ApiClient("creatives", self)
        self.customeventtypes = ApiClient("customeventtypes", self)
        self.dataviews = ApiClient("dataviews", self)
        self.deliveryestimate = ApiClient("deliveryestimate", self)
        self.dspcampaigns = ApiClient("dspcampaigns", self)
        self.earningsaccounts = ApiClient("earningsaccounts", self)
        self.externaladunits = ApiClient("externaladunits", self)
        self.externaldemandsources = ApiClient("externaldemandsources", self)
        self.facebookcampaigns = ApiClient("facebookcampaigns", self)
        self.forecasts = ApiClient("forecasts", self)
        self.impactreport = ApiClient("impactreport", self)
        self.keyvalues = ApiClient("keyvalues", self)
        self.keyvaluesupload = ApiClient("keyvalues/upload", self)
        self.keywords = ApiClient("keywords", self)
        self.layouts = ApiClient("layouts", self)
        self.lineitems = ApiClient("lineitems", self)
        self.mediachannels = ApiClient("mediachannels", self)
        self.mediaplans = ApiClient("mediaplans", self)
        self.networkforecast = ApiClient("networkforecast", self)
        self.networkprofiles = ApiClient("networkprofiles", self)
        self.networks = ApiClient("networks", self)
        self.notifications = ApiClient("notifications", self)
        self.notificationpreferences = ApiClient("notificationpreferences", self)
        self.orders = ApiClient("orders", self)
        self.predict = ApiClient("stats/predict", self)
        self.reachestimate = ApiClient("reachestimate", self)
        self.reports = ApiClient("reports", self)
        self.reportschedules = ApiClient("reportschedules", self)
        self.reporttemplates = ApiClient("reporttemplates", self)
        self.roles = ApiClient("roles", self)
        self.search = ApiClient("search", self)
        self.sites = ApiClient("sites", self)
        self.teams = ApiClient("teams", self)
        self.stats = ApiClient("stats", self)
        self.tiers = ApiClient("tiers", self)
        self.traffic = ApiClient("stats/traffic", self)
        self.userprofiles = ApiClient("userprofiles", self)
        self.user = ApiClient("user", self)
        self.users = ApiClient("users", self)
        self.segments = ApiClient("segments", self)
        self.segmentsupload = ApiClient("segments/upload", self)
        self.segmentsusersupload = ApiClient("segments/users/upload", self)
        self.workspaces = ApiClient("workspaces", self)
        self.zippedassets = ApiClient("zippedassets", self)
        self.devices = ApiClient("devices", self)
        self.sitegroups = ApiClient("sitegroups", self)


class ApiClient:
    """
    This class provides convenience methods for a specific API endpoint.
    Typically this class would not be used directly. Instead access the endpoints via the Api class.
    """

    def __init__(self, resourceName, apiContext, version="/v1"):
        """
        Construct the api endpoint client.
        :param resourceName:    name of the endpoint on the url
        :param apiContext:      Api class to provide context
        :param version:         api version for the url
        :return:
        """
        self.resourceName = resourceName
        self.api = apiContext
        self.authorisation = None
        self.version = version
        self.baseUrl = self.api.location
        self.session = requests.Session()

    def get(self, objectId, args={}):
        """
        Perform a GET request for the supplied object id.
        :param objectId:    object id used to construct the url
        :param args:        optional dictionary of query parameters
        :return:            dictionary of the JSON object returned
        """
        headers = self.auth()
        headers['Accept-Encoding'] = 'gzip'
        r = self.handle_err(self.session.get(self.baseUrl + self.version + "/" + self.resourceName + "/" + objectId,
                                             headers=headers,
                                             params=dict(self.api.defaultArgs.items() + args.items())))
        if r.text == '':
            return None
        else:
            return r.json()

    def post(self, objectId=None, data={}, args={}):
        """
        Perform a POST request for the supplied object id.
        :param objectId:    object id used to construct the url
        :param data:        optional dictionary of form parameters
        :param args        optional dictionary of query parameters
        :return:            dictionary of the JSON object returned
        """
        headers = self.auth()
        headers['Accept-Encoding'] = 'gzip'

        url = self.baseUrl + self.version + "/" + self.resourceName + "/" + objectId

        r = self.handle_err(self.session.post(url,
                                             headers=headers,
                                              data=data, params=dict(self.api.defaultArgs.items() + args.items())))
        if r.text == '':
            return None
        else:
            return r.json()

    def query(self, args={}):
        """
        Perform a query (a GET from an endpoint without a specific object ID).
        :param args:        optional dictionary of query parameters
        :return:            dictionary containing a 'results' key holding a list of results
        """
        headers = self.auth()
        headers['Accept-Encoding'] = 'gzip'
        r = self.handle_err(self.session.get(self.baseUrl + self.version + "/" + self.resourceName,
                                             headers=headers,
                                             params=dict(self.api.defaultArgs.items() + args.items())))
        if r.text == '':
            return None
        else:
            return r.json()

    def run(self, data, args={}):
        """
        Perform a query requiring a request body to be sent (i.e. requires POST rather than GET).
        :param data:        dictionary to be converted to json to post
        :param args:        query parameters
        :return:            dictionary containing a 'results' key holding a list of results
        """
        headers = self.auth()
        headers['Content-Type'] = 'application/json'
        headers['Accept-Encoding'] = 'gzip'
        return self.handle_err(self.session.post(self.baseUrl + self.version + "/" + self.resourceName,
                                                 headers=headers,
                                                 data=json.dumps(data),
                                                 params=dict(self.api.defaultArgs.items() + args.items()))).json()

    def update(self, payload, args={}, ignore=set()):
        """
        Updates an object. The supplied object payload must contain an 'id' of the object which is used to construct the url.
        :param payload:     dictionary containing the object's values
        :param args:        optional dictionary of query parameters
        :param ignore:      optional set of keys to ignore when comparing the posted JSON to the response JSON.
        :return:            the JSON response from the endpoint (usually contains the entire updated object).
        """
        if 'id' not in payload:
            raise ValueError("Payload must have an id")

        dumps = json.dumps(payload)
        url = self.baseUrl + self.version + "/" + self.resourceName + "/" + payload['id']
        headers = self.auth()
        headers['Content-Type'] = 'application/json'
        headers['Accept-Encoding'] = 'gzip'
        r = self.handle_err(self.session.post(url,
                                              headers=headers,
                                              data=dumps,
                                              params=dict(self.api.defaultArgs.items() + args.items())))
        if self.api.verify:
            assert compare_api_json_equal(payload, json.loads(r.text), set(self.api.defaultIgnore).union(ignore))
        if r.text == '':
            return None
        else:
            return r.json()

    def auth(self):
        """
        Returns the authorisation header for api access. Used internally.
        """
        if not self.authorisation:
            if self.api.apiKey:
                self.authorisation = {'Authorization': 'Bearer ' + self.api.apiKey}
            elif self.api.username:
                data = {'grant_type': 'password',
                        'scope': 'ng_api',
                        'username': self.api.username,
                        'password': self.api.password}

                endpoint = "/authenticate"

                if self.api.masquerade_user:
                    data.update({'masqueradeUser': self.api.masquerade_user})
                    endpoint = "/masquerade"

                payload = json.dumps(data)

                r = self.handle_err(self.session.post(self.baseUrl + endpoint, data=payload, params=self.api.defaultAuthArgs,
                                                      headers={'Content-Type': 'application/json'}))
                response = r.json()
                if 'access_token' not in response:
                    raise RuntimeError("API authentication failed in POST " + r.url)
                self.authorisation = {'Authorization': 'Bearer ' + response['access_token']}
            else:
                self.authorisation = {}

        return self.authorisation

    @staticmethod
    def handle_err(r):
        """
        Checks the status code of an HTTP response and raises an exception if it is an error. Used internally.
        """
        try:
            r.raise_for_status()
            return r
        except requests.exceptions.HTTPError as httpError:
            err = RuntimeError("API Error " + str(r.request.method) + " " + str(r.url) + " response " + str(r.status_code) + " " + str(r.text))
            err.httpError = httpError
            raise err

    def upload_resource(self, parent, id, resource_path, content_type, args={}):
        """
        Upload a file to an API endpoint.
        :param parent:          the sub-resource name to upload to
        :param id:              the id of the object to update
        :param resource_path:   path to the file on the local filesystem
        :param content_type:    mime content type of the file
        :param args:            optional dictionary of query parameters
        :return:                dictionary of the JSON object returned
        """
        if parent is None:
            url = self.baseUrl + self.version + "/" + self.resourceName + "/" + id
        else:
            url = self.baseUrl + self.version + "/" + self.resourceName + "/" + parent + "/" + id

        m = MultipartEncoder({'file': (os.path.basename(resource_path), read_binary(resource_path), content_type)})

        r = self.handle_err(self.session.post(
            url,
            data=m,
            headers=dict(self.auth().items() + {'Content-Type': m.content_type}.items()),
            params=dict(self.api.defaultArgs.items() + args.items())))
        if r.text == '':
            return None
        else:
            return r.json()

    def upload(self, resource_path, args={}):
        """
        Upload a file to an API endpoint.
        :param resource_path:   path to the file on the local filesystem
        :param args:            optional dictionary of query parameters
        :return:                dictionary of the JSON object returned
        """
        url = self.baseUrl + self.version + "/" + self.resourceName
        files = {'file': read_text(resource_path)}
        r = self.handle_err(self.session.post(
            url,
            files=files,
            headers=self.auth(),
            params=dict(self.api.defaultArgs.items() + args.items())))
        if r.text == '':
            return None
        else:
            return r.json()


class AdServer:
    """
    Provides access to the Adnuntius ad server.
    """

    def __init__(self, base_url):
        """
        Construct the class.
        :param base_url:    URL of the ad server host, for example "http://adserver.adnuntius.com"
        """
        self.base_url = base_url
        self.session = requests.Session()

    def request_ad_unit(self, ad_unit, cookies=None, headers=None, extra_params=None):
        """
        Makes a request for an ad unit.
        :param ad_unit:       the id of the ad unit.
        :param cookies:       optional dictionary of cookies
        :param headers:       optional dictionary of headers
        :param extra_params:  optional dictionary of query parameters
        :return:              the python requests response object. Response content can be accessed using response.text
        """
        if not cookies:
            cookies = {}
        if not headers:
            headers = {}
        if not extra_params:
            extra_params = {}
        headers['Accept-Encoding'] = 'gzip'
        parameters = {'auId': ad_unit}
        parameters.update(extra_params)
        r = self.session.get(self.base_url + "/i", params=parameters, cookies=cookies, headers=headers)
        return r

    def request_ad_units(self, ad_units, cookies=None, headers=None, extra_params=None, meta_data=None, key_values = None):
        """
        Makes a request for multiple ad units using a composed ad tag.
        :param ad_units: the ids of the ad unit.
        :param cookies:  optional dictionary of cookies
        :param headers:  optional dictionary of headers
        :param extra_params:  optional dictionary of parameters to include in composed request
        :return:         the python requests response object. Response content can be accessed using response.text
        """
        if not cookies:
            cookies = {}
        if not meta_data:
            meta_data = {}
        final_headers = {'Content-type': 'application/json', 'Accept-Encoding': 'gzip'}
        if headers:
            final_headers.update(headers)
        data = { 'adUnits': [], 'metaData': meta_data }
        json.dumps(data)

        for auId in ad_units:
            adunit = {'auId': auId, 'targetId': generate_id()}
            if key_values:
                adunit['kv'] = key_values

            data['adUnits'].append(adunit)

        if extra_params:
            data.update(extra_params)

        r = self.session.post(self.base_url + "/i", data=json.dumps(data), params={'tt': 'composed'}, cookies=cookies, headers=final_headers)
        return r

    def request_viewable_ad_unit(self, ad_unit, response_token, cookies=None, headers=None):
        """
        Makes a viewable impression request for an ad unit. This requires the ad unit to have previously been requested.
        :param ad_unit:        the id of the ad unit.
        :param response_token: the ad server token provided in the rt field of the original requests response object.
        :param cookies:        optional dictionary of cookies
        :param headers:        optional dictionary of headers
        :return:               the python requests response object. Response content can be accessed using response.text
        """
        if not cookies:
            cookies = {}
        if not headers:
            headers = {}
        parameters = {'auId': ad_unit}
        parameters.update({'rt': response_token})
        r = self.session.get(self.base_url + "/v", params=parameters, cookies=cookies, headers=headers)
        return r

    def set_retarget_key_values(self, network_id, key_values, expiry):
        """
        Sets some re-targeting key-values on the user's cookie
        :param network_id:     the network id
        :param key_values:     a map of the key-values
        :return:               the python requests response object. Response content can be accessed using response.text
        """
        data = {
            'network': network_id,
            'keyValues': []
        }
        for key in key_values:
            data['keyValues'].append(
                {
                    'key': key,
                    'value': key_values[key],
                    'expiry': expiry
                }
            )
        r = self.session.post(self.base_url + "/r", data=json.dumps(data))
        return r

    def trigger_conversion(self, conversion_event=None, network_id=None, source_id=None, headers=None):
        """
        Triggers a conversion event
        :return:               the python requests response object. Response content can be accessed using response.text
        """
        if not headers:
            headers = {}

        data = {
            'network': network_id,
            'adSource': source_id,
            'eventType': conversion_event
        }
        r = self.session.post(self.base_url + "/pixelc.gif", data=json.dumps(data), headers=headers)
        return r

    def trigger_event(self, url):
        """
        Triggers an event by requesting a URL. Uses the ad-server session so that cookies are shared.
        :param url:
        :return:
        """
        if url[0:2] == '//':
            url = "http:" + url
        r = self.session.get(url, allow_redirects=False)
        return r

    def post_event(self, url, event):
        """
        Triggers a event by POST data
        :return: the python requests response object. Response content can be accessed using response.text
        """
        if url[0:2] == '//':
            url = "http:" + url
        r = self.session.post(url, allow_redirects=False, data=json.dumps(event))
        return r

    def clear_cookies(self):
        """
        Clears cookies from this session
        :return:
        """
        self.session.cookies.clear()

    def set_consent(self, network_id, consent):
        """
        Sets consents on the user's cookie
        :param network_id:     the network id
        :param consent:        a list of consents
        :return:               the python requests response object. Response content can be accessed using response.text
        """
        data = {
            'network': network_id,
            'consent': []
        }
        if isinstance(consent, basestring):
            data['consent'].append(consent)
        else:
            for c in consent:
                data['consent'].append(c)
        return self.session.post(self.base_url + "/consent", data=json.dumps(data))

    def get_consent(self, network_id):
        """
        Gets the consent set on a user's cookie.
        :param network_id:     the network id
        :return:               the python requests response object. Response content can be accessed using response.text
        """
        return self.session.get(self.base_url + "/consent?network=" + network_id)
