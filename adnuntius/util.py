"""Api utilities for the Adnuntius APIs."""

__copyright__ = "Copyright (c) 2021 Adnuntius AS.  All rights reserved."

import datetime
import uuid
import random

from dateutil.parser import parse
from dateutil.tz import tzutc

dns_cache = {}


def date_to_string(date):
    """
    Converts a python datetime into the string format required by the API.
    """
    tzdate = date

    if not isinstance(tzdate, datetime.datetime) and isinstance(tzdate, datetime.date):
        # it's not a datetime, so make a datetime with a time of 0
        tzdate = datetime.datetime.combine(date, datetime.time())

    if tzdate.tzinfo is not None and tzdate.tzinfo != tzutc():
        raise ValueError("Date must have UTC tz")

    # clear the timezone info
    tzdate = tzdate.replace(tzinfo=None)

    return tzdate.isoformat() + "Z"


# a random id used for identifiers for users and such, implements same basic
# algorithm as the UI
def generate_alphanum_id(length=16):
    letters = '012356789bcdfghjklmnpqrstvwxyz'

    password = ''
    for i in range(0, length):
        password += ''.join(random.sample(letters, 1))
    return password


def generate_id():
    return str(uuid.uuid4())


def id_reference(obj):
    """
    Returns a dictionary containing an 'object reference' which is required by the API in some cases.
    :param obj: if obj is a string it is used as the object id, otherwise a dictionary containing an 'id' key
    :return:    a
    """
    return {'id': str(obj)} if isinstance(obj, str) else {'id': obj['id']}


def read_text(path):
    with open(path) as theFile:
        return "".join(line for line in theFile)


def read_binary(path):
    with open(path, 'rb') as theFile:
        return theFile.read()


def str_to_date(string):
    """
    Converts a string-format date from the API into a python datetime.
    """
    return None if (string is None or string == '') else parse(string)
