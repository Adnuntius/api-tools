"""Api utilities for the Adnuntius APIs."""

__copyright__ = "Copyright (c) 2018 adNuntius AS.  All rights reserved."

import datetime
import uuid

import dateutil


def strToDate(str):
    """
    Converts a string-format date from the API into a python datetime.
    """
    return None if (str is None or str == '') else dateutil.parser.parse(str)


def date_to_string(date):
    """
    Converts a python datetime into the string format required by the API.
    """
    tzdate = date

    if not isinstance(tzdate, datetime.datetime) and isinstance(tzdate, datetime.date):
        # it's not a datetime, so make a datetime with a time of 0
        tzdate = datetime.datetime.combine(date, datetime.time())

    if tzdate.tzinfo is not None and tzdate.tzinfo != dateutil.tz.tzutc():
        raise ValueError("Date must have UTC tz")

    # clear the timezone info
    tzdate = tzdate.replace(tzinfo=None)

    return tzdate.isoformat() + "Z"


def id_reference(obj):
    """
    Returns a dictionary containing an 'object reference' which is required by the API in some cases.
    :param obj: if obj is a string it is used as the object id, otherwise it is assumed to be a dictionary containing an 'id' key
    :return:    a
    """
    return {'id': str(obj)} if isinstance(obj, basestring) else {'id': obj['id']}


def generate_id():
    return str(uuid.uuid4())


def read_text(path):
    with open(path) as theFile:
        return "".join(line for line in theFile)


def read_binary(path):
    with open(path) as theFile:
        return theFile.read()
