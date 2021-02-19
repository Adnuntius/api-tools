"""Utility code to compare json objects."""

__copyright__ = "Copyright (c) 2021 Adnuntius AS.  All rights reserved."


def compare_api_json_equal(payload, loaded, ignore, path=[]):
    """
    Compares a posted payload JSON to the response. Pre-processes both JSONs to exclude the ignored fields.
    Also ignores url parameter on objects and references, handles unicode.
    """

    are_equal = True

    uignore = to_unicode(set(ignore))
    if path != [] and set(loaded.keys()) == {'id', 'url'}:
        uignore.add('url')

    def assertTrue(condition, msg):
        if not condition:
            print(msg + " at path " + str(path))
            return False
        return True

    uloaded = to_unicode(loaded)
    upayload = to_unicode(payload)

    uloaded = {k: v for (k, v) in list(uloaded.items()) if k not in uignore}
    upayload = {k: v for (k, v) in list(upayload.items()) if k not in uignore}

    uloaded = normalise_json_testdata(uloaded, uignore)
    upayload = normalise_json_testdata(upayload, uignore)

    for k in set(uloaded.keys()).union(list(upayload.keys())):
        are_equal &= assertTrue(k in list(upayload.keys()), "Key <" + k + "> not in payload")
        are_equal &= assertTrue(k in list(uloaded.keys()), "Key <" + k + "> not in response")
        if k in list(upayload.keys()) and k in list(uloaded.keys()):
            payload_val = upayload[k]
            loaded_val = uloaded[k]
            are_equal &= compare_api_json_values_equal(payload_val, loaded_val, k, ignore, path)

    return are_equal


class hashabledict(dict):
    """
    A subclass of the standard python dict that supports hashing and so can be used as a key in another dictionary.
    """
    def __hash__(self):
        return hash(tuple(sorted(self.items())))


def normalise_json_testdata(obj, ignore):
    """
    Various normalisations of the JSON sourced test data:
    - make it immutable to avoid accidental manipulation of baseline values
    - remove any keys we want to ignore
    - lowercase any values with a key of "id" (since we always lowercase the external IDs in the hash)
    """
    if type(obj) == dict:
        # remove any keys we want to ignore
        obj = {k: v for k, v in list(obj.items()) if k not in ignore}

        # drop the URL key if we are only comparing object references
        if set(obj.keys()) == {'id', 'url'}:
            obj.pop('url')

        # lowercase the ID field if present
        if 'id' in obj and type(obj['id']) == str:
            obj['id'] = obj['id'].lower()

        # wrap in a hashabledict so we can use a standard dictionary as a key
        return hashabledict({(k, normalise_json_testdata(v, {i.replace(k + '.', '', 1) for i in ignore
                                                             if i.startswith(k + '.')})) for k, v in list(obj.items())})
    elif type(obj) == list:
        return frozenset({normalise_json_testdata(i, ignore) for i in obj})
    else:
        return obj


def compare_api_json_values_equal(payload_val, loaded_val, key, ignore, path):
    """
    Compares the values from a specific key in two dictionaries.
     If the values are dictionaries, recursively compares them using compare_api_json_equal.
    :param payload_val: value from the payload dictionary
    :param loaded_val:  value from the loaded dictionary
    :param key:         name of the key for the value
    :param ignore:      ignored keys
    :param path:        current path into the object graph in dotted notation
    :return:            true if equal
    """
    def assertTrue(condition, msg):
        if not condition:
            print(msg + " at path " + str(path))
            return False
        return True

    if type(payload_val) == hashabledict and type(loaded_val) == hashabledict:
        # descend and compare sub-objects
        sub_ignores = {i.replace(key + '.', '', 1) for i in ignore if i.startswith(key + '.')}
        return assertTrue(compare_api_json_equal(payload_val, loaded_val, sub_ignores, path + [key]),
                          "Key <" + key + "> Objects not equal")

    elif type(payload_val) == list and type(loaded_val) == list:
        raise RuntimeError("Shouldn't happen")
    else:
        return assertTrue(payload_val == loaded_val, "Key <" + key + "> Payload value <" + str(payload_val) +
                          "> not equal to loaded <" + str(loaded_val) + ">")


def to_unicode(obj):
    """
    Converts any string values into unicode equivalents.
    This is necessary to allow comparisons between local non-unicode strings and the unicode values returned by the api.
    :param obj:     a string to be converted to unicode, or otherwise a dict, list,
    set which will be recursively processed to convert strings to unicode
    :return:        a unicode version of obj
    """
    # recursively process dictionary keys and values or set/list items
    if type(obj) is dict:
        return {to_unicode(k): to_unicode(v) for k, v in list(obj.items())}
    elif type(obj) is list:
        return [to_unicode(v) for v in obj]
    elif type(obj) is set:
        return {to_unicode(v) for v in obj}
    elif type(obj) is str:
        return str(obj)
    else:
        return obj
