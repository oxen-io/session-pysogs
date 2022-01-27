from json import dumps
from auth import x_sogs_for


def sogs_get(client, url, user):
    """
    GETs a test `client` request to `url` with X-SOGS-* signature headers signing the request for
    `user`.
    """
    return client.get(url, headers=x_sogs_for(user, "GET", url))


def sogs_post(client, url, json, user):
    """
    POSTs a test `client` request to `url` with the given `json` as body and X-SOGS-* signature
    headers signing the request for `user`.
    """
    data = dumps(json).encode()

    return client.post(
        url, data=data, content_type='application/json', headers=x_sogs_for(user, "POST", url, data)
    )


def sogs_put(client, url, json, user):
    """
    PUTs a test `client` request to `url` with the given `json` as body and X-SOGS-* signature
    headers signing the request for `user`.
    """
    data = dumps(json).encode()

    return client.put(
        url, data=data, content_type='application/json', headers=x_sogs_for(user, "PUT", url, data)
    )
