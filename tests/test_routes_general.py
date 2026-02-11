from sogs.model import capabilities as core_caps
from sogs import utils
from sogs.web import app


def test_capabilities(client):
    r = client.get("/capabilities")
    assert r.status_code == 200
    assert r.json == {"capabilities": sorted(core_caps)}

    r = client.get("/capabilities?required=sogs")
    assert r.status_code == 200
    assert r.json == {"capabilities": sorted(core_caps)}

    r = client.get("/capabilities?required=magic")
    assert r.status_code == 412
    assert r.json == {"capabilities": sorted(core_caps), "missing": ["magic"]}

    r = client.get("/capabilities?required=magic,sogs")
    assert r.status_code == 412
    assert r.json == {"capabilities": sorted(core_caps), "missing": ["magic"]}

    r = client.get("/capabilities?required=sogs,sogs")
    assert r.status_code == 200
    assert r.json == {"capabilities": sorted(core_caps)}


def expected_result(code, body, ct="application/json"):
    return {"code": code, "headers": {"content-type": ct}, "body": body}


def batch_data():
    reqs = [
        {"method": "GET", "path": "/capabilities"},
        {"method": "GET", "path": "/capabilities?required=magic"},
        {"method": "GET", "path": "/test_batch_2"},
        {"method": "GET", "path": "/test_batch_1", "headers": {"x-header-123": "zzz"}},
        {"method": "GET", "path": "/test_batch_1"},
        {"method": "GET", "path": "/test_batch_3"},
        {"method": "POST", "path": "/test_batch_4", "b64": 'aGVsbG8gd29ybGQ='},  # "hello world"
        {"method": "POST", "path": "/test_batch_4", "bytes": 'asdf\x00‽zzz'},
        {"method": "POST", "path": "/test_batch_4", "json": [1, 2, 3]},
        {"method": "GET", "path": "/test_batch_1?arg=456"},
    ]
    expected = [
        expected_result(200, {"capabilities": sorted(core_caps)}),
        expected_result(412, {"capabilities": sorted(core_caps), "missing": ["magic"]}),
        expected_result(403, {"z": 3}),
        expected_result(200, {"x": "zzz", "y": "N/A"}),
        expected_result(200, {"x": "def", "y": "N/A"}),
        expected_result(200, "YWJjZGVm", ct="application/octet-stream"),
        expected_result(
            200, utils.encode_base64(b'echo: hello world'), ct="text/plain; charset=utf-8"
        ),
        expected_result(
            200, utils.encode_base64('echo: asdf\x00‽zzz'.encode()), ct="text/plain; charset=utf-8"
        ),
        expected_result(200, {"echo": [1, 2, 3]}, ct="application/json"),
        expected_result(200, {"x": "def", "y": "456"}),
    ]
    return reqs, expected


def batch_data2():
    reqs = [
        {"method": "GET", "path": "/capabilities"},
        {"method": "GET", "path": "/capabilities?required=sogs"},
        {"method": "GET", "path": "/test_batch_1", "headers": {"x-header-123": "zzz"}},
        {"method": "GET", "path": "/test_batch_1"},
        {"method": "GET", "path": "/test_batch_3"},
        {"method": "POST", "path": "/test_batch_4", "b64": 'aGVsbG8gd29ybGQ='},  # "hello world"
        {"method": "GET", "path": "/test_batch_2"},
        {"method": "POST", "path": "/test_batch_4", "bytes": 'asdf\x00‽zzz'},
        {"method": "POST", "path": "/test_batch_4", "json": [1, 2, 3]},
        {"method": "GET", "path": "/test_batch_1?arg=456"},
    ]
    expected = [
        expected_result(200, {"capabilities": sorted(core_caps)}),
        expected_result(200, {"capabilities": sorted(core_caps)}),
        expected_result(200, {"x": "zzz", "y": "N/A"}),
        expected_result(200, {"x": "def", "y": "N/A"}),
        expected_result(200, "YWJjZGVm", ct="application/octet-stream"),
        expected_result(
            200, utils.encode_base64(b'echo: hello world'), ct="text/plain; charset=utf-8"
        ),
        expected_result(403, {"z": 3}),
        expected_result(
            200, utils.encode_base64('echo: asdf\x00‽zzz'.encode()), ct="text/plain; charset=utf-8"
        ),
        expected_result(200, {"echo": [1, 2, 3]}, ct="application/json"),
        expected_result(200, {"x": "def", "y": "456"}),
    ]

    return reqs, expected


def batch_data3():
    reqs, expected = batch_data2()
    reqs = list(reqs[i] for i in range(len(reqs)) if 200 <= expected[i]['code'] < 300)
    expected = list(expected[i] for i in range(len(expected)) if 200 <= expected[i]['code'] < 300)
    return reqs, expected


@app.get("/test_batch_1")
def batch_test_endpoint1():
    from flask import request, jsonify

    x = request.headers.get('X-Header-123', 'def')
    y = request.args.get('arg', 'N/A')
    return jsonify({"x": x, "y": y})


@app.get("/test_batch_2")
def batch_test_endpoint2():
    from flask import jsonify

    return jsonify({"z": 3}), 403


@app.get("/test_batch_3")
def batch_test_endpoint3():
    from flask import Response

    return Response(b'abcdef', mimetype='application/octet-stream')


@app.post("/test_batch_4")
def batch_test_endpoint4():
    from flask import request, jsonify, Response

    if request.is_json:
        return jsonify({"echo": request.json})
    return Response(f"echo: {request.data.decode()}".encode(), mimetype='text/plain')


def test_batch(client):
    d1, b1_exp = batch_data()
    b1 = client.post("/batch", json=d1)
    assert b1.json == b1_exp

    d2, b2_exp = batch_data2()
    b2 = client.post("/batch", json=d2)
    assert b2.json == b2_exp

    d3, b3_exp = batch_data3()
    b3 = client.post("/batch", json=d3)
    assert b3.json == b3_exp


def until_bad_code(batch_exp):
    seq_exp = []
    for e in batch_exp:
        seq_exp.append(e)
        if not 200 <= e['code'] < 300:
            break
    return seq_exp


def test_sequence(client):
    d1, b1_exp = batch_data()
    s1 = client.post("/sequence", json=d1)
    assert s1.json == until_bad_code(b1_exp)

    d2, b2_exp = batch_data2()
    s2 = client.post("/sequence", json=d2)
    assert s2.json == until_bad_code(b2_exp)

    d3, b3_exp = batch_data3()
    s3 = client.post("/sequence", json=d3)
    assert s3.json == until_bad_code(b3_exp)
