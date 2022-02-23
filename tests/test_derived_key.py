def test_derived_key_generation(user):
    assert user.session_id is not None
    session_id = user.session_id
    derived = user.derived_key
    assert derived != session_id
    assert derived[0:2] == '15'
    assert session_id[0:2] == '05'
    assert derived[2:] != session_id[2:]
