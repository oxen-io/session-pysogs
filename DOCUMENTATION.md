All endpoints return the status code in the response body because that's the only way to propagate the status code back to the client when using onion requests.

## Endpoints

### GET /rooms/:room_id

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | No       |       |
| Room          | No       |       |

Returns information about the room with the given ID.

**Response:**

```
{
    status_code: u16,
    room: {
        id: String,
        name: String
    }
}
```

### GET /rooms

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | No       |       |
| Room          | No       |       |

Returns a list of all rooms on the server.

**Response:**

```
{
    status_code: u16,
    rooms: [
        {
            id: String,
            name: String
        },
        ...
    ]
}
```

### POST /files

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | Yes      | Basic |
| Room          | Yes      |       |

Store a file on the server.

**Expected body:**

```
{
    file: String // base64 encoded data
}
```

**Response:**

```
{
    status_code: u16
}
```

### POST /rooms/:room_id/image

| Header        | Required | Notes     |
| ------------- | -------- | --------- |
| Authorization | Yes      | Moderator |
| Room          | No       |           |

Set the image for a room.

**Expected body:**

```
{
    file: String // base64 encoded data
}
```

**Response:**

```
{
    status_code: u16,
    room_id: String
}
```

### GET /files/:file_id

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | Yes      | Basic |
| Room          | Yes      |       |

Get a file from the server.

**Response:**

```
{
    status_code: u16,
    result: String // base64 encoded data
}
```

### GET /rooms/:room_id/image

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | No       |       |
| Room          | No       |       |

Returns the preview image for the given group.

**Response:**

```
{
    status_code: u16,
    result: String // base64 encoded data
}
```

### GET /auth_token_challenge?public_key=string

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | No       |       |
| Room          | Yes      |       |

Get an auth token challenge. The requesting user generates a symmetric key from the ephemeral public key returned by the server and their private key, which can be used to decrypt the ciphertext and get the auth token.

**Response:**

```
{
    status_code: u16,
    challenge: {
        ciphertext: String, // base64 encoded data
        ephemeral_public_key: String // base64 encoded data
    }
}
```

### POST /claim_auth_token

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | Yes      | Basic |
| Room          | Yes      |       |

Claim the auth token in the `Authorization` header.

**Expected body:**

```
{
    public_key: String
}
```

**Response:**

```
{
    status_code: u16
}
```

### DELETE /auth_token

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | Yes      | Basic |
| Room          | Yes      |       |

Delete the auth token in the `Authorization` header.

**Response:**

```
{
    status_code: u16
}
```

### POST /compact_poll
| Header        | Required | Notes                                                                |
| ------------- | -------- | -------------------------------------------------------------------- |
| Authorization | No       | Authorization is handled on a room-by-room basis in the request body |
| Room          | No       |                                                                      |

Poll for new messages, new deletions and the current moderator list for multiple rooms all in one request.

**Expected body:**

```
{
    requests: [
        {
            room_id: String,
            auth_token: String,
            from_deletion_server_id: Option<i64>,
            from_message_server_id: Option<i64>
        },
        {
            ...
        }
    ]
}
```

**Response:**

```
{
    status_code: u16
    results: [
        {
            room_id: String,
            status_code: u16,
            deletions: [
                {
                    deletion_server_id: i64,
                    deleted_message_id: i64
                },
                {
                    ...
                }
            ]
            messages: [
                {
                    server_id: i64,
                    public_key: String,
                    timestamp: i64,
                    data: String,
                    signature: String
                },
                {
                    ...
                }
            ]
            moderators: [ "public_key_0", "public_key_1", "public_key_2", ... ]
        },
        {
            ...
        }
    ]
}
```

### POST /messages

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | Yes      | Basic |
| Room          | Yes      |       |

Store the given message on the server.

**Expected body:**

```
{
    public_key: Option<String>, // the public key of the sender
    timestamp: i64, // the sent timestamp of the message
    data: String, // the serialized protobuf
    signature: String // the base64 encoded message signature
}
```

**Response:**

```
{
    status_code: u16
    message: {
        server_id: String,
        public_key: Option<String>
        timestamp: i64
        data: String
        signature: String
    }
}
```

### GET /messages?from_server_id=i64&limit=u16

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | Yes      | Basic |
| Room          | Yes      |       |

Get messages from the server. If `from_server_id` is set only messages stored after that server ID are returned (limited to a maximum of 256 messages). Otherwise, if `limit` is set, the last `limit` messages stored on the server are returned (limited to a maximum of 256 messages).

**Response:**

```
{
    status_code: u16,
    messages: [
        {
            server_id: String,
            public_key: Option<String>, // the public key of the sender
            timestamp: i64, // the sent timestamp of the message
            data: String, // the serialized protobuf
            signature: String // the base64 encoded message signature
        },
        ...
    ]
}
```

### POST /delete_messages

| Header        | Required | Notes              |
| ------------- | -------- | ------------------ |
| Authorization | Yes      | Basic OR Moderator |
| Room          | Yes      |                    |

Deletes the messages with the given IDs from the server. The requesting user must either be the sender of the messages or have moderation permission.

**Expected body:**

```
{
    ids: [ 0, 1, 2, ... ], // the server IDs of the messages to delete
}
```

**Response:**

```
{
    status_code: u16
}
```

### DELETE /messages/:message_id

| Header        | Required | Notes              |
| ------------- | -------- | ------------------ |
| Authorization | Yes      | Basic OR Moderator |
| Room          | Yes      |                    |

Delete the message with the given ID from the server. The requesting user must either be the sender of the message or have moderation permission.

**Response:**

```
{
    status_code: u16
}
```

### GET /deleted_messages?from_server_id=i64&limit=u16

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | Yes      | Basic |
| Room          | Yes      |       |

Get deleted messages from the server. If `from_server_id` is set only deletions that happened after that server ID are returned (limited to a maximum of 256 deletions). Otherwise, if `limit` is set, the last `limit` deletions stored on the server are returned (limited to a maximum of 256 deletions).

**Response:**

```
{
    status_code: u16,
    ids: [
        {
            deletion_server_id: i64,
            deleted_message_id: i64
        },
        {
            ...
        }
    ]
}
```

### GET /moderators

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | Yes      | Basic |
| Room          | Yes      |       |

Get the full list of moderators.

**Response:**

```
{
    status_code: u16,
    moderators: [ "public_key_0", "public_key_1", "public_key_2", ... ]
}
```

### POST /block_list

| Header        | Required | Notes     |
| ------------- | -------- | --------- |
| Authorization | Yes      | Moderator |
| Room          | Yes      |           |

Ban the given public key from the server.

**Expected body:**

```
{
    public_key: String
}
```

**Response:**

```
{
    status_code: u16
}
```

### POST /ban_and_delete_all

| Header        | Required | Notes     |
| ------------- | -------- | --------- |
| Authorization | Yes      | Moderator |
| Room          | Yes      |           |

Ban the given public key from the server and delete all messages sent by them.

**Expected body:**

```
{
    public_key: String
}
```

**Response:**

```
{
    status_code: u16
}
```

### DELETE /block_list/:public_key

| Header        | Required | Notes     |
| ------------- | -------- | --------- |
| Authorization | Yes      | Moderator |
| Room          | Yes      |           |

Unban the given public key from the server.

**Response:**

```
{
    status_code: u16
}
```

### GET /block_list

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | Yes      | Basic |
| Room          | Yes      |       |

Get the full list of banned public_keys.

**Response:**

```
{
    status_code: u16,
    moderators: [ "public_key_0", "public_key_1", "public_key_2", ... ]
}
```

### GET /member_count

| Header        | Required | Notes |
| ------------- | -------- | ----- |
| Authorization | Yes      | Basic |
| Room          | Yes      |       |

Get the member count for the given room.

**Response:**

```
{
    status_code: u16,
    member_count: usize
}
```
