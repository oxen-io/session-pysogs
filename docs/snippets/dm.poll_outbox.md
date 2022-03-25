# URL Parameters

- `msgid` — the numeric message ID of the last message.  (Newer messages will always
have a higher ID).
    
# Query Parameters

The request takes an optional `limit` query parameter indicating the number of messages to
return (up to 256).  If omitted, at most 100 messages are returned.
    
# Return value

This method, on success, returns *either* a 200 (OK) status code with a list of 1 or more new
messages, or else returns a 304 (Not Modified) response with an empty body to indicate that
there are no messages for this user newer than the given ID.

If there are messages this returns a JSON array of up to `limit` (default 100) messages, with
oldest messages first.  Each element is exactly as described in the [all messages](#GET-inbox)
endpoint.
