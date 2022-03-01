# Query Parameters

The request takes an optional `limit` query parameter indicating the number of messages to
return (up to 256).  If omitted, at most 100 messages are returned.

# Return value

Returns a JSON array of up to `limit` (default 100) messages, with oldest messages first.  Each
element is a JSON object with keys:

- `id` — the unique integer message id.
- `posted_at` — unix timestamp (float) when the message was received by SOGS.
- `expires_at` — unix timestamp (float) when SOGS will expire and delete the message.
- `message` — the encrypted message body.
- `sender` — the (blinded) Session ID of the sender of the message.
- `recipient` — the (blinded) Session ID of the recpient of the message.
