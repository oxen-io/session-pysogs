# Example:

```http
GET /room/sudoku HTTP/1.1
Host: example.com
```

```json
{
  "active_users": 8471519,
  "active_users_cutoff": 604800,
  "admins": [
    "050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  ],
  "created": 1645556525.154345,
  "description": "All the best sodoku discussion!",
  "info_updates": 341,
  "message_sequence": 45091759,
  "moderators": [
    "05fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
    "05ffffeeeeddddccccbbbbaaaa9999888877776666555544443333222211110000"
  ],
  "name": "Sudoku Solvers Club",
  "read": true,
  "token": "sudoku",
  "upload": true,
  "write": true
}
```
