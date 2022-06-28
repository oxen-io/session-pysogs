# Example retrieving capabilities:

```http
GET /capabilities HTTP/1.1
Host: example.com
```

```json
{
  "capabilities": ["sogs", "batch"]
}
```

# Example with capability check

```http
GET /capabilities?required=magic,batch HTTP/1.1
```

```json
{
  "capabilities": ["sogs", "batch"],
  "missing": ["magic"]
}
```
