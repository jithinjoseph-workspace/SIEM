# NDR Per-User Page Permissions API Specification

Below is the complete API reference for developers to consume the newly added and updated backend permission endpoints.

---

## 1. POST `/api/auth/login`
Authenticates a user and issues a signed stateless JWT token containing their granular page permissions.

* **Method:** `POST`
* **Endpoint:** `/api/auth/login`
* **Request Payload (JSON):**
```json
{
  "username": "jithin_admin",
  "password": "password123"
}
```

* **Success Response (200 OK):**
```json
{
  "status": "ok",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "username": "jithin_admin",
    "role": "tenant_admin",
    "tenant_id": "acmes",
    "permissions": [
      "dashboard",
      "alerts",
      "logs",
      "live",
      "rules",
      "soar",
      "network-map",
      "intel",
      "health",
      "users"
    ]
  }
}
```

* **Error Response (200 OK):**
```json
{
  "status": "error",
  "message": "Invalid username or password"
}
```

---

## 2. POST `/api/auth/users`
Registers a new user under a tenant. You can optionally supply an explicit `"permissions"` list. If omitted, the backend automatically seeds the database with the standard defaults mapping for the chosen role.

* **Method:** `POST`
* **Endpoint:** `/api/auth/users`
* **Request Payload with Custom Permissions (JSON):**
```json
{
  "username": "analyst_bob",
  "password": "securepassword123",
  "role": "analyst",
  "tenant_id": "acmes",
  "permissions": [
    "dashboard",
    "alerts",
    "logs"
  ]
}
```

* **Request Payload relying on Role Defaults (JSON):**
```json
{
  "username": "viewer_alice",
  "password": "securepassword123",
  "role": "viewer",
  "tenant_id": "acmes"
}
```

* **Success Response (200 OK):**
```json
{
  "status": "ok",
  "message": "User analyst_bob created!"
}
```

* **Error Response (200 OK):**
```json
{
  "status": "error",
  "message": "Username and password required"
}
```

---

## 3. PUT `/api/auth/users/:id/permissions`
Overwrites the granular page-level permissions for a specific user. Updates are synchronous and immediate using ClickHouse ReplacingMergeTree inserts.

* **Method:** `PUT`
* **Endpoint:** `/api/auth/users/:id/permissions` (replace `:id` with the user's UUID string)
* **Headers:** `Authorization: Bearer <JWT_TOKEN>`
* **Request Payload (JSON):**
```json
{
  "permissions": [
    "dashboard",
    "alerts",
    "logs",
    "live"
  ]
}
```

* **Success Response (200 OK):**
```json
{
  "status": "ok"
}
```

* **Error Response (200 OK):**
```json
{
  "status": "error",
  "message": "Clickhouse connection failure..."
}
```

---

## 4. GET `/api/auth/users`
Retrieves the list of active users, their roles, tenants, and active permission list string.

* **Method:** `GET`
* **Endpoint:** `/api/auth/users`
* **Headers:** `Authorization: Bearer <JWT_TOKEN>`

* **Success Response (200 OK):**
```json
{
  "status": "ok",
  "users": [
    {
      "id": "e222aee9-3497-468f-8ca6-f43b7697d735",
      "username": "analyst_bob",
      "role": "analyst",
      "tenant_id": "acmes",
      "permissions": "dashboard,alerts,logs,live",
      "created_at": "2026-05-21 13:05:00"
    }
  ]
}
```

---

## 5. GET `/api/auth/me`
Decodes the active token from request header and returns profile state and active permissions.

* **Method:** `GET`
* **Endpoint:** `/api/auth/me`
* **Headers:** `Authorization: Bearer <JWT_TOKEN>`

* **Success Response (200 OK):**
```json
{
  "status": "ok",
  "user": {
    "username": "analyst_bob",
    "role": "analyst",
    "tenant_id": "acmes",
    "permissions": [
      "dashboard",
      "alerts",
      "logs",
      "live"
    ]
  }
}
```

---

## Appendix: Default Role Page Mappings

| Role | Automatically Assigned Page Permission Default String |
|---|---|
| `admin` / `super_admin` | `dashboard,alerts,logs,live,rules,soar,network-map,intel,settings,health,users,setup` |
| `tenant_admin` | `dashboard,alerts,logs,live,rules,soar,network-map,intel,health,users` |
| `analyst` | `dashboard,alerts,logs,live,network-map,intel,health` |
| `viewer` (and others) | `dashboard,alerts,health` |
