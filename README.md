# Todo REST API

A simple Express REST API for managing todos with persistence and validation.

## Setup

1. **Install dependencies**

   ```bash
   npm install
   ```

2. **Start the server**

   ```bash
   npm start
   ```

   The server will run on `http://localhost:3000` by default. Set the `PORT` environment variable to use a different port.

3. **Run in development mode** (with auto-reload)

   ```bash
   npm run dev
   ```

## Running Tests

```bash
npm test
```

## API Documentation

| Method | Endpoint | Description | Request Body | Success Response |
|--------|----------|-------------|--------------|------------------|
| GET | `/todos` | Retrieve all todos | — | `200 OK` array of todo objects |
| GET | `/todos/:id` | Retrieve a single todo by ID | — | `200 OK` todo object |
| POST | `/todos` | Create a new todo | `{ "title": string, "completed"?: boolean }` | `201 Created` todo object |
| PUT | `/todos/:id` | Replace a todo by ID | `{ "title": string, "completed"?: boolean }` | `200 OK` updated todo object |
| PATCH | `/todos/:id` | Partially update a todo by ID | `{ "title"?: string, "completed"?: boolean }` | `200 OK` updated todo object |
| DELETE | `/todos/:id` | Delete a todo by ID | — | `204 No Content` |

### Todo Object

```json
{
  "id": "string (UUID)",
  "title": "string",
  "completed": false,
  "createdAt": "ISO 8601 timestamp",
  "updatedAt": "ISO 8601 timestamp"
}
```

### Error Responses

| Status | Meaning |
|--------|---------|
| `400 Bad Request` | Validation failed (e.g. missing or invalid `title`) |
| `404 Not Found` | No todo exists with the given ID |
| `500 Internal Server Error` | Unexpected server error |

Error response body:

```json
{
  "error": "Human-readable error message"
}
```
