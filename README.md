# Fastly NGWAF Request Count Dashboard

A very small local Node.js dashboard for testing Fastly NGWAF request count queries.

## Requirements

- Node.js 18 or newer
- A Fastly API key with access to the NGWAF workspace

## Setup

Install dependencies:

```sh
npm install
```

Create a local environment file:

```sh
cp .env.example .env
```

Edit `.env`:

```sh
FASTLY_API_KEY=your_fastly_api_key
FASTLY_WORKSPACE_ID=your_workspace_id
REQUEST_DELAY_MS=250
ALLOWED_IPS=
INTERNAL_PASSWORD=
```

`REQUEST_DELAY_MS` is optional and defaults to `250` when it is not set.
If Fastly starts returning transient `500` responses while testing, try a larger value such as `1000` or `2000`.

`ALLOWED_IPS` is optional. When set, use a comma-separated list of allowed client IPs:

```sh
ALLOWED_IPS=127.0.0.1,203.0.113.10
```

The app checks the first IP in `X-Forwarded-For` when that header is present, otherwise it falls back to the direct request IP.

`INTERNAL_PASSWORD` is optional. When set, the dashboard requires the shared password before showing the query form:

```sh
INTERNAL_PASSWORD=change-me
```

## Run

```sh
npm start
```

Open:

```text
http://localhost:3000
```

For development with Node's watch mode:

```sh
npm run dev
```

## Notes

- The dashboard uses Express, EJS, dotenv, and Tailwind via CDN.
- There is no database, background job system, or frontend framework.
- Optional IP allowlisting and a simple shared internal password can be enabled with environment variables.
- API queries are run sequentially with a configurable delay between requests.
- Results are added to the table as each query completes.
- Transient Fastly `5xx` responses are retried once before the row is shown as an error.
- The Fastly API key is only read server-side and is not rendered in the UI.
- The workspace ID is displayed in the page header so it is clear which workspace is being queried.
