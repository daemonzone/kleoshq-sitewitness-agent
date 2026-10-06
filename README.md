# SiteWitness Agent

A serverless ingestion API that receives SiteWitness event reports, validates them via HMAC signatures, deduplicates events, and triggers asynchronous processing.

## Overview

This project provides a webhook endpoint (`/api/ingest/[slug]`) that:

1. **Receives** JSON event payloads from SiteWitness
2. **Validates** HMAC signatures using source credentials
3. **Deduplicates** events based on payload hash and idempotency key
4. **Stores** validated events in a PostgreSQL database (Neon)
5. **Triggers** an external processor webhook after successful ingestion

## Architecture

- **Framework**: Vercel serverless functions
- **Database**: Neon PostgreSQL (event storage)
- **Auth**: Supabase (source credential management)
- **Validation**: HMAC-SHA256 signatures
- **Deduplication**: Idempotency key + payload hash

## Environment Variables

Create a `.env` file (copy from `.env.sample`):

```bash
# Database connection (Neon PostgreSQL)
DATABASE_URL=postgresql://user:password@host/dbname?sslmode=require&channel_binding=require

# Supabase — server-side (service_role bypasses RLS)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SECRET_KEY=your-service-role-key

# Processor webhook URL (triggered after ingestion commits)
PROCESSOR_URL=https://your-processor-url/api/process
```

## Installation

```bash
npm install
```

## API Endpoint

### POST `/api/ingest/[slug]`

Receives event reports from a SiteWitness source.

**Path Parameters:**
- `slug` (string, required): Source identifier

**Headers:**
- `Content-Type`: `application/json`
- `x-sitewitness-signature`: HMAC-SHA256 signature (`sha256=<hex>`)
- `x-sitewitness-host`: Target host/domain

**Request Body:**
```json
{
  "type": "report_type",
  "data": { ... }
}
```

**Response (Success):**
```json
{
  "ok": true
}
```

**Response (Duplicate):**
```json
{
  "ok": true,
  "duplicate": true
}
```

**Error Responses:**
- `400`: Invalid content type, missing headers, invalid JSON
- `401`: Invalid HMAC signature
- `403`: Unknown source
- `405`: Method not allowed
- `500`: Server error

## Workflow

1. **Signature Validation**: HMAC-SHA256 is verified against the source's secret key
2. **Deduplication**: Events are checked for duplicates using an idempotency key
3. **Database Commit**: Valid, new events are inserted into the `ingestions` table
4. **Processor Trigger**: After commit, an asynchronous webhook is sent to `PROCESSOR_URL`
5. **Response**: Client receives success response immediately (non-blocking)

## Database Schema

The ingestion event is stored in the `ingestions` table:

```sql
CREATE TABLE ingestions (
  id BIGSERIAL PRIMARY KEY,
  site_identifier VARCHAR,
  source_id VARCHAR,
  idempotency_key VARCHAR UNIQUE,
  payload BYTEA,
  event_type VARCHAR,
  created_at TIMESTAMP DEFAULT NOW()
);
```

## Development

Run tests or start a local development server:

```bash
npm run dev
```

## Logging

The API uses console logging for debugging:

- `📥` — Incoming event delivery
- `💾` — Event stored successfully
- `🔄` — Processor webhook triggered
- Error logs for signature failures, deduplication, and system errors

## Security Considerations

- **HMAC Validation**: Uses timing-safe comparison to prevent timing attacks
- **Gzip Decompression**: Supports optional gzip-compressed payloads
- **Transaction Safety**: Uses database transactions for atomicity
- **Idempotency**: Duplicate events are silently dropped (safe retry semantics)
- **Fire-and-Forget Processing**: Processor trigger failures don't fail the ingestion

## Deployment

This project is designed for Vercel serverless deployment:

```bash
vercel deploy
```

Ensure all environment variables are set in your Vercel project settings.

## License

Proprietary
