require('dotenv').config();
const crypto = require('crypto');
const { Pool } = require('pg');

export const config = {
  api: { bodyParser: false }
};

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 1,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 5000,
});

// ─── HMAC validation ─────────────────────────────────────────────
function verifySignature(rawBody, signature, secret) {
  const expected = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('base64');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected),
      Buffer.from(signature)
    );
  } catch {
    return false;
  }
}

// ─── Payload hash ────────────────────────────────────────────────
function computePayloadHash(rawBody) {
  return crypto
    .createHash('sha256')
    .update(rawBody)
    .digest('hex');
}

// ─── Raw body ────────────────────────────────────────────────────
async function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ─── Handler ─────────────────────────────────────────────────────
module.exports = async function handler(req, res) {

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Fail fast
  if (!req.headers['content-type']?.includes('application/json')) {
    return res.status(400).json({ error: 'Invalid content type' });
  }

  // URL: /api/ingest/<customer>
  const { slug } = req.query;

  if (!slug) {
    return res.status(400).json({ error: 'Missing source slug' });
  }

  const rawBody = await getRawBody(req);

  const signature  = req.headers['x-sim-signature'];
  const deliveryId = req.headers['x-sim-delivery-id'];
  const eventType  = req.headers['x-sim-event'] || 'snapshot';
  const timestamp  = req.headers['x-sim-timestamp'];

  if (!signature || !deliveryId || !timestamp) {
    return res.status(400).json({ error: 'Missing headers' });
  }

  // ── Replay protection (5 min window)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(timestamp)) > 300) {
    return res.status(401).json({ error: 'Stale request' });
  }

  // ── Load source
  let sourceRecord;

  try {
    const result = await pool.query(
      `SELECT * FROM sources
       WHERE slug = $1 AND platform = 'wp_drift' AND active = true`,
      [slug]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'Unknown source' });
    }

    sourceRecord = result.rows[0];

  } catch (err) {
    console.error('DB error:', err.message);
    return res.status(500).json({ error: 'DB error' });
  }

  // ── Verify HMAC
  if (!verifySignature(rawBody, signature, sourceRecord.webhook_secret)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // ── Parse payload
  let payload;

  try {
    payload = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  // ── Derive fields
  const idempotencyKey = `src${sourceRecord.id}-${deliveryId}`;
  const payloadHash    = computePayloadHash(rawBody);

  const aggregateType = payload.type || eventType; // snapshot | delta
  const aggregateId   = payload.site || null;

  console.log(`📥 [${eventType}] ${aggregateType} delivery:${deliveryId}`);

  // ── Transaction
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Dedup
    const dedup = await client.query(
      `INSERT INTO events_processed_keys (source_id, idempotency_key)
       VALUES ($1, $2)
       ON CONFLICT (source_id, idempotency_key) DO NOTHING
       RETURNING id`,
      [sourceRecord.id, idempotencyKey]
    );

    if (dedup.rows.length === 0) {
      await client.query('ROLLBACK');
      console.log('Duplicate ignored:', idempotencyKey);
      return res.status(200).json({ ok: true, duplicate: true });
    }

    // Insert event
    const result = await client.query(
      `INSERT INTO events
        (source_id, event_type, aggregate_type, aggregate_id, payload, payload_hash)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      [
        sourceRecord.id,
        eventType,
        aggregateType,
        aggregateId,
        payload,
        payloadHash
      ]
    );

    await client.query('COMMIT');

    console.log(`💾 Stored event ${result.rows[0].id}`);

    return res.status(200).json({ ok: true });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Transaction failed:', err.message);

    // important: return 200 to avoid retries storm
    return res.status(200).json({ ok: false });
  } finally {
    client.release();
  }
};