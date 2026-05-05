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
// We receive the gzip body, decompress it to get the JSON, then verify.
function verifySignature(jsonBody, signature, secret) {
  // Strip the "sha256=" prefix
  const sigValue = signature.startsWith('sha256=') ? signature.slice(7) : signature;

  const expected = crypto
    .createHmac('sha256', secret)
    .update(jsonBody)          // sign the JSON string, not the gzip bytes
    .digest('hex');            // PHP uses hex output

  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'utf8'),
      Buffer.from(sigValue,  'utf8')
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

  // Content-Type check
  const contentType = req.headers['content-type'] || '';

  if (!contentType.includes('application/json')) {
    return res.status(400).json({ error: 'Invalid content type' });
  }

  // URL: /api/ingest/<customer>
  const { slug } = req.query;
  console.log(`Slug: ${slug}`);

  if (!slug) {
    return res.status(400).json({ error: 'Missing source slug' });
  }

  console.log("Headers", req.headers);

  const rawBody = await getRawBody(req);

  const signature = req.headers['x-sitewitness-signature'];
  const host      = req.headers['x-sitewitness-host'];

  if (!signature || !host) {
    console.log(`Missing valid headers`);
    return res.status(400).json({ error: 'Missing headers' });
  }

  // Decompress if the body was gzip-encoded (PHP sends Content-Encoding: gzip).
  // The HMAC is computed over the raw JSON string, not the compressed bytes.
  let jsonBody;
  const contentEncoding = req.headers['content-encoding'] || '';
  if (contentEncoding.includes('gzip')) {
    try {
      jsonBody = require('zlib').gunzipSync(rawBody);
    } catch (err) {
      console.error('Decompression failed:', err.message);
      return res.status(400).json({ error: 'Failed to decompress body' });
    }
  } else {
    jsonBody = rawBody;
  }

  // ── Replay protection (5 min window)
  // const now = Math.floor(Date.now() / 1000);
  // if (Math.abs(now - Number(timestamp)) > 300) {
  //   return res.status(401).json({ error: 'Stale request' });
  // }

  // ── Load source
  let sourceRecord;

  try {
    const result = await pool.query(
      `SELECT * FROM sources
       WHERE slug = $1 AND active = true`,
      [slug]
    );

    if (result.rows.length === 0) {
      console.error("Source not found"); 
      return res.status(403).json({ error: 'Unknown source' });
    }

    sourceRecord = result.rows[0];

    console.log("Customer found");
    console.log(sourceRecord);

  } catch (err) {
    console.error('DB error:', err.message);
    return res.status(500).json({ error: 'DB error' });
  }

  // ── Verify HMAC
  if (!verifySignature(jsonBody, signature, sourceRecord.webhook_secret)) {
    console.error("Signature is NOT valid")
    return res.status(401).json({ error: 'Invalid signature' });
  }

  console.log("Signature is valid")

  // ── Parse payload
  let payload;

  try {
    payload = JSON.parse(jsonBody.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  // ── Derive fields
  const payloadHash    = computePayloadHash(jsonBody);
  const deliveryId = `${payloadHash}`;
  const idempotencyKey = `${slug}-${sourceRecord.id}-${deliveryId}`;
  const eventType = 'sitewitness_report';

  const aggregateType = payload.type || eventType; // snapshot | delta
  const aggregateId   = payload.site || null;

  console.log(`📥 [${eventType}] ${aggregateType} delivery: ${deliveryId}`);

  // ── Transaction
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Dedup
    const dedup = await client.query(
      `INSERT INTO ingestions (site_identifier, source_id, idempotency_key, 
       payload, event_type)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (site_identifier, source_id, idempotency_key) DO NOTHING
       RETURNING id`,
      [host, sourceRecord.id, idempotencyKey, jsonBody, eventType]
    );

    if (dedup.rows.length === 0) {
      await client.query('ROLLBACK');
      console.log('Duplicate ignored:', idempotencyKey);
      return res.status(200).json({ ok: true, duplicate: true });
    }

    await client.query('COMMIT');

    console.log(`💾 Stored event ${dedup.rows[0].id}`);

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