require('dotenv').config();
const crypto = require('crypto');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');

export const config = {
  api: { bodyParser: false }
};

// ─── Neon pool (event writes) ─────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 1,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 5000,
});

// ─── HMAC validation ──────────────────────────────────────────────
function verifySignature(jsonBody, signature, secret) {
  const sigValue = signature.startsWith('sha256=') ? signature.slice(7) : signature;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(jsonBody)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'utf8'),
      Buffer.from(sigValue,  'utf8')
    );
  } catch {
    return false;
  }
}

// ─── Payload hash ─────────────────────────────────────────────────
function computePayloadHash(rawBody) {
  return crypto.createHash('sha256').update(rawBody).digest('hex');
}

// ─── Raw body ─────────────────────────────────────────────────────
async function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end',  () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ─── Handler ──────────────────────────────────────────────────────
module.exports = async function handler(req, res) {

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/json')) {
    return res.status(400).json({ error: 'Invalid content type' });
  }

  const { slug } = req.query;
  console.log(`Slug: ${slug}`);
  if (!slug) {
    return res.status(400).json({ error: 'Missing source slug' });
  }

  const rawBody  = await getRawBody(req);
  const signature = req.headers['x-sitewitness-signature'];
  const host      = req.headers['x-sitewitness-host'];

  if (!signature || !host) {
    console.log('Missing valid headers');
    return res.status(400).json({ error: 'Missing headers' });
  }

  // ── Decompress if gzip ──────────────────────────────────────────
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

  // ── Load source from Supabase ───────────────────────────────────
  let sourceRecord;

  try {
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SECRET_KEY;

    console.log('SUPABASE_URL:', supabaseUrl);
    console.log('SUPABASE_SECRET_KEY:', supabaseKey ? '(set)' : '(missing)');

    const supabase = createClient(supabaseUrl, supabaseKey);

    const { data, error } = await supabase
      .from('sources')
      .select('id, hmac, enabled')
      .eq('id', slug)
      .eq('enabled', true)
      .single();

    if (error || !data) {
      console.error('Source not found in Supabase:', error?.message);
      return res.status(403).json({ error: 'Unknown source' });
    }

    sourceRecord = data;
    console.log('Source found:', sourceRecord.id);

  } catch (err) {
    console.error('Supabase error:', err.message);
    return res.status(500).json({ error: 'Supabase error' });
  }

  // ── Verify HMAC ─────────────────────────────────────────────────
  if (!verifySignature(jsonBody, signature, sourceRecord.hmac)) {
    console.error('Signature is NOT valid');
    return res.status(401).json({ error: 'Invalid signature' });
  }
  console.log('Signature is valid');

  // ── Parse payload ───────────────────────────────────────────────
  let payload;
  try {
    payload = JSON.parse(jsonBody.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  // ── Derive fields ───────────────────────────────────────────────
  const payloadHash    = computePayloadHash(jsonBody);
  const idempotencyKey = `${slug}-${sourceRecord.id}-${payloadHash}`;
  const eventType      = 'sitewitness_report';
  const aggregateType  = payload.type || eventType;

  console.log(`📥 [${eventType}] ${aggregateType} delivery: ${payloadHash}`);

  // ── Write to Neon ───────────────────────────────────────────────
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const dedup = await client.query(
      `INSERT INTO ingestions (site_identifier, source_id, idempotency_key, payload, event_type)
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
    return res.status(200).json({ ok: false });
  } finally {
    client.release();
  }
};
