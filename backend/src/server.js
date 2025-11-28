import cors from 'cors'
import express from 'express'
import { createHash, randomInt } from 'crypto'
import { pool, initDb } from './db.js'

const app = express()
const port = process.env.PORT || 4000
const isVercel = Boolean(process.env.VERCEL)
const PIN_SECRET = process.env.PIN_SECRET || 'tutuyu-pin-secret'

// CORS: allow local dev + any origin (public API)
app.use(
  cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: '*',
  }),
)
app.options('*', cors())
app.use(
  express.json({
    // Allow content payloads (e.g., base64 images) up to 20MB.
    limit: '20mb',
  }),
)

// Ensure database initialization happens before handling requests (including on Vercel lambdas).
const dbReady = initDb().catch((err) => {
  console.error('DB init failed', err)
  throw err
})
app.use((req, _res, next) => {
  dbReady.then(() => next()).catch(next)
})

const toShipment = (row) =>
  row && {
    ...row,
    quantity: Number(row.quantity) || 0,
    weight: Number(row.weight) || 0,
    price: Number(row.price) || 0,
    paid_amount: Number(row.paid_amount) || 0,
    balance: Number(row.balance) || 0,
  }

const normalizePhone = (phone) => (phone || '').replace(/\D+/g, '')
const hashPin = (phone, pin) => createHash('sha256').update(`${PIN_SECRET}:${phone}:${pin}`).digest('hex')

const fetchShipmentWithPin = async (id) => {
  const row = (
    await pool.query(
      `
      SELECT s.*, cp.pin_plain
      FROM shipments s
      LEFT JOIN customer_pins cp
        ON regexp_replace(cp.phone, '\\D', '', 'g') = regexp_replace(s.phone, '\\D', '', 'g')
      WHERE s.id = $1
    `,
      [id],
    )
  ).rows[0]
  if (row && !row.pin_plain && row.phone) {
    const { pin } = await ensurePinForPhone(row.phone, { exposePin: true })
    if (pin) row.pin_plain = pin
  }
  return row
}

const ensurePinForPhone = async (phone, { exposePin = false } = {}) => {
  const normalized = normalizePhone(phone)
  if (!normalized) return { created: false }
  const existing = await pool.query('SELECT pin_hash, pin_plain FROM customer_pins WHERE phone = $1', [normalized])
  if (existing.rowCount) {
    const row = existing.rows[0]
    if (row.pin_plain) return { created: false, pin: exposePin ? row.pin_plain : undefined }
    const regen = String(randomInt(0, 10000)).padStart(4, '0')
    const regenHash = hashPin(normalized, regen)
    await pool.query('UPDATE customer_pins SET pin_hash = $1, pin_plain = $2 WHERE phone = $3', [
      regenHash,
      regen,
      normalized,
    ])
    return { created: true, pin: exposePin ? regen : undefined }
  }
  const pin = String(randomInt(0, 10000)).padStart(4, '0')
  const pinHash = hashPin(normalized, pin)
  const { rows } = await pool.query(
    'INSERT INTO customer_pins (phone, pin_hash, pin_plain) VALUES ($1,$2,$3) ON CONFLICT (phone) DO UPDATE SET pin_hash = EXCLUDED.pin_hash, pin_plain = EXCLUDED.pin_plain RETURNING pin_plain',
    [normalized, pinHash, pin],
  )
  return { created: true, pin: exposePin ? rows[0]?.pin_plain || pin : undefined }
}

const verifyPinForPhone = async (phone, pin) => {
  const normalized = normalizePhone(phone)
  if (!normalized || !pin) return false
  const { rows } = await pool.query('SELECT pin_hash FROM customer_pins WHERE phone = $1', [normalized])
  if (!rows.length) return false
  const pinHash = hashPin(normalized, pin)
  return rows[0].pin_hash === pinHash
}

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next)

app.post(
  '/api/pins/ensure',
  asyncHandler(async (req, res) => {
    const phone = (req.body.phone || '').toString()
    const normalized = normalizePhone(phone)
    if (!normalized) return res.status(400).json({ message: 'Утасны дугаар буруу.' })
    const exposePin = req.body.admin === true || req.headers['x-admin-pin'] === PIN_SECRET
    const { created, pin } = await ensurePinForPhone(normalized, { exposePin })
    res.json({ created, phone: normalized, pin: exposePin ? pin : undefined })
  }),
)

app.post(
  '/api/pins/lookup',
  asyncHandler(async (req, res) => {
    const phone = (req.body.phone || '').toString()
    const normalized = normalizePhone(phone)
    if (!normalized) return res.status(400).json({ message: 'Утасны дугаар буруу.' })
    const { created, pin } = await ensurePinForPhone(normalized, { exposePin: true })
    if (!pin) return res.status(500).json({ message: 'PIN үүсгэхэд алдаа.' })
    res.json({ pin, created, phone: normalized })
  }),
)

app.get(
  '/health',
  asyncHandler(async (_req, res) => {
    await pool.query('SELECT 1')
    res.json({ ok: true })
  }),
)

app.get(
  '/api/shipments',
  asyncHandler(async (req, res) => {
    const {
      phone,
      barcode,
      status,
      location,
      dateFrom,
      dateTo,
      search,
      page = 1,
      limit = 20,
    } = req.query

    const conditions = []
    const values = []
    const add = (sql, val) => {
      values.push(val)
      conditions.push(`${sql} $${values.length}`)
    }
    const addDate = (sql, val) => {
      values.push(val)
      conditions.push(`${sql} $${values.length}::date`)
    }

    if (phone) add('s.phone ILIKE', `%${phone}%`)
    if (barcode) add('s.barcode ILIKE', `%${barcode}%`)
    if (status) add('s.status =', status)
    if (location) add('s.location =', location)
    if (dateFrom) addDate('s.arrival_date >=', dateFrom)
    if (dateTo) addDate('s.arrival_date <=', dateTo)
    if (search) {
      const start = values.length
      values.push(`%${search}%`, `%${search}%`, `%${search}%`)
      conditions.push(
        `(s.phone ILIKE $${start + 1} OR s.barcode ILIKE $${start + 2} OR COALESCE(s.notes,'') ILIKE $${start + 3})`,
      )
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''
    const limitNum = Math.max(1, Math.min(Number(limit) || 20, 200))
    const pageNum = Math.max(1, Number(page) || 1)
    const offset = (pageNum - 1) * limitNum

    const total = (
      await pool.query(`SELECT COUNT(*)::int AS count FROM shipments s ${where}`, values)
    ).rows[0].count

    const rows = (
      await pool.query(
        `
        SELECT s.*, cp.pin_plain
        FROM shipments s
        LEFT JOIN customer_pins cp
          ON regexp_replace(cp.phone, '\\\\D', '', 'g') = regexp_replace(s.phone, '\\\\D', '', 'g')
        ${where}
        ORDER BY s.arrival_date DESC NULLS LAST, s.id DESC
        LIMIT $${values.length + 1} OFFSET $${values.length + 2}
      `,
        [...values, limitNum, offset],
      )
    ).rows

    await Promise.all(
      rows.map(async (row) => {
        if (row.pin_plain || !row.phone) return
        const { pin } = await ensurePinForPhone(row.phone, { exposePin: true })
        if (pin) row.pin_plain = pin
      }),
    )

    res.json({ data: rows.map(toShipment), meta: { page: pageNum, limit: limitNum, total } })
  }),
)

app.get(
  '/api/shipments/:id',
  asyncHandler(async (req, res) => {
    const row = await fetchShipmentWithPin(req.params.id)
    if (!row) return res.status(404).json({ message: 'Бичлэг олдсонгүй' })
    res.json(toShipment(row))
  }),
)

app.post(
  '/api/shipments',
  asyncHandler(async (req, res) => {
  const {
    barcode,
    phone = '',
    customer_name = '',
    quantity = 1,
    weight = 0,
    price = 0,
    paid_amount = 0,
    status = 'received',
    delivery_status = '',
    location = 'warehouse',
    arrival_date = new Date().toISOString().slice(0, 10),
    notes = '',
    delivery_note = '',
    courier = '',
    delivered_at = null,
  } = req.body || {}
    const locationClean = (location || 'warehouse').toLowerCase()
    const deliveryStatusClean =
      delivery_status ||
      (locationClean === 'delivery' ? 'delivery' : 'warehouse')

    if (!barcode) return res.status(400).json({ message: 'Бар код заавал' })

    const cleanPrice = Number(price) || 0
    const cleanPaid = Number(paid_amount) || 0
    const cleanQuantity = Number(quantity) || 1
    const cleanWeight = Number(weight) || 0
    const balance = cleanPrice - cleanPaid

    const created = (
      await pool.query(
      `INSERT INTO shipments
         (barcode, phone, customer_name, quantity, weight, price, paid_amount, balance, status, delivery_status, location, arrival_date, notes, delivery_note, courier, delivered_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
         RETURNING *`,
        [
          barcode.trim(),
          phone.trim(),
          customer_name.trim(),
          cleanQuantity,
          cleanWeight,
          cleanPrice,
          cleanPaid,
          balance,
          status,
          deliveryStatusClean,
          locationClean,
          arrival_date,
          notes,
          delivery_note,
          courier,
          delivered_at,
        ],
      )
    ).rows[0]

    res.status(201).json(toShipment(created))
  }),
)

app.put(
  '/api/shipments/:id',
  asyncHandler(async (req, res) => {
    const existing = (await pool.query('SELECT * FROM shipments WHERE id = $1', [req.params.id])).rows[0]
    if (!existing) return res.status(404).json({ message: 'Бичлэг олдсонгүй' })

  const merged = {
    ...existing,
    ...req.body,
  }

    const skipPin =
      req.body.admin === true || req.body.adminBypass === true || req.headers['x-admin-bypass-pin'] === PIN_SECRET
    merged.quantity = Number(merged.quantity) || 1
    merged.weight = Number(merged.weight) || 0
    merged.price = Number(merged.price) || 0
    merged.paid_amount = Number(merged.paid_amount) || 0
    merged.balance = merged.price - merged.paid_amount

    // Хүргэлт рүү шилжүүлэх үед PIN шаардлагатай: байхгүй бол үүсгээд дараагийн илгээхэд шаардлагатай болгоно.
    const wantsDelivery = (merged.location || '').toLowerCase() === 'delivery'
    const mergedDeliveryStatus = wantsDelivery
      ? merged.delivery_status || merged.deliveryStatus || 'delivery'
      : 'warehouse'
    const phone = (merged.phone || existing.phone || '').trim()
    if (wantsDelivery && !skipPin) {
      if (!phone) {
        return res.status(400).json({ message: 'Хүргэлтийн утас заавал оруулна уу.' })
      }
      const pinInput = (req.body.pin || req.body.delivery_pin || req.body.deliveryPin || '').toString().trim()
      const { created } = await ensurePinForPhone(phone)
      const pinOk = await verifyPinForPhone(phone, pinInput)
      if (!pinOk) {
        const message = created
          ? '4 оронтой (насан туршийн) хүргэлтийн PIN үүсгэлээ. 99205050 дугаарт залгаж PIN-ээ лавлаад оруулна уу.'
          : 'Хүргэлтийн PIN шаардлагатай. 99205050 дугаарт залгаж PIN-ээ лавлаад дахин илгээнэ үү.'
        return res.status(403).json({
          code: 'PIN_REQUIRED',
          message,
          pinCreated: created,
        })
      }
    } else if (wantsDelivery && skipPin && phone) {
      await ensurePinForPhone(phone)
    }

    await pool.query(
      `UPDATE shipments SET
        barcode = $1, phone = $2, customer_name = $3, quantity = $4, weight = $5,
        price = $6, paid_amount = $7, balance = $8,
        status = $9, delivery_status = $10, location = $11, arrival_date = $12, notes = $13,
        delivery_note = $14, courier = $15,
        updated_at = NOW()
      WHERE id = $16`,
      [
        merged.barcode,
        merged.phone,
        merged.customer_name,
        merged.quantity,
        merged.weight,
        merged.price,
        merged.paid_amount,
        merged.balance,
        merged.status,
        mergedDeliveryStatus,
        merged.location,
        merged.arrival_date,
        merged.notes,
        merged.delivery_note || null,
        merged.courier || null,
        req.params.id,
      ],
    )

    const updated = await fetchShipmentWithPin(req.params.id)
    res.json(toShipment(updated))
  }),
)

app.patch(
  '/api/shipments/:id/status',
  asyncHandler(async (req, res) => {
    const existing = await fetchShipmentWithPin(req.params.id)
    if (!existing) return res.status(404).json({ message: 'Бичлэг олдсонгүй' })

    const status = req.body.status || existing.status
    const location = (req.body.location || existing.location || 'warehouse').toLowerCase()
    const delivery_status = req.body.delivery_status || existing.delivery_status || (location === 'delivery' ? 'delivery' : 'warehouse')
    const delivered_at =
      delivery_status === 'delivered'
        ? existing.delivered_at || new Date().toISOString()
        : delivery_status === 'canceled' || delivery_status === 'pending'
          ? null
          : existing.delivered_at

    // Буцаах үед төлсөн дүнг 0 болгож үлдэгдлийг сэргээнэ.
    const paid_amount = status === 'pending' ? 0 : existing.paid_amount || 0
    const balance =
      status === 'pending' ? (existing.price || 0) : (existing.balance != null ? existing.balance : 0)

    await pool.query(
      `UPDATE shipments
       SET status = $1, delivery_status = $2, location = $3, delivered_at = $4, paid_amount = $5, balance = $6, updated_at = NOW()
       WHERE id = $7`,
      [status, delivery_status, location, delivered_at, paid_amount, balance, req.params.id],
    )

    const updated = await fetchShipmentWithPin(req.params.id)

    res.json(toShipment(updated))
  }),
)

app.get(
  '/api/shipments/:id/payments',
  asyncHandler(async (req, res) => {
    const payments = (
      await pool.query('SELECT * FROM payments WHERE shipment_id = $1 ORDER BY created_at DESC', [req.params.id])
    ).rows
    res.json(payments)
  }),
)

app.post(
  '/api/shipments/:id/payments',
  asyncHandler(async (req, res) => {
    const shipment = await fetchShipmentWithPin(req.params.id)
    if (!shipment) return res.status(404).json({ message: 'Бичлэг олдсонгүй' })

    const amount = Number(req.body.amount) || 0
    const method = req.body.method || 'cash'
    if (amount <= 0) return res.status(400).json({ message: 'Төлбөрийн дүн > 0 байх ёстой' })

    await pool.query('INSERT INTO payments (shipment_id, amount, method) VALUES ($1,$2,$3)', [
      req.params.id,
      amount,
      method,
    ])

    const paid = (shipment.paid_amount || 0) + amount
    const balance = (shipment.price || 0) - paid
    const status = balance <= 0 ? 'paid' : shipment.status

    await pool.query(
      `UPDATE shipments
       SET paid_amount = $1, balance = $2, status = $3, updated_at = NOW()
       WHERE id = $4`,
      [paid, balance, status, req.params.id],
    )

    const updated = await fetchShipmentWithPin(req.params.id)

    const payments = (
      await pool.query('SELECT * FROM payments WHERE shipment_id = $1 ORDER BY created_at DESC', [req.params.id])
    ).rows

    res.status(201).json({ shipment: toShipment(updated), payments })
  }),
)

app.get(
  '/api/stats/summary',
  asyncHandler(async (_req, res) => {
    const totals = (
      await pool.query('SELECT COUNT(*)::int AS count, COALESCE(SUM(price),0)::int AS price, COALESCE(SUM(balance),0)::int AS balance FROM shipments')
    ).rows[0]

    const byStatusRows = (await pool.query('SELECT status, COUNT(*)::int AS count FROM shipments GROUP BY status')).rows
    const byStatus = byStatusRows.reduce((acc, row) => ({ ...acc, [row.status]: row.count }), {})

    res.json({
      total_shipments: totals.count || 0,
      total_price: Number(totals.price) || 0,
      total_balance: Number(totals.balance) || 0,
      by_status: byStatus,
    })
  }),
)

// Контент (хаяг холбох, үнэ тариф) хадгалах/унших
app.get(
  '/api/content',
  asyncHandler(async (_req, res) => {
    const row = (await pool.query("SELECT payload FROM site_content WHERE key = 'sections'")).rows[0]
    const payload = row?.payload
    const sections = typeof payload === 'string' ? JSON.parse(payload || '[]') : payload || []
    res.json({ sections })
  }),
)

app.put(
  '/api/content',
  asyncHandler(async (req, res) => {
    const sections = Array.isArray(req.body.sections) ? req.body.sections : []
    const payload = JSON.stringify(sections)
    await pool.query(
      `INSERT INTO site_content(key, payload, updated_at)
       VALUES ('sections', $1::jsonb, NOW())
       ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()`,
      [payload],
    )
    res.json({ sections })
  }),
)

app.use((err, _req, res, _next) => {
  console.error(err)
  res.status(500).json({ message: 'Серверийн алдаа' })
})

const start = async () => {
  await dbReady
  app.listen(port, () => {
    console.log(`Backend up on http://localhost:${port}`)
  })
}

if (!isVercel) {
  start().catch((err) => {
    console.error('Start failed', err)
    process.exit(1)
  })
}

// For Vercel serverless
export default app
