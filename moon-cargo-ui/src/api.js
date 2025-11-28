const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:4000'
const ADMIN_PIN_SECRET =
  import.meta.env.VITE_ADMIN_PIN_SECRET || import.meta.env.VITE_PIN_SECRET || 'tutuyu-pin-secret'

const toUi = (row) => {
  const paidAmount = Number(row.paid_amount) || 0
  const price = Number(row.price) || 0
  const balance = Number(row.balance) || price - paidAmount
  const deliveryStatus = row.delivery_status || (row.location === 'delivery' ? 'delivery' : 'warehouse')
  const knownStatus = ['paid', 'pending', 'delivered', 'delayed', 'canceled']
  const status = knownStatus.includes(row.status)
    ? row.status
    : balance <= 0
      ? 'paid'
      : 'pending'

  return {
    id: row.id,
    tracking: row.barcode,
    phone: row.phone || '',
    pin: row.pin || row.pin_plain || '',
    customerName: row.customer_name || '',
    quantity: Number(row.quantity) || 1,
    weight: Number(row.weight) || 0,
    declared: price,
    paidAmount,
    balance,
    status,
    deliveryStatus,
    location: row.location || (deliveryStatus === 'delivery' ? 'delivery' : 'warehouse'),
    arrivalDate: row.arrival_date || '',
    deliveryAddress: row.notes || '',
    deliveryNote: row.delivery_note || '',
    createdAt: row.created_at || '',
  }
}

const normalizePhone = (phone) => (phone || '').toString().replace(/\D+/g, '')

const toApi = (record) => ({
  barcode: record.tracking?.trim().toUpperCase(),
  phone: normalizePhone(record.phone),
  customer_name: record.customerName || '',
  quantity: Number(record.quantity) || 1,
  weight: Number(record.weight) || 0,
  price: Number(record.declared) || 0,
  paid_amount: Number(record.paidAmount) || 0,
  status: record.status || 'pending',
  delivery_status: record.deliveryStatus || (record.location === 'delivery' ? 'delivery' : 'warehouse'),
  location: record.location || 'warehouse',
  arrival_date: record.arrivalDate || new Date().toISOString().slice(0, 10),
  notes: record.deliveryAddress || '',
  delivery_note: record.deliveryNote || '',
  pin: record.pin || record.deliveryPin || record.pinCode || '',
  admin: record.admin === true ? true : undefined,
  adminBypass: record.adminBypass === true ? true : undefined,
})

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  })
  if (!res.ok) {
    const text = await res.text()
    let parsed = null
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = null
    }
    const err = new Error(parsed?.message || text || `Request failed ${res.status}`)
    if (parsed?.code) err.code = parsed.code
    if (parsed?.pin) err.pin = parsed.pin
    if (parsed?.pinCreated !== undefined) err.pinCreated = parsed.pinCreated
    throw err
  }
  if (res.status === 204) return null
  return res.json()
}

export async function listShipments() {
  const data = await request('/api/shipments')
  return (data?.data || []).map(toUi)
}

export async function createShipment(record) {
  const payload = toApi(record)
  const created = await request('/api/shipments', { method: 'POST', body: JSON.stringify(payload) })
  return toUi(created)
}

export async function updateShipment(id, record) {
  const payload = toApi(record)
  const updated = await request(`/api/shipments/${id}`, { method: 'PUT', body: JSON.stringify(payload) })
  return toUi(updated)
}

export async function setShipmentStatus(id, status, location, deliveryStatus) {
  const updated = await request(`/api/shipments/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status, location, delivery_status: deliveryStatus }),
  })
  return toUi(updated)
}

export async function addPayment(id, amount, method = 'cash') {
  const result = await request(`/api/shipments/${id}/payments`, {
    method: 'POST',
    body: JSON.stringify({ amount, method }),
  })
  return { shipment: result.shipment ? toUi(result.shipment) : null, payments: result.payments || [] }
}

export async function ensurePin(phone) {
  const body = JSON.stringify({ phone: normalizePhone(phone), admin: true })
  return request('/api/pins/ensure', {
    method: 'POST',
    body,
    headers: { 'x-admin-pin': ADMIN_PIN_SECRET },
  })
}

export async function lookupPin(phone) {
  const body = JSON.stringify({ phone: normalizePhone(phone) })
  try {
    // Эхлээд shipments API-гаас (жагсаалт дээрхтэй адил) PIN-ийг авч үзнэ.
    const resp = await request(`/api/shipments?phone=${encodeURIComponent(normalizePhone(phone))}&limit=1`)
    const fromList = resp?.data?.[0]?.pin || resp?.data?.[0]?.pin_plain
    if (fromList) return { pin: fromList, phone: normalizePhone(phone), created: false }
  } catch (_) {
    // ignore, fallback доош
  }
  // Fallback: dedicated lookup эсвэл ensurePin.
  try {
    return await request('/api/pins/lookup', {
      method: 'POST',
      body,
      headers: { 'x-admin-pin': ADMIN_PIN_SECRET },
    })
  } catch (error) {
    try {
      return await ensurePin(phone)
    } catch {
      throw error
    }
  }
}

export async function fetchSections() {
  const res = await request('/api/content')
  return res.sections || []
}

export async function saveSections(sections) {
  const res = await request('/api/content', {
    method: 'PUT',
    body: JSON.stringify({ sections }),
  })
  return res.sections || []
}
