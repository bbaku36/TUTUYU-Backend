import { useEffect, useMemo, useState } from 'react'
import BarcodeScanner from './BarcodeScanner.jsx'
import AdminCreate from './admin/AdminCreate.jsx'
import AdminDashboard from './admin/AdminDashboard.jsx'
import AdminDelivery from './admin/AdminDelivery.jsx'
import AdminDocuments from './admin/AdminDocuments.jsx'
import AdminList from './admin/AdminList.jsx'
import AdminPayments from './admin/AdminPayments.jsx'
import { StatusChip, deliveryStatusOptions, formatCurrency, formatDate } from './admin/common.jsx'
import { addPayment, createShipment, setShipmentStatus, updateShipment } from '../api.js'
import {
  ADDRESS_SECTION_TITLE,
  ATTENTION_SECTION_TITLE,
  PRICE_SECTION_TITLE,
  SCHEDULE_PREVIOUS_TITLES,
  SCHEDULE_SECTION_TITLE,
} from '../constants.js'

const createFormDefaults = () => ({
  phone: '',
  tracking: '',
  warehouse: '',
  weight: '',
  declared: '',
  location: 'Баянзүрх салбар',
  cubic: '',
  arrivalDate: new Date().toISOString().slice(0, 10),
  quantity: 1,
  deliveryAddress: '',
})

export default function AdminPanel({
  records = [],
  onRecordsChange = () => {},
  sections = [],
  onSectionsChange = () => {},
  newDeliveryCount = 0,
  onClearNewDelivery = () => {},
}) {
  const [activeSection, setActiveSection] = useState('dashboard')
  const [formData, setFormData] = useState(createFormDefaults)
  const [filterPhone, setFilterPhone] = useState('')
  const [filterTracking, setFilterTracking] = useState('')
  const [deliveryTabFilter, setDeliveryTabFilter] = useState('all')
  const [paymentPhoneQuery, setPaymentPhoneQuery] = useState('')
  const [paymentTrackingQuery, setPaymentTrackingQuery] = useState('')
  const [paymentAmounts, setPaymentAmounts] = useState({})
  const [paymentGroupAmounts, setPaymentGroupAmounts] = useState({})
  const [deliveryGroupAddresses, setDeliveryGroupAddresses] = useState({})
  const [autoFillTracking, setAutoFillTracking] = useState(true)
  const [scannerTarget, setScannerTarget] = useState(null)
  const [toast, setToast] = useState('')
  const [deliveryInputPhone, setDeliveryInputPhone] = useState('')
  const [deliveryInputValue, setDeliveryInputValue] = useState('')
  const [documentPage, setDocumentPage] = useState(1)
  const [visiblePage, setVisiblePage] = useState(1)
  const [addressInfo, setAddressInfo] = useState('')
  const [priceInfo, setPriceInfo] = useState('')
  const [scheduleInfo, setScheduleInfo] = useState('')
  const [attentionInfo, setAttentionInfo] = useState('')
  const [scheduleImage, setScheduleImage] = useState('')
  const [copiedKey, setCopiedKey] = useState('')

  // Нийт үнэ = зарласан үнэ (тоо ширхэгтэй хамааралгүй)
  const amountOf = (record) => Number(record.declared) || 0

  const updateRecords = (updater) => {
    onRecordsChange((prevRaw) => {
      const prev = Array.isArray(prevRaw) ? prevRaw : []
      return updater(prev)
    })
  }

  const syncRecord = (updated) => {
    if (!updated?.id) return
    updateRecords((prev) => prev.map((record) => (record.id === updated.id ? updated : record)))
  }

  const handleFormChange = (field) => (event) => {
    const value = field === 'tracking' ? event.target.value.toUpperCase() : event.target.value
    setFormData((prev) => ({ ...prev, [field]: value }))
  }

  const handleFormSubmit = async (event) => {
    event.preventDefault()
    try {
      const created = await createShipment({ ...formData, status: 'pending' })
      updateRecords((prev) => [created, ...prev])
      setToast('Барааны бүртгэл хадгалагдлаа.')
      setFormData(createFormDefaults())
      setTimeout(() => setToast(''), 2500)
    } catch (error) {
      console.error('Бараа хадгалах үед алдаа гарлаа', error)
      setToast('Хадгалах үед алдаа гарлаа')
      setTimeout(() => setToast(''), 2500)
    }
  }

  const setShipmentStatusAndSync = async (id, status, location, deliveryStatus) => {
    try {
      const updated = await setShipmentStatus(id, status, location, deliveryStatus)
      syncRecord(updated)
    } catch (error) {
      console.error('Статус шинэчлэхэд алдаа', error)
    }
  }

  const updateRecordStatus = (id, nextStatus) => {
    const current = records.find((record) => record.id === id)
    if (!current) return
    const resetToWarehouse = nextStatus === 'pending'
    const nextLocation = resetToWarehouse ? 'warehouse' : current.location
    const nextDeliveryStatus = resetToWarehouse ? 'warehouse' : current.deliveryStatus || current.delivery_status
    setShipmentStatusAndSync(id, nextStatus, nextLocation, nextDeliveryStatus)
  }

  const updateRecordLocation = (id, nextLocation) => {
    const current = records.find((record) => record.id === id)
    if (!current) return
    setShipmentStatusAndSync(id, current.status, nextLocation, current.deliveryStatus || current.delivery_status)
  }

  const handlePaymentAmountChange = (id, value) => {
    setPaymentAmounts((prev) => ({ ...prev, [id]: value }))
  }

  const payRemaining = async (record) => {
    const total = amountOf(record)
    const paid = Number(record.paidAmount) || 0
    const remaining = Math.max(0, total - paid)
    if (remaining <= 0) {
      setShipmentStatusAndSync(record.id, 'paid', record.location)
      return
    }
    try {
      const result = await addPayment(record.id, remaining)
      if (result?.shipment) syncRecord(result.shipment)
    } catch (error) {
      console.error('Үлдэгдэл төлбөрт алдаа', error)
    }
  }

  const handleDeliveryChange = (record, next) => {
    // Байршил нь warehouse / delivery, харин deliveryStatus нь хүргэлтийн тусдаа төлөв.
    if (next === 'warehouse') {
      setShipmentStatusAndSync(record.id, record.status, 'warehouse', 'warehouse')
    } else if (next === 'delivery') {
      setShipmentStatusAndSync(record.id, record.status, 'delivery', 'delivery')
    } else {
      setShipmentStatusAndSync(record.id, record.status, 'delivery', next)
    }
  }

  const payCustom = async (record) => {
    const raw = paymentAmounts[record.id]
    const amount = Number(raw)
    if (!raw || Number.isNaN(amount) || amount <= 0) return
    try {
      const result = await addPayment(record.id, amount)
      if (result?.shipment) syncRecord(result.shipment)
      setPaymentAmounts((prev) => ({ ...prev, [record.id]: '' }))
    } catch (error) {
      console.error('Төлбөр нэмэхэд алдаа', error)
    }
  }

  const payCustomForPhone = async (phone) => {
    const raw = paymentGroupAmounts[phone]
    const amount = Number(raw)
    if (!raw || Number.isNaN(amount) || amount <= 0) return
    const normalized = (phone || '').replace(/\s+/g, '')
    let remaining = amount
    // Ачаануудыг нэг бүрчлэн үлдэгдэлтэй хэмжээнд төлнө.
    // eslint-disable-next-line no-restricted-syntax
    for (const record of filteredRecords.filter((r) => (r.phone || '').replace(/\s+/g, '') === normalized)) {
      const balance = Math.max(0, (Number(record.declared) || 0) - (Number(record.paidAmount) || 0))
      if (balance <= 0) continue
      const payNow = Math.min(balance, remaining)
      if (payNow <= 0) break
      // eslint-disable-next-line no-await-in-loop
      const result = await addPayment(record.id, payNow)
      if (result?.shipment) syncRecord(result.shipment)
      remaining -= payNow
      if (remaining <= 0) break
    }
    setPaymentGroupAmounts((prev) => ({ ...prev, [phone]: '' }))
  }

  const updateAddressForPhone = async (phone, address) => {
    const normalized = (phone || '').replace(/\s+/g, '')
    // eslint-disable-next-line no-restricted-syntax
    for (const record of records.filter((r) => (r.phone || '').replace(/\s+/g, '') === normalized)) {
      // eslint-disable-next-line no-await-in-loop
      await updateAddress(record, address)
    }
  }

  const updateAddress = async (record, address) => {
    try {
      const updated = await updateShipment(record.id, { ...record, deliveryAddress: address })
      syncRecord(updated)
    } catch (error) {
      console.error('Хаяг шинэчлэхэд алдаа', error)
    }
  }

  const payAllForPhone = async (phone) => {
    const phoneKey = (phone || '').replace(/\s+/g, '')
    const targets = filteredRecords.filter(
      (r) => (r.phone || '').replace(/\s+/g, '') === phoneKey && (Number(r.balance) > 0 || Number(r.paidAmount) < Number(r.declared)),
    )
    for (const record of targets) {
      // Эрсдэл багасгахын тулд нэг бүрчлэн дуудна.
      // payRemaining дотор addPayment/setShipmentStatus-ийг зохицуулна.
      // eslint-disable-next-line no-await-in-loop
      await payRemaining(record)
    }
  }

  const sendGroupToDelivery = async (phone, addressOverride, targetLocation = 'delivery') => {
    const address = addressOverride ?? deliveryGroupAddresses[phone] ?? ''
    const normalized = (phone || '').replace(/\s+/g, '')
    // eslint-disable-next-line no-restricted-syntax
    for (const record of records.filter((r) => (r.phone || '').replace(/\s+/g, '') === normalized)) {
      // eslint-disable-next-line no-await-in-loop
      const updated = await updateShipment(record.id, {
        ...record,
        location: targetLocation,
        deliveryStatus: targetLocation === 'delivery' ? 'delivery' : 'warehouse',
        deliveryAddress: address,
        admin: true,
        adminBypass: true,
      })
      syncRecord(updated)
    }
    setDeliveryInputPhone('')
    setDeliveryInputValue('')
    setActiveSection('delivery')
  }

  const setDeliveryStatusForPhone = async (phone, nextStatus) => {
    const normalized = (phone || '').replace(/\s+/g, '')
    // eslint-disable-next-line no-restricted-syntax
    for (const record of records.filter((r) => (r.phone || '').replace(/\s+/g, '') === normalized)) {
      // eslint-disable-next-line no-await-in-loop
      const updated = await updateShipment(record.id, {
        ...record,
        location: 'delivery',
        deliveryStatus: nextStatus,
        admin: true,
        adminBypass: true,
      })
      syncRecord(updated)
    }
  }

  const handleScannerDetected = (value) => {
    if (!value) return
    if (scannerTarget === 'form') {
      setFormData((prev) => ({ ...prev, tracking: value.toUpperCase() }))
      setAutoFillTracking(true)
      setActiveSection('create')
    } else if (scannerTarget === 'records') {
      const code = value.toUpperCase()
      setFilterTracking(code)
      setPaymentTrackingQuery(code)
    }
    setScannerTarget(null)
  }

  const filteredRecords = useMemo(
    () =>
      records.filter((record) => {
        const phoneOk = filterPhone
          ? (record.phone || '').replace(/\s+/g, '').includes(filterPhone.replace(/\s+/g, ''))
          : true
        const trackingOk = filterTracking
          ? (record.tracking || '').toUpperCase().includes(filterTracking.trim().toUpperCase())
          : true
        return phoneOk && trackingOk
      }),
    [records, filterPhone, filterTracking],
  )

  const paymentFilteredRecords = useMemo(
    () =>
      records.filter((record) => {
        const matchesPhone = paymentPhoneQuery
          ? (record.phone || '').replace(/\s+/g, '').includes(paymentPhoneQuery.replace(/\s+/g, ''))
          : true
        const matchesTracking = paymentTrackingQuery
          ? (record.tracking || '').toUpperCase().includes(paymentTrackingQuery.trim().toUpperCase())
          : true
        const total = amountOf(record)
        const paid = Number(record.paidAmount) || 0
        const balance = Math.max(0, total - paid)
        const hasBalance = balance > 0
        return matchesPhone && matchesTracking && hasBalance
      }),
    [records, paymentPhoneQuery, paymentTrackingQuery],
  )

  const totals = useMemo(
    () =>
      filteredRecords.reduce(
        (acc, record) => {
          const amount = amountOf(record)
          const paid = Number(record.paidAmount) || 0
          acc.count += 1
          acc.amount += amount
          acc.paid += paid
          acc.balance += Math.max(0, amount - paid)
          return acc
        },
        { count: 0, amount: 0, paid: 0, balance: 0 },
      ),
    [filteredRecords],
  )


  const isDeliveredSettled = (record) => {
    const total = amountOf(record)
    const paid = Number(record.paidAmount) || 0
    const balance = Math.max(0, total - paid)
    const delivered = (record.deliveryStatus || record.status || '') === 'delivered'
    return delivered && balance <= 0
  }

  const visibleRecords = useMemo(
    () => filteredRecords.filter((record) => !isDeliveredSettled(record)),
    [filteredRecords],
  )

  const documentRecords = useMemo(
    () => filteredRecords.filter((record) => isDeliveredSettled(record)),
    [filteredRecords],
  )

  const documentTotals = useMemo(
    () =>
      documentRecords.reduce(
        (acc, record) => {
          const amount = amountOf(record)
          const paid = Number(record.paidAmount) || 0
          acc.count += 1
          acc.amount += amount
          acc.paid += paid
          acc.balance += Math.max(0, amount - paid)
          return acc
        },
        { count: 0, amount: 0, paid: 0, balance: 0 },
      ),
    [documentRecords],
  )

  const documentPageSize = 10
  const documentPageCount = Math.max(1, Math.ceil(documentRecords.length / documentPageSize))

  useEffect(() => {
    setDocumentPage(1)
  }, [documentRecords.length])

  const documentPageRecords = useMemo(
    () => documentRecords.slice((documentPage - 1) * documentPageSize, documentPage * documentPageSize),
    [documentRecords, documentPage],
  )

  useEffect(() => {
    if (activeSection === 'delivery' && newDeliveryCount > 0) {
      onClearNewDelivery()
    }
  }, [activeSection, newDeliveryCount, onClearNewDelivery])

  const phoneGroups = useMemo(() => {
    const map = {}
    visibleRecords.forEach((record) => {
      const key = record.phone?.trim() || 'Дугаар оруулаагүй'
      if (!map[key]) {
        map[key] = { phone: key, pin: record.pin || '', items: [], total: 0, paid: 0, balance: 0 }
      } else if (!map[key].pin && record.pin) {
        map[key].pin = record.pin
      }
      const amount = amountOf(record)
      const paid = Number(record.paidAmount) || 0
      map[key].items.push(record)
      map[key].total += amount
      map[key].paid += paid
      map[key].balance += Math.max(0, amount - paid)
    })
    return Object.values(map)
  }, [visibleRecords])

  const phoneGroupPageSize = 10
  const phoneGroupPageCount = Math.max(1, Math.ceil(phoneGroups.length / phoneGroupPageSize))

  useEffect(() => {
    setVisiblePage(1)
  }, [phoneGroups.length])

  const phoneGroupsPage = useMemo(
    () => phoneGroups.slice((visiblePage - 1) * phoneGroupPageSize, visiblePage * phoneGroupPageSize),
    [phoneGroups, visiblePage],
  )

  const addressLines = useMemo(
    () => addressInfo.split('\n').map((line) => line.trim()).filter(Boolean),
    [addressInfo],
  )

  const handleCopyLine = async (text, key) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedKey(key)
      setTimeout(() => setCopiedKey(''), 1200)
    } catch (error) {
      console.error('Хуулах үед алдаа', error)
      setCopiedKey(key)
      setTimeout(() => setCopiedKey(''), 1200)
    }
  }

  const handleClearScheduleImage = () => setScheduleImage('')

  useEffect(() => {
    const toText = (titles) => {
      const lookups = Array.isArray(titles) ? titles : [titles]
      const section = sections.find((item) => lookups.includes(item.title))
      if (!section) return ''
      return (section.description || [])
        .map((line) => (typeof line === 'string' ? line : line?.text || line?.copy || ''))
        .filter(Boolean)
        .join('\n')
    }
    const addressTitles = [ADDRESS_SECTION_TITLE, SCHEDULE_SECTION_TITLE, ...SCHEDULE_PREVIOUS_TITLES]
    const scheduleTitles = [SCHEDULE_SECTION_TITLE, ...SCHEDULE_PREVIOUS_TITLES]
    const attentionTitles = [ATTENTION_SECTION_TITLE]

    setAddressInfo(toText(addressTitles))
    setPriceInfo(toText(PRICE_SECTION_TITLE))
    setScheduleInfo(toText(scheduleTitles))
    setAttentionInfo(toText(attentionTitles))

    const scheduleSection = sections.find((item) => scheduleTitles.includes(item.title))
    setScheduleImage(scheduleSection?.image || '')
  }, [sections])

  const handleCustomerContentSave = async (options = {}) => {
    const scheduleImageValue = Object.prototype.hasOwnProperty.call(options, 'scheduleImage')
      ? options.scheduleImage
      : scheduleImage
    const addressLines = addressInfo
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
    const priceLines = priceInfo
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
    const scheduleLines = scheduleInfo
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
    const attentionLines = attentionInfo
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)

    const updated = sections.map((section) => {
      if (section.title === PRICE_SECTION_TITLE) {
        return { ...section, description: priceLines }
      }
      if (section.title === ADDRESS_SECTION_TITLE) {
        return { ...section, description: addressLines.length ? addressLines : [''] }
      }
      if (section.title === SCHEDULE_SECTION_TITLE || SCHEDULE_PREVIOUS_TITLES.includes(section.title)) {
        return {
          ...section,
          title: SCHEDULE_SECTION_TITLE,
          description: scheduleLines.length ? scheduleLines : [''],
          image: scheduleImageValue || '',
        }
      }
      if (section.title === ATTENTION_SECTION_TITLE) {
        return { ...section, description: attentionLines.length ? attentionLines : [''], image: '' }
      }
      return section
    })

    const withAddress = updated.some((section) => section.title === ADDRESS_SECTION_TITLE)
      ? updated
      : [
          {
            title: ADDRESS_SECTION_TITLE,
            description: addressLines.length ? addressLines : [''],
            image: '',
          },
          ...updated,
        ]

    const withPrice = withAddress.some((section) => section.title === PRICE_SECTION_TITLE)
      ? withAddress
      : [...withAddress, { title: PRICE_SECTION_TITLE, description: priceLines, image: '' }]

    const withSchedule = withPrice.some((section) => section.title === SCHEDULE_SECTION_TITLE)
      ? withPrice.map((section) =>
          section.title === SCHEDULE_SECTION_TITLE
            ? {
                ...section,
                description: scheduleLines.length ? scheduleLines : [''],
                image: scheduleImageValue || '',
              }
            : section,
        )
      : [
          ...withPrice,
          {
            title: SCHEDULE_SECTION_TITLE,
            description: scheduleLines.length ? scheduleLines : [''],
            image: scheduleImageValue || '',
          },
        ]

    const withAttention = withSchedule.some((section) => section.title === ATTENTION_SECTION_TITLE)
      ? withSchedule.map((section) =>
          section.title === ATTENTION_SECTION_TITLE
            ? { ...section, description: attentionLines.length ? attentionLines : [''], image: '' }
            : section,
        )
      : [
          ...withSchedule,
          { title: ATTENTION_SECTION_TITLE, description: attentionLines.length ? attentionLines : [''], image: '' },
        ]

    try {
      await onSectionsChange(withAttention)
      setToast('Хэрэглэгчийн мэдээлэл хадгалагдлаа.')
    } catch (error) {
      console.error('Контент хадгалах үед алдаа', error)
      setToast('Хадгалах үед алдаа гарлаа')
    }
    setTimeout(() => setToast(''), 2500)
  }

  const deliveryGroups = useMemo(() => {
    const map = {}
    records
      .filter((record) => record.location === 'delivery')
      .filter((record) => {
        const total = amountOf(record)
        const paid = Number(record.paidAmount) || 0
        const balance = Math.max(0, total - paid)
        const delivered = (record.deliveryStatus || record.status || '') === 'delivered'
        return !(delivered && balance <= 0)
      })
      .forEach((record) => {
        const key = record.phone?.trim() || 'Дугаар оруулаагүй'
        if (!map[key]) {
          map[key] = { phone: key, items: [], address: record.deliveryAddress || '' }
        }
        if (!map[key].address && record.deliveryAddress) {
          map[key].address = record.deliveryAddress
        }
        map[key].items.push(record)
      })
    return Object.values(map)
  }, [records])

  const deliveryVisibleCount = useMemo(
    () => deliveryGroups.reduce((sum, group) => sum + group.items.length, 0),
    [deliveryGroups],
  )

  const analytics = useMemo(() => {
    const warehouseCount = records.filter((r) => r.location === 'warehouse').length
    const deliveryCount = records.filter((r) => r.location === 'delivery').length
    const balance = records.reduce((sum, r) => {
      const total = amountOf(r)
      const paid = Number(r.paidAmount) || 0
      return sum + Math.max(0, total - paid)
    }, 0)

    const now = new Date()
    const thisMonth = now.toISOString().slice(0, 7) // yyyy-mm
    const perDay = {}
    records.forEach((r) => {
      const day = (r.arrivalDate || '').slice(0, 10)
      if (day.startsWith(thisMonth)) {
        perDay[day] = (perDay[day] || 0) + 1
      }
    })
    const days = Object.entries(perDay)
      .sort(([a], [b]) => (a < b ? 1 : -1))
      .slice(0, 7)

    return { warehouseCount, deliveryCount, balance, days }
  }, [records])

const navItems = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'list', label: 'Барааны жагсаалт' },
  { id: 'documents', label: 'Шинэ баримт' },
  { id: 'delivery', label: 'Хүргэлт' },
  { id: 'create', label: 'Бараа бүртгэх' },
  { id: 'list-payments', label: 'Төлбөрийн үлдэгдэл' },
]

  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:gap-6">
      <aside className="w-full shrink-0 rounded-3xl bg-white/90 p-4 text-[#2f1f1a] shadow-xl shadow-[#e2a07d33] lg:w-72">
        <div className="flex flex-col gap-2 rounded-2xl bg-gradient-to-r from-[#CDA799] to-[#CDA799] px-4 py-4 text-white">
          <div className="flex items-center justify-between">
            <p className="text-sm opacity-80">Админ</p>
            <span className="rounded-full bg-white/20 px-2 py-1 text-xs">Mobile friendly</span>
          </div>
          <p className="text-xl font-semibold">TUTUYU Cargo</p>
        </div>
        <nav className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:block lg:space-y-2">
          {navItems.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveSection(item.id)}
              className={`flex w-full items-center justify-between rounded-xl px-3 py-2 text-left text-xs font-semibold transition sm:text-sm ${
                activeSection === item.id
                  ? 'bg-[#CDA799] text-white shadow-lg shadow-[#0f513240]'
                  : 'bg-white text-[#2f1f1a] hover:bg-white/90 border border-[#f0d9c5]'
              }`}
            >
              <span className="flex items-center gap-2">
                {item.label}
                {item.id === 'delivery' && newDeliveryCount > 0 ? (
                  <span className="rounded-full bg-[#fbe9dd] px-2 py-0.5 text-[11px] font-semibold text-[#b5654f]">
                    {newDeliveryCount} шинэ
                  </span>
                ) : null}
              </span>
              <span className="text-xs opacity-70">→</span>
            </button>
          ))}
        </nav>
        <div className="mt-4 grid grid-cols-2 gap-2 lg:mt-6 lg:space-y-2 lg:rounded-2xl lg:border lg:border-[#e8d2c4] lg:bg-white/70 lg:p-3 lg:text-sm lg:text-[#6f4a3b]">
          <p className="text-[11px] uppercase text-[#b27b66] lg:col-span-2">Нийлбэр</p>
          <p className="text-xs lg:text-sm">
            Ачаа: <span className="font-semibold text-[#3b231f]">{documentTotals.count}</span>
          </p>
          <p className="text-xs lg:text-sm">
            Нийт үнэ: <span className="font-semibold text-[#3b231f]">{formatCurrency(totals.amount)}</span>
          </p>
          <p className="text-xs lg:text-sm">
            Төлсөн: <span className="font-semibold text-[#3b231f]">{formatCurrency(totals.paid)}</span>
          </p>
          <p className="text-xs lg:text-sm">
            Үлдэгдэл: <span className="font-semibold text-[#c24b34]">{formatCurrency(documentTotals.balance)}</span>
          </p>
        </div>
      </aside>

      <div className="flex-1 min-w-0 space-y-4 rounded-3xl bg-white/80 p-4 shadow-xl shadow-[#f1c6a255] sm:p-5 lg:p-6">
        {newDeliveryCount > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[#f7c8c8] bg-[#fff2f2] px-4 py-3 text-sm text-[#8d6457]">
            <div>
              <p className="font-semibold text-[#b42318]">Шинэ хүргэлтийн хүсэлт {newDeliveryCount} ширхэг</p>
              <p className="text-xs">Хүргэлт хэсэгт орж хаяг, утсыг шалгаад хүргэлтэнд шилжүүлээрэй.</p>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setActiveSection('delivery')}
                className="rounded-full border border-[#b5654f] bg-white px-3 py-1.5 text-xs font-semibold text-[#b5654f]"
              >
                Харах
              </button>
              <button
                type="button"
                onClick={onClearNewDelivery}
                className="rounded-full border border-[#f0d9c5] bg-white px-3 py-1.5 text-xs font-semibold text-[#8d6457]"
              >
                Мэдсэн
              </button>
            </div>
          </div>
        )}
        {activeSection === 'dashboard' && (
          <AdminDashboard
            analytics={analytics}
            addressInfo={addressInfo}
            setAddressInfo={setAddressInfo}
            priceInfo={priceInfo}
            setPriceInfo={setPriceInfo}
            scheduleInfo={scheduleInfo}
            setScheduleInfo={setScheduleInfo}
            scheduleImage={scheduleImage}
            onScheduleImageChange={setScheduleImage}
            onClearScheduleImage={handleClearScheduleImage}
            attentionInfo={attentionInfo}
            setAttentionInfo={setAttentionInfo}
            addressLines={addressLines}
            copiedKey={copiedKey}
            handleCopyLine={handleCopyLine}
            handleCustomerContentSave={handleCustomerContentSave}
            formatCurrency={formatCurrency}
          />
        )}

        {activeSection === 'documents' && (
          <AdminDocuments
            filterPhone={filterPhone}
            setFilterPhone={setFilterPhone}
            filterTracking={filterTracking}
            setFilterTracking={setFilterTracking}
            documentTotals={documentTotals}
            documentPageRecords={documentPageRecords}
            documentRecords={documentRecords}
            documentPage={documentPage}
            documentPageCount={documentPageCount}
            documentPageSize={documentPageSize}
            formatCurrency={formatCurrency}
            formatDate={formatDate}
            StatusChip={StatusChip}
            deliveryStatusOptions={deliveryStatusOptions}
            handleDeliveryChange={handleDeliveryChange}
            updateRecordStatus={updateRecordStatus}
            payRemaining={payRemaining}
            amountOf={amountOf}
            onOpenPayments={() => setActiveSection('list-payments')}
          />
        )}

        {activeSection === 'list' && (
          <AdminList
            filterPhone={filterPhone}
            setFilterPhone={setFilterPhone}
            filterTracking={filterTracking}
            setFilterTracking={setFilterTracking}
            paymentGroupAmounts={paymentGroupAmounts}
            setPaymentGroupAmounts={setPaymentGroupAmounts}
            payCustomForPhone={payCustomForPhone}
            payAllForPhone={payAllForPhone}
            phoneGroups={phoneGroups}
            phoneGroupsPage={phoneGroupsPage}
            visiblePage={visiblePage}
            setVisiblePage={setVisiblePage}
            phoneGroupPageCount={phoneGroupPageCount}
            deliveryInputPhone={deliveryInputPhone}
            deliveryInputValue={deliveryInputValue}
            setDeliveryInputPhone={setDeliveryInputPhone}
            setDeliveryInputValue={setDeliveryInputValue}
            deliveryGroupAddresses={deliveryGroupAddresses}
            setDeliveryGroupAddresses={setDeliveryGroupAddresses}
            sendGroupToDelivery={sendGroupToDelivery}
            setDeliveryStatusForPhone={setDeliveryStatusForPhone}
            amountOf={amountOf}
            formatCurrency={formatCurrency}
          />
        )}
        {activeSection === 'delivery' && (
          <AdminDelivery
            filterPhone={filterPhone}
            setFilterPhone={setFilterPhone}
            filterTracking={filterTracking}
            setFilterTracking={setFilterTracking}
            deliveryTabFilter={deliveryTabFilter}
            setDeliveryTabFilter={setDeliveryTabFilter}
            deliveryVisibleCount={deliveryVisibleCount}
            deliveryGroups={deliveryGroups}
            sendGroupToDelivery={sendGroupToDelivery}
            setDeliveryInputPhone={setDeliveryInputPhone}
            setDeliveryInputValue={setDeliveryInputValue}
            deliveryInputPhone={deliveryInputPhone}
            deliveryInputValue={deliveryInputValue}
            setDeliveryStatusForPhone={setDeliveryStatusForPhone}
            amountOf={amountOf}
            formatCurrency={formatCurrency}
            StatusChip={StatusChip}
          />
        )}
        {activeSection === 'list-payments' && (
          <AdminPayments
            paymentPhoneQuery={paymentPhoneQuery}
            setPaymentPhoneQuery={setPaymentPhoneQuery}
            paymentTrackingQuery={paymentTrackingQuery}
            setPaymentTrackingQuery={setPaymentTrackingQuery}
            paymentFilteredRecords={paymentFilteredRecords}
            paymentAmounts={paymentAmounts}
            handlePaymentAmountChange={handlePaymentAmountChange}
            payCustom={payCustom}
            payRemaining={payRemaining}
            updateRecordLocation={updateRecordLocation}
            amountOf={amountOf}
            formatCurrency={formatCurrency}
            StatusChip={StatusChip}
            setScannerTarget={setScannerTarget}
          />
        )}

        {activeSection === 'create' && (
          <AdminCreate
            formData={formData}
            handleFormChange={handleFormChange}
            handleFormSubmit={handleFormSubmit}
            autoFillTracking={autoFillTracking}
            setAutoFillTracking={setAutoFillTracking}
            setScannerTarget={setScannerTarget}
            toast={toast}
          />
        )}

        {scannerTarget && (
          <BarcodeScanner open onClose={() => setScannerTarget(null)} onDetect={handleScannerDetected} />
        )}
      </div>
    </div>
  )
}
