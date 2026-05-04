import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ArrowDown,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  Shield,
  Target,
  TrendingDown,
  TrendingUp,
  X,
  Zap,
} from 'lucide-react'
import { useAuthStore } from '@/stores/authStore'
import { useThemeStore } from '@/stores/themeStore'
import { useMarketData } from '@/hooks/useMarketData'
import { tradingApi } from '@/api/trading'
import { optionChainApi } from '@/api/option-chain'
import { scalperBracketApi } from '@/api/scalper-bracket'
import type { BracketOrder } from '@/api/scalper-bracket'
import type { PlaceOrderRequest } from '@/types/trading'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { showToast } from '@/utils/toast'
import { cn } from '@/lib/utils'

// ==================== Constants ====================

const UNDERLYINGS = [
  { value: 'NIFTY', exchange: 'NFO', strikeGap: 50 },
  { value: 'BANKNIFTY', exchange: 'NFO', strikeGap: 100 },
  { value: 'FINNIFTY', exchange: 'NFO', strikeGap: 50 },
  { value: 'MIDCPNIFTY', exchange: 'NFO', strikeGap: 25 },
  { value: 'SENSEX', exchange: 'BFO', strikeGap: 100 },
  { value: 'BANKEX', exchange: 'BFO', strikeGap: 100 },
]

// Fallback lot sizes (used if API unavailable) — will be overridden by dynamic values
const FALLBACK_LOT_SIZES: Record<string, number> = {
  NIFTY: 65, BANKNIFTY: 30, FINNIFTY: 65, MIDCPNIFTY: 120,
  SENSEX: 20, BANKEX: 30,
}

const LOT_PRESETS = [1, 2, 3, 5, 10]

const INDEX_EXCHANGE_MAP: Record<string, string> = {
  NIFTY: 'NSE_INDEX',
  BANKNIFTY: 'NSE_INDEX',
  FINNIFTY: 'NSE_INDEX',
  MIDCPNIFTY: 'NSE_INDEX',
  SENSEX: 'BSE_INDEX',
  BANKEX: 'BSE_INDEX',
}

// ==================== Helpers ====================

function formatPrice(price: number | null | undefined): string {
  if (price === null || price === undefined) return '0.00'
  return price.toFixed(2)
}

function convertExpiryToSymbol(expiry: string): string {
  // Expiry comes as "06-MAR-25" → "06MAR25" for symbol construction
  return expiry.replace(/-/g, '')
}

function buildOptionSymbol(underlying: string, expiry: string, strike: number, type: 'CE' | 'PE'): string {
  const exp = convertExpiryToSymbol(expiry)
  return `${underlying}${exp}${strike}${type}`
}

// ==================== Types ====================

interface ScalperPosition {
  symbol: string
  exchange: string
  product: string
  quantity: number
  averagePrice: number
  ltp: number
  pnl: number
}

// ==================== Component ====================

function ScalperTerminal() {
  const { apiKey } = useAuthStore()
  const { appMode } = useThemeStore()
  const isAnalyzer = appMode === 'analyzer'

  // Core state
  const [underlying, setUnderlying] = useState('NIFTY')
  const [expiry, setExpiry] = useState('')
  const [expiries, setExpiries] = useState<string[]>([])
  const [product, setProduct] = useState<'MIS' | 'NRML'>('NRML')
  const [lots, setLots] = useState(1)
  const [customLots, setCustomLots] = useState('')

  // Dynamic lot sizes from master contract DB (starts with fallbacks, updated from API)
  const [lotSizeMap, setLotSizeMap] = useState<Record<string, number>>(FALLBACK_LOT_SIZES)

  // Strike state
  const [spotLtp, setSpotLtp] = useState(0)
  const [atmStrike, setAtmStrike] = useState(0)
  const [strikeOffset, setStrikeOffset] = useState(0)

  // UI state
  const [isLoadingExpiries, setIsLoadingExpiries] = useState(false)
  const [isRefreshingLtp, setIsRefreshingLtp] = useState(false)
  const [orderInProgress, setOrderInProgress] = useState<string | null>(null) // null | 'BUY-CE' | 'BUY-PE' | 'SELL-CE' | 'SELL-PE'
  const [isExitingAll, setIsExitingAll] = useState(false)
  const [exitingPosition, setExitingPosition] = useState<string | null>(null)
  const [positions, setPositions] = useState<ScalperPosition[]>([])
  const [isLoadingPositions, setIsLoadingPositions] = useState(false)
  const [initError, setInitError] = useState<string | null>(null)
  const [initTrigger, setInitTrigger] = useState(0) // Increment to re-trigger initialization

  // Track whether first data load is complete (expiries + LTP)
  const [isInitializing, setIsInitializing] = useState(true)
  const initDoneRef = useRef(false)

  // Bracket order settings
  const [bracketEnabled, setBracketEnabled] = useState(true)
  const [bracketMode, setBracketModeRaw] = useState<'broker' | 'ui'>('broker')
  // In analyzer mode, force bracket mode to 'ui' (broker SL orders don't work in sandbox)
  const effectiveBracketMode = isAnalyzer ? 'ui' : bracketMode
  const setBracketMode = (v: 'broker' | 'ui') => setBracketModeRaw(v)
  const [slPoints, setSlPoints] = useState(15)
  const [targetPoints, setTargetPoints] = useState(20)
  const [trailEnabled, setTrailEnabled] = useState(true)
  const [trailStep, setTrailStep] = useState(5)

  // Active bracket orders (keyed by symbol)
  const [activeBrackets, setActiveBrackets] = useState<Map<string, BracketOrder>>(new Map())
  const bracketCheckRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const bracketActionInProgress = useRef<Set<string>>(new Set()) // prevent concurrent actions per symbol

  // Refs
  const positionTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const priceTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Derived values
  const underlyingConfig = useMemo(
    () => {
      const base = UNDERLYINGS.find((u) => u.value === underlying)!
      return { ...base, lotSize: lotSizeMap[underlying] || FALLBACK_LOT_SIZES[underlying] || 1 }
    },
    [underlying, lotSizeMap]
  )
  const currentStrike = useMemo(
    () => atmStrike + strikeOffset * underlyingConfig.strikeGap,
    [atmStrike, strikeOffset, underlyingConfig.strikeGap]
  )
  const ceSymbol = useMemo(
    () => (expiry && currentStrike ? buildOptionSymbol(underlying, expiry, currentStrike, 'CE') : ''),
    [underlying, expiry, currentStrike]
  )
  const peSymbol = useMemo(
    () => (expiry && currentStrike ? buildOptionSymbol(underlying, expiry, currentStrike, 'PE') : ''),
    [underlying, expiry, currentStrike]
  )
  const quantity = lots * underlyingConfig.lotSize

  // WebSocket subscriptions for CE, PE, and position symbols (for bracket monitoring)
  const wsSymbols = useMemo(() => {
    const syms: Array<{ symbol: string; exchange: string }> = []
    if (ceSymbol) syms.push({ symbol: ceSymbol, exchange: underlyingConfig.exchange })
    if (peSymbol) syms.push({ symbol: peSymbol, exchange: underlyingConfig.exchange })
    // Add position symbols for live LTP in bracket monitoring
    for (const pos of positions) {
      if (!syms.find(s => s.symbol === pos.symbol && s.exchange === pos.exchange)) {
        syms.push({ symbol: pos.symbol, exchange: pos.exchange })
      }
    }
    return syms
  }, [ceSymbol, peSymbol, underlyingConfig.exchange, positions])

  const { data: marketData, isConnected } = useMarketData({
    symbols: wsSymbols,
    mode: 'Quote',
    enabled: wsSymbols.length > 0,
  })

  // REST API fallback prices (polled when WebSocket data is absent)
  const [restPrices, setRestPrices] = useState<Map<string, number>>(new Map())
  const restPollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // REST API polling for CE/PE prices — like AlgoMirror's /scalper/api/option-prices
  const fetchRestPrices = useCallback(async () => {
    if (!apiKey) return
    const symbolsToFetch: Array<{ symbol: string; exchange: string }> = []
    if (ceSymbol) symbolsToFetch.push({ symbol: ceSymbol, exchange: underlyingConfig.exchange })
    if (peSymbol) symbolsToFetch.push({ symbol: peSymbol, exchange: underlyingConfig.exchange })
    // Also fetch position symbols for bracket monitoring
    for (const pos of positions) {
      if (!symbolsToFetch.find(s => s.symbol === pos.symbol && s.exchange === pos.exchange)) {
        symbolsToFetch.push({ symbol: pos.symbol, exchange: pos.exchange })
      }
    }
    if (symbolsToFetch.length === 0) return
    try {
      const resp = await tradingApi.getMultiQuotes(apiKey, symbolsToFetch)
      if (resp.status === 'success' && resp.results) {
        setRestPrices(prev => {
          const updated = new Map(prev)
          for (const r of resp.results!) {
            if (r.data?.ltp) {
              updated.set(`${r.exchange}:${r.symbol}`, r.data.ltp)
            }
          }
          return updated
        })
      }
    } catch { /* silent */ }
  }, [apiKey, ceSymbol, peSymbol, underlyingConfig.exchange, positions])

  // Start REST polling when symbols are ready, refresh every 3s
  useEffect(() => {
    if (!ceSymbol && !peSymbol) return
    // Fetch immediately
    fetchRestPrices()
    restPollRef.current = setInterval(fetchRestPrices, 3000)
    return () => {
      if (restPollRef.current) clearInterval(restPollRef.current)
    }
  }, [fetchRestPrices, ceSymbol, peSymbol])

  const cePrice = useMemo(() => {
    if (!ceSymbol) return 0
    const key = `${underlyingConfig.exchange}:${ceSymbol}`
    // Priority: WebSocket LTP → REST API fallback
    const wsLtp = marketData.get(key)?.data?.ltp
    if (wsLtp && wsLtp > 0) return wsLtp
    return restPrices.get(key) ?? 0
  }, [marketData, ceSymbol, underlyingConfig.exchange, restPrices])

  const pePrice = useMemo(() => {
    if (!peSymbol) return 0
    const key = `${underlyingConfig.exchange}:${peSymbol}`
    // Priority: WebSocket LTP → REST API fallback
    const wsLtp = marketData.get(key)?.data?.ltp
    if (wsLtp && wsLtp > 0) return wsLtp
    return restPrices.get(key) ?? 0
  }, [marketData, peSymbol, underlyingConfig.exchange, restPrices])

  // Previous prices for flash animation
  const prevCePrice = useRef(0)
  const prevPePrice = useRef(0)
  const [ceFlash, setCeFlash] = useState<'up' | 'down' | null>(null)
  const [peFlash, setPeFlash] = useState<'up' | 'down' | null>(null)

  useEffect(() => {
    if (cePrice && prevCePrice.current && cePrice !== prevCePrice.current) {
      setCeFlash(cePrice > prevCePrice.current ? 'up' : 'down')
      const timer = setTimeout(() => setCeFlash(null), 500)
      return () => clearTimeout(timer)
    }
    prevCePrice.current = cePrice
  }, [cePrice])

  useEffect(() => {
    if (pePrice && prevPePrice.current && pePrice !== prevPePrice.current) {
      setPeFlash(pePrice > prevPePrice.current ? 'up' : 'down')
      const timer = setTimeout(() => setPeFlash(null), 500)
      return () => clearTimeout(timer)
    }
    prevPePrice.current = pePrice
  }, [pePrice])

  // ==================== API Calls ====================

  const refreshLtp = useCallback(async () => {
    if (!apiKey || !expiry) return
    setIsRefreshingLtp(true)
    try {
      const indexExchange = INDEX_EXCHANGE_MAP[underlying] || 'NSE_INDEX'
      const expiryFormatted = convertExpiryToSymbol(expiry) // "06-MAR-25" → "06MAR25"
      const response = await optionChainApi.getOptionSymbol(
        apiKey, underlying, indexExchange, expiryFormatted, 'ATM', 'CE'
      )
      if (response.status === 'success' && response.underlying_ltp) {
        const ltp = response.underlying_ltp
        setSpotLtp(ltp)
        const atm = Math.round(ltp / underlyingConfig.strikeGap) * underlyingConfig.strikeGap
        setAtmStrike(atm)
        setStrikeOffset(0)
        // Update lot size from the same response
        if (response.lotsize) {
          setLotSizeMap(prev => ({ ...prev, [underlying]: response.lotsize! }))
        }
        setInitError(null)
      } else {
        showToast.error(response.message || 'Failed to fetch LTP')
      }
    } catch {
      showToast.error('Failed to fetch LTP')
    }
    setIsRefreshingLtp(false)
    // Mark initialization as complete after first successful LTP fetch
    if (!initDoneRef.current) {
      initDoneRef.current = true
      setIsInitializing(false)
    }
  }, [apiKey, underlying, expiry, underlyingConfig.strikeGap])

  const refreshPositions = useCallback(async () => {
    if (!apiKey) return
    setIsLoadingPositions(true)
    try {
      const response = await tradingApi.getPositions(apiKey)
      if (response.status === 'success' && response.data) {
        // Filter to only FnO positions with non-zero quantity
        const fnoPositions = response.data
          .filter((p) => {
            const isFnO = p.exchange === 'NFO' || p.exchange === 'BFO'
            return isFnO && p.quantity !== 0
          })
          .map((p) => ({
            symbol: p.symbol,
            exchange: p.exchange,
            product: p.product,
            quantity: p.quantity,
            averagePrice: p.average_price,
            ltp: p.ltp,
            pnl: p.pnl,
          }))
        setPositions(fnoPositions)
      }
    } catch {
      console.error('Failed to fetch positions')
    }
    setIsLoadingPositions(false)
  }, [apiKey])

  // ==================== Bracket Order Helpers ====================

  const refreshBrackets = useCallback(async () => {
    try {
      const resp = await scalperBracketApi.getStatus()
      if (resp.status === 'success') {
        const map = new Map<string, BracketOrder>()
        for (const b of resp.brackets) {
          map.set(b.symbol, b)
        }
        setActiveBrackets(map)
      }
    } catch (e) {
      console.error('Failed to fetch brackets:', e)
    }
  }, [])

  const placeOrder = useCallback(
    async (optionType: 'CE' | 'PE', action: 'BUY' | 'SELL') => {
      if (!apiKey || orderInProgress) return
      if (!expiry) {
        showToast.warning('Select an expiry first')
        return
      }

      const symbol = optionType === 'CE' ? ceSymbol : peSymbol
      if (!symbol) {
        showToast.error('Symbol not ready')
        return
      }

      const orderId = `${action}-${optionType}`
      setOrderInProgress(orderId)

      try {
        const orderReq: PlaceOrderRequest = {
          apikey: apiKey,
          strategy: 'Scalper',
          exchange: underlyingConfig.exchange,
          symbol,
          action,
          quantity,
          pricetype: 'MARKET',
          product,
        }

        const response = await tradingApi.placeOrder(orderReq)
        if (response.status === 'success') {
          showToast.success(`${action} ${optionType} order placed`, 'orders')

          // Place bracket SL if bracket is enabled
          if (bracketEnabled) {
            const entryPrice = optionType === 'CE' ? cePrice : pePrice
            if (entryPrice > 0) {
              try {
                const bracketResp = await scalperBracketApi.placeSL({
                  symbol,
                  exchange: underlyingConfig.exchange,
                  product,
                  entry_action: action,
                  quantity,
                  entry_price: entryPrice,
                  sl_points: slPoints,
                  target_points: targetPoints,
                  trail_enabled: trailEnabled,
                  trail_step: trailStep,
                  bracket_mode: effectiveBracketMode,
                })
                if (bracketResp.status === 'success') {
                  showToast.success(bracketResp.message || 'Bracket SL placed', 'orders')
                  refreshBrackets()
                } else {
                  showToast.error(bracketResp.message || 'Bracket SL failed', 'orders')
                }
              } catch (bracketErr) {
                showToast.error(`Bracket SL error: ${bracketErr instanceof Error ? bracketErr.message : 'Unknown'}`, 'orders')
              }
            }
          }
        } else {
          showToast.error(response.message || 'Order failed', 'orders')
        }

        // Refresh positions after order
        setTimeout(() => refreshPositions(), 1000)
      } catch (e) {
        showToast.error(`Order failed: ${e instanceof Error ? e.message : 'Unknown error'}`, 'orders')
      }

      setOrderInProgress(null)
    },
    [apiKey, expiry, ceSymbol, peSymbol, underlyingConfig.exchange, quantity, product, orderInProgress, refreshPositions, bracketEnabled, effectiveBracketMode, slPoints, targetPoints, trailEnabled, trailStep, cePrice, pePrice, refreshBrackets]
  )

  const exitPosition = useCallback(
    async (pos: ScalperPosition) => {
      setExitingPosition(pos.symbol)
      try {
        // Cancel any active bracket SL before exiting
        const bracket = activeBrackets.get(pos.symbol)
        if (bracket) {
          try {
            await scalperBracketApi.cancelSL({
              symbol: pos.symbol,
              exchange: pos.exchange,
              product: pos.product,
            })
          } catch { /* ignore cancel errors */ }
        }

        const response = await tradingApi.closePosition(pos.symbol, pos.exchange, pos.product)
        if (response.status === 'success') {
          showToast.success(`Exited ${pos.symbol}`, 'orders')
        } else {
          showToast.error(response.message || 'Exit failed', 'orders')
        }
        setTimeout(() => { refreshPositions(); refreshBrackets() }, 1000)
      } catch (e) {
        showToast.error(`Exit failed: ${e instanceof Error ? e.message : 'Unknown error'}`, 'orders')
      }
      setExitingPosition(null)
    },
    [refreshPositions, refreshBrackets, activeBrackets]
  )

  const exitAllPositions = useCallback(async () => {
    if (positions.length === 0) {
      showToast.info('No positions to exit')
      return
    }
    setIsExitingAll(true)
    try {
      // Cancel all active brackets first
      for (const [, bracket] of activeBrackets) {
        try {
          await scalperBracketApi.cancelSL({
            symbol: bracket.symbol,
            exchange: bracket.exchange,
            product: bracket.product,
          })
        } catch { /* ignore */ }
      }

      const response = await tradingApi.closeAllPositions()
      if (response.status === 'success') {
        showToast.success('All positions closed', 'orders')
      } else {
        showToast.error(response.message || 'Exit all failed', 'orders')
      }
      setTimeout(() => { refreshPositions(); refreshBrackets() }, 1000)
    } catch (e) {
      showToast.error(`Exit all failed: ${e instanceof Error ? e.message : 'Unknown error'}`, 'orders')
    }
    setIsExitingAll(false)
  }, [positions.length, refreshPositions, refreshBrackets, activeBrackets])

  // ==================== Partial Exit & TSL Update ====================

  const partialExit = useCallback(
    async (pos: ScalperPosition, fraction: number) => {
      const absQty = Math.abs(pos.quantity)
      const lotSize = lotSizeMap[underlying] || FALLBACK_LOT_SIZES[underlying] || 1
      let exitQty = Math.floor(absQty * fraction)
      // Snap to lot size
      if (lotSize > 1) {
        exitQty = Math.floor(exitQty / lotSize) * lotSize
      }
      if (exitQty <= 0) {
        showToast.warning(`Cannot partial exit: qty too small (${absQty} × ${Math.round(fraction * 100)}%)`)
        return
      }
      if (exitQty >= absQty) exitQty = absQty

      try {
        showToast.info(`Partial exit ${Math.round(fraction * 100)}%: ${exitQty} of ${absQty}...`, 'orders')
        const resp = await scalperBracketApi.partialExit({
          symbol: pos.symbol,
          exchange: pos.exchange,
          product: pos.product,
          quantity: pos.quantity,
          exit_qty: exitQty,
        })
        if (resp.status === 'success') {
          showToast.success(`Partial exit: ${exitQty} qty of ${pos.symbol}`, 'orders')
          setTimeout(() => { refreshPositions(); refreshBrackets() }, 1000)
        } else {
          showToast.error(resp.message || 'Partial exit failed', 'orders')
        }
      } catch (e) {
        showToast.error(`Partial exit error: ${e instanceof Error ? e.message : 'Unknown'}`, 'orders')
      }
    },
    [lotSizeMap, underlying, refreshPositions, refreshBrackets]
  )

  const updateSLPrice = useCallback(
    async (pos: ScalperPosition, newSL: number) => {
      if (!newSL || newSL <= 0) {
        showToast.error('Invalid SL price')
        return
      }
      const bracket = activeBrackets.get(pos.symbol)
      if (!bracket) {
        showToast.warning('No active bracket for this position')
        return
      }
      const isLong = bracket.action === 'BUY'
      if (isLong && newSL >= pos.ltp) {
        showToast.error(`SL ${newSL.toFixed(2)} must be below LTP ${pos.ltp.toFixed(2)} for long position`)
        return
      }
      if (!isLong && newSL <= pos.ltp) {
        showToast.error(`SL ${newSL.toFixed(2)} must be above LTP ${pos.ltp.toFixed(2)} for short position`)
        return
      }
      try {
        const resp = await scalperBracketApi.updateSL({
          symbol: pos.symbol,
          exchange: pos.exchange,
          product: pos.product,
          new_sl_price: newSL,
          current_ltp: pos.ltp,
        })
        if (resp.status === 'success') {
          showToast.success(`SL updated → ₹${(resp.new_sl_price || newSL).toFixed(2)}`, 'orders')
          refreshBrackets()
        } else {
          showToast.error(resp.message || 'SL update failed', 'orders')
        }
      } catch (e) {
        showToast.error(`SL update error: ${e instanceof Error ? e.message : 'Unknown'}`, 'orders')
      }
    },
    [activeBrackets, refreshBrackets]
  )

  // ==================== Effects ====================

  // Primary initialization: load expiries + LTP in one sequential flow with retry
  // Modeled after OptionChain's retry pattern for master contract readiness
  useEffect(() => {
    let cancelled = false
    let retryTimer: ReturnType<typeof setTimeout> | null = null

    const initialize = async () => {
      if (!apiKey) return
      setIsInitializing(true)
      setInitError(null)
      initDoneRef.current = false

      const exchange = UNDERLYINGS.find((u) => u.value === underlying)!.exchange
      const strikeGap = UNDERLYINGS.find((u) => u.value === underlying)!.strikeGap
      const indexExchange = INDEX_EXCHANGE_MAP[underlying] || 'NSE_INDEX'

      // Step 1: Load expiries with retry (master contract may still be downloading)
      const MAX_RETRIES = 10
      let retryCount = 0
      let loadedExpiries: string[] = []

      const tryLoadExpiries = async (): Promise<boolean> => {
        try {
          const resp = await optionChainApi.getExpiries(apiKey, underlying, exchange)
          if (cancelled) return false
          if (resp.status === 'success' && resp.data?.length > 0) {
            loadedExpiries = resp.data
            return true
          }
          return false
        } catch {
          return false
        }
      }

      let gotExpiries = await tryLoadExpiries()
      while (!gotExpiries && retryCount < MAX_RETRIES && !cancelled) {
        retryCount++
        console.log(`[Scalper] Expiry retry ${retryCount}/${MAX_RETRIES} — master contract may still be loading`)
        await new Promise<void>((resolve) => {
          retryTimer = setTimeout(resolve, 2000)
        })
        if (cancelled) return
        gotExpiries = await tryLoadExpiries()
      }

      if (cancelled) return

      if (!gotExpiries) {
        setInitError('No expiry data found. Master contract may not be loaded yet.')
        setIsInitializing(false)
        return
      }

      setExpiries(loadedExpiries)
      setExpiry(loadedExpiries[0])
      setIsLoadingExpiries(false)

      // Step 2: Get LTP + lot size using the just-loaded expiry
      try {
        const expiryFormatted = convertExpiryToSymbol(loadedExpiries[0])
        const resp = await optionChainApi.getOptionSymbol(
          apiKey, underlying, indexExchange, expiryFormatted, 'ATM', 'CE'
        )
        if (cancelled) return
        if (resp.status === 'success' && resp.underlying_ltp) {
          setSpotLtp(resp.underlying_ltp)
          const atm = Math.round(resp.underlying_ltp / strikeGap) * strikeGap
          setAtmStrike(atm)
          setStrikeOffset(0)
          if (resp.lotsize) {
            setLotSizeMap((prev) => ({ ...prev, [underlying]: resp.lotsize! }))
          }
        } else {
          setInitError(resp.message || 'Failed to fetch LTP')
        }
      } catch {
        if (!cancelled) setInitError('Failed to fetch LTP')
      }

      if (!cancelled) {
        initDoneRef.current = true
        setIsInitializing(false)
      }
    }

    initialize()

    return () => {
      cancelled = true
      if (retryTimer) clearTimeout(retryTimer)
    }
  }, [apiKey, underlying, initTrigger]) // eslint-disable-line react-hooks/exhaustive-deps
  // Note: Only re-run on apiKey, underlying change, or manual retry. Other deps are derived from these.

  // Refresh LTP when user manually changes expiry via dropdown (not during init)
  useEffect(() => {
    if (expiry && initDoneRef.current) {
      refreshLtp()
    }
  }, [expiry]) // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-refresh positions periodically
  useEffect(() => {
    if (spotLtp > 0) {
      refreshPositions()
      positionTimerRef.current = setInterval(refreshPositions, 5000)
    }
    return () => {
      if (positionTimerRef.current) clearInterval(positionTimerRef.current)
    }
  }, [spotLtp, refreshPositions])

  // Load brackets on mount + refresh them with positions
  useEffect(() => {
    if (spotLtp > 0) {
      refreshBrackets()
    }
  }, [spotLtp, refreshBrackets])

  // ==================== Bracket Monitoring Loop ====================
  // Runs every 1 second: check LTP vs SL/Target/Trail for each active bracket
  useEffect(() => {
    if (activeBrackets.size === 0) {
      if (bracketCheckRef.current) {
        clearInterval(bracketCheckRef.current)
        bracketCheckRef.current = null
      }
      return
    }

    const checkBrackets = async () => {
      for (const [symbol, bracket] of activeBrackets) {
        // Skip if action already in progress for this symbol
        if (bracketActionInProgress.current.has(symbol)) continue

        // Get live LTP: WebSocket → REST API fallback → position LTP
        const wsKey = `${bracket.exchange}:${symbol}`
        const wsLtp = marketData.get(wsKey)?.data?.ltp
        const restLtp = restPrices.get(wsKey)
        const pos = positions.find(p => p.symbol === symbol)
        const ltp = (wsLtp && wsLtp > 0) ? wsLtp : (restLtp && restLtp > 0) ? restLtp : pos?.ltp
        if (!ltp || ltp <= 0) continue

        const isLong = bracket.action === 'BUY'

        // 1) Check target hit (both modes) — skip when trailing is enabled
        //    (trailing SL replaces fixed target: target will trail alongside SL)
        if (bracket.target_price > 0 && !bracket.trail_enabled) {
          const targetHit = isLong ? ltp >= bracket.target_price : ltp <= bracket.target_price
          if (targetHit) {
            bracketActionInProgress.current.add(symbol)
            try {
              showToast.success(`TARGET HIT: ${symbol} @ ₹${ltp.toFixed(2)}`, 'orders')
              await scalperBracketApi.targetExit({
                symbol: bracket.symbol,
                exchange: bracket.exchange,
                product: bracket.product,
                quantity: bracket.quantity,
              })
              setTimeout(() => { refreshPositions(); refreshBrackets() }, 1000)
            } catch (e) {
              console.error(`Target exit failed for ${symbol}:`, e)
            } finally {
              bracketActionInProgress.current.delete(symbol)
            }
            continue
          }
        }

        // 2) Check SL hit (UI mode only — broker mode has actual SL order on exchange)
        if (bracket.bracket_mode === 'ui' && bracket.sl_price > 0) {
          const slHit = isLong ? ltp <= bracket.sl_price : ltp >= bracket.sl_price
          if (slHit) {
            bracketActionInProgress.current.add(symbol)
            try {
              showToast.error(`SL HIT: ${symbol} @ ₹${ltp.toFixed(2)}`, 'orders')
              await scalperBracketApi.slExit({
                symbol: bracket.symbol,
                exchange: bracket.exchange,
                product: bracket.product,
                quantity: bracket.quantity,
              })
              setTimeout(() => { refreshPositions(); refreshBrackets() }, 1000)
            } catch (e) {
              console.error(`SL exit failed for ${symbol}:`, e)
            } finally {
              bracketActionInProgress.current.delete(symbol)
            }
            continue
          }
        }

        // 3) Check trailing SL
        if (bracket.trail_enabled && bracket.trail_step && bracket.trail_step > 0) {
          const currentBest = bracket.best_price || bracket.entry_price
          const movedFavorably = isLong
            ? ltp > currentBest + bracket.trail_step
            : ltp < currentBest - bracket.trail_step

          if (movedFavorably) {
            bracketActionInProgress.current.add(symbol)
            try {
              const newBest = ltp
              // Calculate how much to trail
              const steps = Math.floor(Math.abs(ltp - currentBest) / bracket.trail_step)
              const trailAmount = steps * bracket.trail_step
              const newSl = isLong
                ? bracket.sl_price + trailAmount
                : bracket.sl_price - trailAmount
              // Trail target alongside SL so it stays ahead of price
              const newTarget = bracket.target_price > 0
                ? (isLong ? bracket.target_price + trailAmount : bracket.target_price - trailAmount)
                : 0

              await scalperBracketApi.trailSL({
                symbol: bracket.symbol,
                exchange: bracket.exchange,
                product: bracket.product,
                new_sl_price: newSl,
                best_price: newBest,
                new_target_price: newTarget,
              })
              showToast.info(`Trail: SL → ₹${newSl.toFixed(2)} | TGT → ₹${newTarget.toFixed(2)}`, 'orders')
              refreshBrackets()
            } catch (e) {
              console.error(`Trail SL failed for ${symbol}:`, e)
            } finally {
              bracketActionInProgress.current.delete(symbol)
            }
          }
        }
      }
    }

    bracketCheckRef.current = setInterval(checkBrackets, 1000)
    return () => {
      if (bracketCheckRef.current) clearInterval(bracketCheckRef.current)
      bracketCheckRef.current = null
    }
  }, [activeBrackets, marketData, restPrices, positions, refreshPositions, refreshBrackets])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (positionTimerRef.current) clearInterval(positionTimerRef.current)
      if (priceTimerRef.current) clearInterval(priceTimerRef.current)
      if (bracketCheckRef.current) clearInterval(bracketCheckRef.current)
      if (restPollRef.current) clearInterval(restPollRef.current)
    }
  }, [])

  // ==================== Lot Selection ====================

  const handleLotPreset = useCallback((n: number) => {
    setLots(n)
    setCustomLots('')
  }, [])

  const handleCustomLots = useCallback((val: string) => {
    setCustomLots(val)
    const n = parseInt(val)
    if (n && n > 0) setLots(n)
  }, [])

  // Smart refresh: reloads everything if no data yet, otherwise just refreshes LTP + lot size
  const handleRefresh = useCallback(async () => {
    if (expiries.length === 0 || !expiry) {
      // No data — re-trigger the initialization effect
      setInitTrigger((prev) => prev + 1)
    } else {
      await refreshLtp()
    }
  }, [expiries.length, expiry, refreshLtp])

  // ==================== Keyboard Shortcuts ====================

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (target.tagName === 'INPUT' || target.tagName === 'SELECT' || target.tagName === 'TEXTAREA') return

      switch (e.key) {
        case 'C': // Shift+C → Sell CE
          e.preventDefault()
          placeOrder('CE', 'SELL')
          break
        case 'P': // Shift+P → Sell PE
          e.preventDefault()
          placeOrder('PE', 'SELL')
          break
        case 'c': // c → Buy CE
          e.preventDefault()
          placeOrder('CE', 'BUY')
          break
        case 'p': // p → Buy PE
          e.preventDefault()
          placeOrder('PE', 'BUY')
          break
        case 'x':
          e.preventDefault()
          exitAllPositions()
          break
        case 'r':
          e.preventDefault()
          handleRefresh()
          break
        case 'ArrowLeft':
          e.preventDefault()
          setStrikeOffset((prev) => prev - 1)
          break
        case 'ArrowRight':
          e.preventDefault()
          setStrikeOffset((prev) => prev + 1)
          break
        case 'ArrowUp':
          e.preventDefault()
          setLots((prev) => {
            const idx = LOT_PRESETS.indexOf(prev)
            if (idx >= 0 && idx < LOT_PRESETS.length - 1) return LOT_PRESETS[idx + 1]
            return Math.max(1, prev + 1)
          })
          break
        case 'ArrowDown':
          e.preventDefault()
          setLots((prev) => {
            const idx = LOT_PRESETS.indexOf(prev)
            if (idx > 0) return LOT_PRESETS[idx - 1]
            return Math.max(1, prev - 1)
          })
          break
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [placeOrder, exitAllPositions, handleRefresh])

  // ==================== Computed ====================

  const strikeLabel = useMemo(() => {
    if (strikeOffset === 0) return 'ATM'
    if (strikeOffset > 0) return `ATM + ${strikeOffset} (OTM CE / ITM PE)`
    return `ATM ${strikeOffset} (ITM CE / OTM PE)`
  }, [strikeOffset])

  const totalPnl = useMemo(
    () => positions.reduce((sum, p) => sum + p.pnl, 0),
    [positions]
  )

  // ==================== Render ====================

  // Show initialization loading state
  if (isInitializing && !initDoneRef.current) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Zap className="h-5 w-5 text-primary" />
          <h1 className="text-2xl font-bold">Scalper Terminal</h1>
        </div>
        <Card>
          <CardContent className="p-8">
            <div className="flex flex-col items-center justify-center gap-3">
              <RefreshCw className="h-8 w-8 animate-spin text-primary" />
              <p className="text-sm text-muted-foreground">
                {isLoadingExpiries ? 'Loading expiry dates...' : isRefreshingLtp ? 'Fetching market data...' : 'Initializing...'}
              </p>
              {initError && (
                <div className="text-center mt-2">
                  <p className="text-sm text-destructive">{initError}</p>
                  <Button variant="outline" size="sm" className="mt-2" onClick={handleRefresh}>
                    <RefreshCw className="h-4 w-4 mr-1" /> Retry
                  </Button>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <TooltipProvider>
      <div className="space-y-4">
        {/* Page Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-primary" />
            <h1 className="text-2xl font-bold">Scalper Terminal</h1>
          </div>
          <div className="flex items-center gap-2">
            {isAnalyzer && (
              <Badge className="text-xs bg-purple-500 hover:bg-purple-600 text-white">
                Analyzer Mode
              </Badge>
            )}
            <Badge variant={isConnected ? 'default' : 'destructive'} className="text-xs">
              {isConnected ? 'Live' : 'Offline'}
            </Badge>
          </div>
        </div>

        {/* Top Controls Bar */}
        <Card>
          <CardContent className="p-4">
            <div className="flex flex-wrap items-end gap-4">
              {/* Underlying */}
              <div className="w-44">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1 block">
                  Underlying
                </label>
                <Select
                  value={underlying}
                  onValueChange={(val) => {
                    setUnderlying(val)
                    setStrikeOffset(0)
                    setSpotLtp(0)
                    setAtmStrike(0)
                  }}
                >
                  <SelectTrigger className="h-9">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {UNDERLYINGS.map((u) => (
                      <SelectItem key={u.value} value={u.value}>
                        {u.value}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Expiry */}
              <div className="w-48">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1 block">
                  Expiry
                </label>
                <Select
                  value={expiry}
                  onValueChange={setExpiry}
                  disabled={isLoadingExpiries || expiries.length === 0}
                >
                  <SelectTrigger className="h-9">
                    <SelectValue placeholder={isLoadingExpiries ? 'Loading...' : 'Select expiry'} />
                  </SelectTrigger>
                  <SelectContent>
                    {expiries.map((exp) => (
                      <SelectItem key={exp} value={exp}>
                        {exp}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Product */}
              <div className="w-36">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1 block">
                  Product
                </label>
                <Select value={product} onValueChange={(v) => setProduct(v as 'MIS' | 'NRML')}>
                  <SelectTrigger className="h-9">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="MIS">MIS (Intraday)</SelectItem>
                    <SelectItem value="NRML">NRML (Carry)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Refresh */}
              <Button
                variant="outline"
                size="sm"
                onClick={handleRefresh}
                disabled={isRefreshingLtp || isLoadingExpiries}
                className="h-9"
              >
                <RefreshCw className={cn('h-4 w-4 mr-1', (isRefreshingLtp || isLoadingExpiries) && 'animate-spin')} />
                Refresh
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Main Trading Panel */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Left: Strike & Order Panel */}
          <div className="lg:col-span-2 space-y-4">
            {/* Strike Selection & Prices */}
            <Card>
              <CardContent className="p-4">
                {/* LTP Row */}
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-muted-foreground uppercase">
                      {underlying}
                    </span>
                    <span className={cn('text-xl font-bold', isRefreshingLtp && 'opacity-50 animate-pulse')}>
                      {spotLtp > 0 ? formatPrice(spotLtp) : '--'}
                    </span>
                  </div>
                  <Badge variant="outline" className="text-xs">
                    ATM: {atmStrike > 0 ? atmStrike : '--'}
                  </Badge>
                </div>

                {/* Strike Display */}
                <div className="flex items-center justify-center gap-4 py-4">
                  <Button
                    variant="outline"
                    size="icon"
                    className="h-9 w-9 rounded-full"
                    onClick={() => setStrikeOffset((prev) => prev - 1)}
                  >
                    <ChevronLeft className="h-5 w-5" />
                  </Button>
                  <div className="text-center">
                    <div className="text-4xl font-extrabold tabular-nums tracking-tight">
                      {currentStrike > 0 ? currentStrike : '--'}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">{strikeLabel}</div>
                  </div>
                  <Button
                    variant="outline"
                    size="icon"
                    className="h-9 w-9 rounded-full"
                    onClick={() => setStrikeOffset((prev) => prev + 1)}
                  >
                    <ChevronRight className="h-5 w-5" />
                  </Button>
                </div>

                {/* CE / PE Prices */}
                <div className="grid grid-cols-2 gap-4 mt-2">
                  <div className="rounded-lg p-3 text-center border bg-emerald-500/10 border-emerald-500/20">
                    <div className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 uppercase mb-1">
                      CE Price
                    </div>
                    <div
                      className={cn(
                        'text-lg font-semibold tabular-nums transition-colors duration-150',
                        ceFlash === 'up' && 'text-emerald-500',
                        ceFlash === 'down' && 'text-red-500'
                      )}
                    >
                      {cePrice > 0 ? `₹${formatPrice(cePrice)}` : '--'}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1 truncate" title={ceSymbol}>
                      {ceSymbol || '--'}
                    </div>
                  </div>
                  <div className="rounded-lg p-3 text-center border bg-red-500/10 border-red-500/20">
                    <div className="text-xs font-semibold text-red-600 dark:text-red-400 uppercase mb-1">
                      PE Price
                    </div>
                    <div
                      className={cn(
                        'text-lg font-semibold tabular-nums transition-colors duration-150',
                        peFlash === 'up' && 'text-emerald-500',
                        peFlash === 'down' && 'text-red-500'
                      )}
                    >
                      {pePrice > 0 ? `₹${formatPrice(pePrice)}` : '--'}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1 truncate" title={peSymbol}>
                      {peSymbol || '--'}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Lots & Action Buttons */}
            <Card>
              <CardContent className="p-4">
                {/* Lot Selector */}
                <div className="flex items-center gap-3 mb-4">
                  <span className="text-sm font-semibold text-muted-foreground uppercase">Lots</span>
                  <div className="flex gap-2">
                    {LOT_PRESETS.map((n) => (
                      <Button
                        key={n}
                        variant={lots === n && !customLots ? 'default' : 'outline'}
                        size="sm"
                        className="h-8 w-10 tabular-nums"
                        onClick={() => handleLotPreset(n)}
                      >
                        {n}
                      </Button>
                    ))}
                    <Input
                      type="number"
                      placeholder="#"
                      className="h-8 w-16 text-center font-bold tabular-nums"
                      min={1}
                      max={500}
                      value={customLots}
                      onChange={(e) => handleCustomLots(e.target.value)}
                      onFocus={(e) => e.target.select()}
                    />
                  </div>
                  <div className="flex items-center gap-1 ml-auto">
                    <span className="text-xs text-muted-foreground">Lot:</span>
                    <span className="text-xs tabular-nums text-muted-foreground">{underlyingConfig.lotSize}</span>
                    <span className="text-xs text-muted-foreground mx-1">×</span>
                    <span className="text-xs text-muted-foreground">{lots}</span>
                    <span className="text-xs text-muted-foreground mx-1">=</span>
                    <span className="text-xs text-muted-foreground">Qty:</span>
                    <span className="font-bold text-sm tabular-nums">{quantity}</span>
                  </div>
                </div>

                {/* BUY Buttons */}
                <div className="grid grid-cols-2 gap-4">
                  <Button
                    className="h-16 text-lg font-bold bg-emerald-500 hover:bg-emerald-600 text-white shadow-lg"
                    disabled={!!orderInProgress || !ceSymbol}
                    onClick={() => placeOrder('CE', 'BUY')}
                  >
                    {orderInProgress === 'BUY-CE' ? (
                      <RefreshCw className="h-5 w-5 animate-spin mr-2" />
                    ) : (
                      <TrendingUp className="h-5 w-5 mr-2" />
                    )}
                    <div className="flex flex-col items-center">
                      <span>BUY CE</span>
                      <span className="text-[10px] font-normal opacity-70">[C]</span>
                    </div>
                  </Button>
                  <Button
                    className="h-16 text-lg font-bold bg-red-500 hover:bg-red-600 text-white shadow-lg"
                    disabled={!!orderInProgress || !peSymbol}
                    onClick={() => placeOrder('PE', 'BUY')}
                  >
                    {orderInProgress === 'BUY-PE' ? (
                      <RefreshCw className="h-5 w-5 animate-spin mr-2" />
                    ) : (
                      <TrendingDown className="h-5 w-5 mr-2" />
                    )}
                    <div className="flex flex-col items-center">
                      <span>BUY PE</span>
                      <span className="text-[10px] font-normal opacity-70">[P]</span>
                    </div>
                  </Button>
                </div>

                {/* SELL Buttons */}
                <div className="grid grid-cols-2 gap-4 mt-3">
                  <Button
                    variant="outline"
                    className="h-14 text-base font-bold border-2 border-emerald-500 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/10"
                    disabled={!!orderInProgress || !ceSymbol}
                    onClick={() => placeOrder('CE', 'SELL')}
                  >
                    {orderInProgress === 'SELL-CE' ? (
                      <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                    ) : (
                      <ArrowDown className="h-4 w-4 mr-2" />
                    )}
                    <div className="flex flex-col items-center">
                      <span>SELL CE</span>
                      <span className="text-[10px] font-normal opacity-70">[⇧C]</span>
                    </div>
                  </Button>
                  <Button
                    variant="outline"
                    className="h-14 text-base font-bold border-2 border-red-500 text-red-600 dark:text-red-400 hover:bg-red-500/10"
                    disabled={!!orderInProgress || !peSymbol}
                    onClick={() => placeOrder('PE', 'SELL')}
                  >
                    {orderInProgress === 'SELL-PE' ? (
                      <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                    ) : (
                      <ArrowDown className="h-4 w-4 mr-2" />
                    )}
                    <div className="flex flex-col items-center">
                      <span>SELL PE</span>
                      <span className="text-[10px] font-normal opacity-70">[⇧P]</span>
                    </div>
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Right: Bracket Settings + Positions Panel */}
          <div className="space-y-4">
            {/* Bracket Order Settings */}
            <Card>
              <CardHeader className="p-4 pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <Shield className="h-3.5 w-3.5" />
                    Bracket Orders
                  </CardTitle>
                  <Switch
                    checked={bracketEnabled}
                    onCheckedChange={setBracketEnabled}
                  />
                </div>
              </CardHeader>
              {bracketEnabled && (
                <CardContent className="p-4 pt-0 space-y-3">
                  {/* Mode selector */}
                  <div className="flex items-center gap-2">
                    <Label className="text-xs text-muted-foreground w-14">Mode</Label>
                    <Select value={effectiveBracketMode} onValueChange={(v) => setBracketMode(v as 'broker' | 'ui')} disabled={isAnalyzer}>
                      <SelectTrigger className="h-7 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="broker" disabled={isAnalyzer}>Broker SL (exchange order)</SelectItem>
                        <SelectItem value="ui">UI Monitor (browser only)</SelectItem>
                      </SelectContent>
                    </Select>
                    {isAnalyzer && (
                      <p className="text-[10px] text-purple-500 mt-0.5">Broker SL unavailable in Analyzer mode</p>
                    )}
                  </div>

                  {/* SL & Target points */}
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <Label className="text-xs text-muted-foreground">SL Points</Label>
                      <Input
                        type="number"
                        className="h-7 text-xs tabular-nums"
                        value={slPoints}
                        min={1}
                        step={1}
                        onChange={(e) => setSlPoints(Number(e.target.value) || 0)}
                      />
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">Target Points</Label>
                      <Input
                        type="number"
                        className="h-7 text-xs tabular-nums"
                        value={targetPoints}
                        min={1}
                        step={1}
                        onChange={(e) => setTargetPoints(Number(e.target.value) || 0)}
                      />
                    </div>
                  </div>

                  {/* Trail toggle + step */}
                  <div className="flex items-center gap-2">
                    <Switch
                      checked={trailEnabled}
                      onCheckedChange={setTrailEnabled}
                      className="scale-75"
                    />
                    <Label className="text-xs text-muted-foreground">Trail SL</Label>
                    {trailEnabled && (
                      <div className="flex items-center gap-1 ml-auto">
                        <Label className="text-xs text-muted-foreground">Step</Label>
                        <Input
                          type="number"
                          className="h-7 w-16 text-xs tabular-nums"
                          value={trailStep}
                          min={1}
                          step={1}
                          onChange={(e) => setTrailStep(Number(e.target.value) || 0)}
                        />
                      </div>
                    )}
                  </div>

                  {/* Active brackets summary */}
                  {activeBrackets.size > 0 && (
                    <div className="border-t pt-2 mt-1">
                      <div className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                        <Target className="h-3 w-3" />
                        Active Brackets ({activeBrackets.size})
                      </div>
                      <div className="space-y-1 max-h-[120px] overflow-y-auto">
                        {Array.from(activeBrackets.values()).map((b) => {
                          return (
                            <div key={b.id} className="flex items-center justify-between text-xs rounded px-1.5 py-0.5 bg-muted/50">
                              <span className="font-mono truncate max-w-[100px]" title={b.symbol}>
                                {b.symbol.slice(-8)}
                              </span>
                              <div className="flex items-center gap-2 tabular-nums">
                                <span className="text-red-500" title="SL">
                                  SL:{b.sl_price?.toFixed(1)}
                                </span>
                                <span className="text-emerald-500" title="Target">
                                  T:{b.target_price?.toFixed(1)}
                                </span>
                                {b.trail_enabled && (
                                  <Badge variant="outline" className="text-[9px] px-1 py-0 h-3.5">
                                    Trail
                                  </Badge>
                                )}
                                <Badge
                                  variant={b.bracket_mode === 'broker' ? 'default' : 'secondary'}
                                  className="text-[9px] px-1 py-0 h-3.5"
                                >
                                  {b.bracket_mode === 'broker' ? 'BRK' : 'UI'}
                                </Badge>
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}
                </CardContent>
              )}
            </Card>

            {/* Positions */}
            <Card className="h-full">
              <CardHeader className="p-4 pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                    Open Positions
                  </CardTitle>
                  <div className="flex items-center gap-2">
                    <span
                      className={cn(
                        'text-sm font-bold tabular-nums',
                        totalPnl >= 0 ? 'text-emerald-500' : 'text-red-500'
                      )}
                    >
                      {totalPnl >= 0 ? '+' : ''}₹{formatPrice(Math.abs(totalPnl))}
                    </span>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          onClick={refreshPositions}
                          disabled={isLoadingPositions}
                        >
                          <RefreshCw
                            className={cn('h-3.5 w-3.5', isLoadingPositions && 'animate-spin')}
                          />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Refresh positions</TooltipContent>
                    </Tooltip>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-4 pt-0">
                {/* Positions List */}
                <div className="space-y-2 overflow-y-auto max-h-[400px]">
                  {positions.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8 text-sm">
                      No open positions
                    </div>
                  ) : (
                    positions.map((pos) => {
                      const isCE = pos.symbol.endsWith('CE')
                      const bracket = activeBrackets.get(pos.symbol)
                      return (
                        <div
                          key={`${pos.symbol}-${pos.exchange}`}
                          className={cn(
                            'rounded-lg p-3 border space-y-1 hover:bg-muted/50 transition-colors',
                            bracket && 'border-l-2 border-l-blue-500'
                          )}
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Badge
                                variant={isCE ? 'default' : 'destructive'}
                                className="text-[10px] px-1.5 py-0"
                              >
                                {isCE ? 'CE' : 'PE'}
                              </Badge>
                              <span className="text-sm font-semibold truncate max-w-[140px]" title={pos.symbol}>
                                {pos.symbol}
                              </span>
                            </div>
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-6 text-xs text-red-500 border-red-500/50 hover:bg-red-500/10"
                              onClick={() => exitPosition(pos)}
                              disabled={exitingPosition === pos.symbol}
                            >
                              {exitingPosition === pos.symbol ? (
                                <RefreshCw className="h-3 w-3 animate-spin" />
                              ) : (
                                'EXIT'
                              )}
                            </Button>
                          </div>
                          <div className="flex items-center justify-between text-xs">
                            <span className="text-muted-foreground">
                              {pos.quantity} qty · Avg {formatPrice(pos.averagePrice)}
                            </span>
                            <span
                              className={cn(
                                'font-bold tabular-nums',
                                pos.pnl >= 0 ? 'text-emerald-500' : 'text-red-500'
                              )}
                            >
                              {pos.pnl >= 0 ? '+' : ''}₹{formatPrice(Math.abs(pos.pnl))}
                            </span>
                          </div>
                          {/* Bracket SL/Target indicators */}
                          {bracket && (
                            <div className="space-y-1 pt-0.5">
                              <div className="flex items-center gap-2 text-[10px] tabular-nums">
                                <span className="text-red-400">
                                  SL: ₹{bracket.sl_price?.toFixed(2)}
                                </span>
                                <span className="text-emerald-400">
                                  T: ₹{bracket.target_price?.toFixed(2)}
                                </span>
                                {bracket.trail_enabled && (
                                  <span className="text-blue-400">
                                    Trail↑{bracket.trail_step}
                                  </span>
                                )}
                                <Badge
                                  variant={bracket.bracket_mode === 'broker' ? 'default' : 'secondary'}
                                  className="text-[8px] px-1 py-0 h-3 ml-auto"
                                >
                                  {bracket.bracket_mode === 'broker' ? 'BRK' : 'UI'}
                                </Badge>
                              </div>
                              {/* Partial Exit + TSL Update */}
                              <div className="flex items-center gap-1 pt-0.5 border-t border-border/30">
                                <span className="text-[9px] text-muted-foreground shrink-0">Part:</span>
                                <Button
                                  variant="outline"
                                  className="h-5 px-1.5 text-[9px] text-orange-500 border-orange-500/40 hover:bg-orange-500/10"
                                  onClick={() => partialExit(pos, 0.5)}
                                  title={`Exit 50% (${Math.floor(Math.abs(pos.quantity) * 0.5)} of ${Math.abs(pos.quantity)})`}
                                >
                                  50%
                                </Button>
                                <Button
                                  variant="outline"
                                  className="h-5 px-1.5 text-[9px] text-orange-500 border-orange-500/40 hover:bg-orange-500/10"
                                  onClick={() => partialExit(pos, 0.75)}
                                  title={`Exit 75% (${Math.floor(Math.abs(pos.quantity) * 0.75)} of ${Math.abs(pos.quantity)})`}
                                >
                                  75%
                                </Button>
                                <span className="text-[9px] text-muted-foreground/40 mx-0.5">|</span>
                                <span className="text-[9px] text-muted-foreground shrink-0">SL:</span>
                                <Input
                                  type="number"
                                  defaultValue={bracket.sl_price?.toFixed(2)}
                                  step={0.05}
                                  min={0.05}
                                  className="h-5 w-16 px-1 text-[9px] text-center tabular-nums"
                                  id={`sl-update-${pos.symbol}`}
                                  onKeyDown={(e) => {
                                    if (e.key === 'Enter') {
                                      const val = parseFloat((e.target as HTMLInputElement).value)
                                      if (val > 0) updateSLPrice(pos, val)
                                    }
                                  }}
                                />
                                <Button
                                  variant="outline"
                                  className="h-5 px-1.5 text-[9px] text-blue-500 border-blue-500/40 hover:bg-blue-500/10"
                                  onClick={() => {
                                    const el = document.getElementById(`sl-update-${pos.symbol}`) as HTMLInputElement
                                    if (el) {
                                      const val = parseFloat(el.value)
                                      if (val > 0) updateSLPrice(pos, val)
                                    }
                                  }}
                                  title="Update trailing SL price"
                                >
                                  Set
                                </Button>
                              </div>
                            </div>
                          )}
                        </div>
                      )
                    })
                  )}
                </div>

                {/* Exit All Button */}
                <div className="mt-4 pt-3 border-t">
                  <Button
                    variant="destructive"
                    className="w-full bg-orange-500 hover:bg-orange-600"
                    onClick={exitAllPositions}
                    disabled={isExitingAll || positions.length === 0}
                  >
                    {isExitingAll ? (
                      <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                    ) : (
                      <X className="h-4 w-4 mr-2" />
                    )}
                    EXIT ALL
                    <span className="text-[10px] font-normal opacity-70 ml-1">[X]</span>
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Keyboard Shortcuts Info */}
        <div className="flex flex-wrap justify-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-muted border rounded text-[10px] font-mono">C</kbd> Buy CE
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-muted border rounded text-[10px] font-mono">P</kbd> Buy PE
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-muted border rounded text-[10px] font-mono">⇧C</kbd> Sell CE
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-muted border rounded text-[10px] font-mono">⇧P</kbd> Sell PE
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-muted border rounded text-[10px] font-mono">X</kbd> Exit All
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-muted border rounded text-[10px] font-mono">R</kbd> Refresh
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-muted border rounded text-[10px] font-mono">←</kbd>
            <kbd className="px-1.5 py-0.5 bg-muted border rounded text-[10px] font-mono">→</kbd> Strike
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-muted border rounded text-[10px] font-mono">↑</kbd>
            <kbd className="px-1.5 py-0.5 bg-muted border rounded text-[10px] font-mono">↓</kbd> Lots
          </span>
        </div>
      </div>
    </TooltipProvider>
  )
}

export default ScalperTerminal
