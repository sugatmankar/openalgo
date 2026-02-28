import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Check, ChevronsUpDown, Plus, Trash2, RefreshCw } from 'lucide-react'
import {
  ColorType,
  CrosshairMode,
  LineSeries,
  createChart,
  type IChartApi,
  type ISeriesApi,
} from 'lightweight-charts'
import { useThemeStore } from '@/stores/themeStore'
import { oiProfileApi } from '@/api/oi-profile'
import {
  combinePremiumApi,
  type CombinePremiumData,
  type CombinePremiumDataPoint,
  type CombinePremiumLeg,
} from '@/api/combine-premium'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Button } from '@/components/ui/button'
import { showToast } from '@/utils/toast'

const FNO_EXCHANGES = [
  { value: 'NFO', label: 'NFO' },
  { value: 'BFO', label: 'BFO' },
]

const DEFAULT_UNDERLYINGS: Record<string, string[]> = {
  NFO: ['NIFTY', 'BANKNIFTY', 'FINNIFTY', 'MIDCPNIFTY'],
  BFO: ['SENSEX', 'BANKEX'],
}

const CHART_HEIGHT = 500

// Colors for individual legs on the chart
const LEG_COLORS = [
  '#f59e0b', // amber
  '#8b5cf6', // violet
  '#ec4899', // pink
  '#14b8a6', // teal
  '#f97316', // orange
  '#6366f1', // indigo
  '#ef4444', // red
  '#84cc16', // lime
]

function convertExpiryForAPI(expiry: string): string {
  if (!expiry) return ''
  const parts = expiry.split('-')
  if (parts.length === 3) {
    return `${parts[0]}${parts[1].toUpperCase()}${parts[2].slice(-2)}`
  }
  return expiry.replace(/-/g, '').toUpperCase()
}

function formatIST(unixSeconds: number): { date: string; time: string } {
  const d = new Date(unixSeconds * 1000)
  const ist = new Date(d.getTime() + 5.5 * 60 * 60 * 1000)
  const dd = ist.getUTCDate().toString().padStart(2, '0')
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
  const mo = months[ist.getUTCMonth()]
  const hh = ist.getUTCHours().toString().padStart(2, '0')
  const mm = ist.getUTCMinutes().toString().padStart(2, '0')
  const ampm = ist.getUTCHours() >= 12 ? 'PM' : 'AM'
  return { date: `${dd} ${mo}`, time: `${hh}:${mm} ${ampm}` }
}

interface LegConfig {
  id: number
  strike: number | null
  option_type: 'CE' | 'PE'
  action: 'BUY' | 'SELL'
}

export default function CombinePremium() {
  const { mode, appMode } = useThemeStore()
  const isDarkMode = mode === 'dark'
  const isAnalyzer = appMode === 'analyzer'

  // Control state
  const [isLoading, setIsLoading] = useState(false)
  const [selectedExchange, setSelectedExchange] = useState('NFO')
  const [underlyings, setUnderlyings] = useState<string[]>(DEFAULT_UNDERLYINGS.NFO)
  const [underlyingOpen, setUnderlyingOpen] = useState(false)
  const [selectedUnderlying, setSelectedUnderlying] = useState('NIFTY')
  const [expiries, setExpiries] = useState<string[]>([])
  const [selectedExpiry, setSelectedExpiry] = useState('')
  const [intervals, setIntervals] = useState<string[]>([])
  const [selectedInterval, setSelectedInterval] = useState('1m')
  const [selectedDays, setSelectedDays] = useState('3')
  const [chartData, setChartData] = useState<CombinePremiumData | null>(null)
  const [strikes, setStrikes] = useState<number[]>([])

  // Legs
  const [legs, setLegs] = useState<LegConfig[]>([
    { id: 1, strike: null, option_type: 'CE', action: 'SELL' },
    { id: 2, strike: null, option_type: 'PE', action: 'SELL' },
  ])
  const nextLegId = useRef(3)

  // Series visibility
  const [showCombined, setShowCombined] = useState(true)
  const [showSpot, setShowSpot] = useState(false)

  // Chart refs
  const chartContainerRef = useRef<HTMLDivElement>(null)
  const chartRef = useRef<IChartApi | null>(null)
  const combinedSeriesRef = useRef<ISeriesApi<'Line'> | null>(null)
  const spotSeriesRef = useRef<ISeriesApi<'Line'> | null>(null)
  // Tooltip state
  const [tooltipData, setTooltipData] = useState<{
    visible: boolean
    x: number
    y: number
    point: CombinePremiumDataPoint | null
  }>({ visible: false, x: 0, y: 0, point: null })

  // Chart colors
  const chartColors = useMemo(() => {
    if (isAnalyzer) {
      return {
        bg: isDarkMode ? '#1a1625' : '#faf5ff',
        text: isDarkMode ? '#e9d5ff' : '#581c87',
        grid: isDarkMode ? '#2d2640' : '#e9d5ff',
        combined: '#22c55e',
        spot: isDarkMode ? '#e2e8f0' : '#334155',
      }
    }
    return {
      bg: isDarkMode ? '#1e1e2e' : '#ffffff',
      text: isDarkMode ? '#cdd6f4' : '#1e293b',
      grid: isDarkMode ? '#313244' : '#e2e8f0',
      combined: '#22c55e',
      spot: isDarkMode ? '#e2e8f0' : '#334155',
    }
  }, [isDarkMode, isAnalyzer])

  // Fetch intervals on mount
  useEffect(() => {
    const fetchIntervals = async () => {
      try {
        const resp = await combinePremiumApi.getIntervals()
        if (resp.status === 'success' && resp.data) {
          const allIntervals = [
            ...(resp.data.minutes || []),
            ...(resp.data.hours || []),
          ]
          if (allIntervals.length > 0) {
            setIntervals(allIntervals)
            if (!allIntervals.includes('1m')) {
              setSelectedInterval(allIntervals[0])
            }
          }
        }
      } catch {
        // fail silently
      }
    }
    fetchIntervals()
  }, [])

  // Fetch underlyings when exchange changes
  useEffect(() => {
    const fetchUnderlyings = async () => {
      try {
        const resp = await oiProfileApi.getUnderlyings(selectedExchange)
        if (resp.status === 'success' && resp.underlyings?.length) {
          setUnderlyings(resp.underlyings)
          if (!resp.underlyings.includes(selectedUnderlying)) {
            setSelectedUnderlying(resp.underlyings[0])
          }
        } else {
          setUnderlyings(DEFAULT_UNDERLYINGS[selectedExchange] || [])
        }
      } catch {
        setUnderlyings(DEFAULT_UNDERLYINGS[selectedExchange] || [])
      }
    }
    fetchUnderlyings()
  }, [selectedExchange]) // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch expiries when underlying changes
  useEffect(() => {
    const fetchExpiries = async () => {
      try {
        const resp = await oiProfileApi.getExpiries(selectedExchange, selectedUnderlying)
        if (resp.status === 'success' && resp.expiries?.length) {
          setExpiries(resp.expiries)
          setSelectedExpiry(resp.expiries[0])
        } else {
          setExpiries([])
          setSelectedExpiry('')
        }
      } catch {
        setExpiries([])
        setSelectedExpiry('')
      }
    }
    if (selectedUnderlying) fetchExpiries()
  }, [selectedExchange, selectedUnderlying])

  // Fetch available strikes when expiry changes
  useEffect(() => {
    const fetchStrikes = async () => {
      if (!selectedExpiry) return
      try {
        const resp = await combinePremiumApi.getStrikes({
          underlying: selectedUnderlying,
          exchange: selectedExchange,
          expiry_date: convertExpiryForAPI(selectedExpiry),
        })
        if (resp.status === 'success' && resp.data?.strikes?.length) {
          const newStrikes = resp.data.strikes
          setStrikes(newStrikes)
          // Auto-select ATM (middle strike) for legs that have no strike set
          const atmStrike = newStrikes[Math.floor(newStrikes.length / 2)]
          setLegs((prev) =>
            prev.map((l) => (l.strike === null ? { ...l, strike: atmStrike } : l))
          )
        } else {
          setStrikes([])
        }
      } catch {
        setStrikes([])
      }
    }
    fetchStrikes()
  }, [selectedExchange, selectedUnderlying, selectedExpiry])

  // Load chart data
  const loadData = useCallback(async () => {
    if (!selectedExpiry || !selectedUnderlying) return

    // Validate legs
    const validLegs: CombinePremiumLeg[] = []
    for (const leg of legs) {
      if (leg.strike === null) {
        showToast.error('Please select a strike for all legs')
        return
      }
      validLegs.push({
        strike: leg.strike,
        option_type: leg.option_type,
        action: leg.action,
      })
    }

    if (validLegs.length === 0) {
      showToast.error('Add at least one leg')
      return
    }

    setIsLoading(true)
    try {
      const resp = await combinePremiumApi.getData({
        underlying: selectedUnderlying,
        exchange: selectedExchange,
        expiry_date: convertExpiryForAPI(selectedExpiry),
        interval: selectedInterval,
        days: Number(selectedDays),
        legs: validLegs,
      })

      if (resp.status === 'success' && resp.data) {
        setChartData(resp.data)
      } else {
        showToast.error(resp.message || 'Failed to load data')
        setChartData(null)
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to load data'
      showToast.error(msg)
      setChartData(null)
    } finally {
      setIsLoading(false)
    }
  }, [selectedExchange, selectedUnderlying, selectedExpiry, selectedInterval, selectedDays, legs])

  // Leg management
  const addLeg = () => {
    const atmStrike = strikes.length ? strikes[Math.floor(strikes.length / 2)] : null
    setLegs((prev) => [
      ...prev,
      { id: nextLegId.current++, strike: atmStrike, option_type: 'CE', action: 'BUY' },
    ])
  }

  const removeLeg = (id: number) => {
    setLegs((prev) => prev.filter((l) => l.id !== id))
  }

  const updateLeg = (id: number, field: keyof LegConfig, value: unknown) => {
    setLegs((prev) =>
      prev.map((l) => (l.id === id ? { ...l, [field]: value } : l))
    )
  }

  // Create / update chart
  useEffect(() => {
    if (!chartContainerRef.current || !chartData || !chartData.series.length) return

    // Cleanup old chart
    if (chartRef.current) {
      chartRef.current.remove()
      chartRef.current = null
    }

    const chart = createChart(chartContainerRef.current, {
      width: chartContainerRef.current.clientWidth,
      height: CHART_HEIGHT,
      layout: {
        background: { type: ColorType.Solid, color: chartColors.bg },
        textColor: chartColors.text,
      },
      grid: {
        vertLines: { color: chartColors.grid },
        horzLines: { color: chartColors.grid },
      },
      crosshair: { mode: CrosshairMode.Normal },
      rightPriceScale: { borderColor: chartColors.grid, visible: true },
      leftPriceScale: { borderColor: chartColors.grid, visible: true },
      timeScale: {
        borderColor: chartColors.grid,
        timeVisible: true,
        secondsVisible: false,
      },
    })

    chartRef.current = chart

    // Combined premium series (right Y-axis)
    const combinedSeries = chart.addSeries(LineSeries, {
      color: chartColors.combined,
      lineWidth: 2,
      title: 'Combined Premium',
      priceScaleId: 'right',
      visible: showCombined,
    })
    combinedSeriesRef.current = combinedSeries

    // Spot series (left Y-axis)
    const spotSeries = chart.addSeries(LineSeries, {
      color: chartColors.spot,
      lineWidth: 1,
      lineStyle: 2, // dashed
      title: 'Spot',
      priceScaleId: 'left',
      visible: showSpot,
    })
    spotSeriesRef.current = spotSeries

    // Set data
    const combinedData = chartData.series.map((p) => ({
      time: p.time as import('lightweight-charts').UTCTimestamp,
      value: p.combined_premium,
    }))
    const spotData = chartData.series.map((p) => ({
      time: p.time as import('lightweight-charts').UTCTimestamp,
      value: p.spot,
    }))

    combinedSeries.setData(combinedData)
    spotSeries.setData(spotData)

    chart.timeScale().fitContent()

    // Crosshair tooltip
    chart.subscribeCrosshairMove((param) => {
      if (!param.time || !param.point || param.point.x < 0 || param.point.y < 0) {
        setTooltipData((prev) => ({ ...prev, visible: false }))
        return
      }

      const time = param.time as number
      const point = chartData.series.find((p) => p.time === time)
      if (point) {
        setTooltipData({
          visible: true,
          x: param.point.x,
          y: param.point.y,
          point,
        })
      }
    })

    // Handle resize
    const handleResize = () => {
      if (chartContainerRef.current && chartRef.current) {
        chartRef.current.applyOptions({
          width: chartContainerRef.current.clientWidth,
        })
      }
    }
    window.addEventListener('resize', handleResize)

    return () => {
      window.removeEventListener('resize', handleResize)
      if (chartRef.current) {
        chartRef.current.remove()
        chartRef.current = null
      }
    }
  }, [chartData, chartColors, showCombined, showSpot])

  // Toggle series visibility
  useEffect(() => {
    combinedSeriesRef.current?.applyOptions({ visible: showCombined })
  }, [showCombined])

  useEffect(() => {
    spotSeriesRef.current?.applyOptions({ visible: showSpot })
  }, [showSpot])

  // Format leg label for display
  const formatLegLabel = (leg: LegConfig) => {
    const strikeStr = leg.strike !== null ? leg.strike : '—'
    return `${leg.action} ${strikeStr} ${leg.option_type}`
  }

  return (
    <div className="py-6 space-y-4">
      {/* Header + Info */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-2xl font-bold">Combine Premium</h1>
          <p className="text-muted-foreground text-sm mt-0.5">
            Combined premium chart for custom multi-leg option strategies
          </p>
        </div>
        {chartData && (
          <div className="flex items-center gap-4 text-sm">
            <span className="font-medium">
              {chartData.underlying}{' '}
              <span className="text-primary">{chartData.underlying_ltp.toLocaleString()}</span>
            </span>
            <span className="text-muted-foreground">
              Exp: {chartData.expiry_date} ({chartData.days_to_expiry}d)
            </span>
          </div>
        )}
      </div>

      {/* Controls */}
      <Card>
        <CardContent className="pt-4 pb-4 space-y-4">
          {/* Row 1: Exchange, Underlying, Expiry, Interval, Days */}
          <div className="flex flex-wrap gap-3 items-end">
            {/* Exchange */}
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Exchange</label>
              <Select value={selectedExchange} onValueChange={setSelectedExchange}>
                <SelectTrigger className="w-[100px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {FNO_EXCHANGES.map((e) => (
                    <SelectItem key={e.value} value={e.value}>{e.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Underlying (searchable combobox) */}
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Underlying</label>
              <Popover open={underlyingOpen} onOpenChange={setUnderlyingOpen}>
                <PopoverTrigger asChild>
                  <Button variant="outline" role="combobox" className="w-[160px] justify-between">
                    {selectedUnderlying || 'Select...'}
                    <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-[200px] p-0">
                  <Command>
                    <CommandInput placeholder="Search..." />
                    <CommandList>
                      <CommandEmpty>No symbol found.</CommandEmpty>
                      <CommandGroup>
                        {underlyings.map((u) => (
                          <CommandItem
                            key={u}
                            value={u}
                            onSelect={() => {
                              setSelectedUnderlying(u)
                              setUnderlyingOpen(false)
                            }}
                          >
                            <Check className={`mr-2 h-4 w-4 ${selectedUnderlying === u ? 'opacity-100' : 'opacity-0'}`} />
                            {u}
                          </CommandItem>
                        ))}
                      </CommandGroup>
                    </CommandList>
                  </Command>
                </PopoverContent>
              </Popover>
            </div>

            {/* Expiry */}
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Expiry</label>
              <Select value={selectedExpiry} onValueChange={setSelectedExpiry}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Select..." />
                </SelectTrigger>
                <SelectContent>
                  {expiries.map((e) => (
                    <SelectItem key={e} value={e}>{e}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Interval */}
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Interval</label>
              <Select value={selectedInterval} onValueChange={setSelectedInterval}>
                <SelectTrigger className="w-[90px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {intervals.map((iv) => (
                    <SelectItem key={iv} value={iv}>{iv}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Days */}
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Days</label>
              <Select value={selectedDays} onValueChange={setSelectedDays}>
                <SelectTrigger className="w-[70px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {['1', '3', '5'].map((d) => (
                    <SelectItem key={d} value={d}>{d}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Row 2: Legs builder */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-muted-foreground">Strategy Legs</label>
              <Button variant="outline" size="sm" onClick={addLeg} className="h-7 text-xs">
                <Plus className="h-3 w-3 mr-1" /> Add Leg
              </Button>
            </div>
            <div className="space-y-2">
              {legs.map((leg, idx) => (
                <div key={leg.id} className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-mono text-muted-foreground w-5">
                    {idx + 1}.
                  </span>

                  {/* Action */}
                  <Select
                    value={leg.action}
                    onValueChange={(v) => updateLeg(leg.id, 'action', v)}
                  >
                    <SelectTrigger className="w-[85px] h-8 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="BUY">BUY</SelectItem>
                      <SelectItem value="SELL">SELL</SelectItem>
                    </SelectContent>
                  </Select>

                  {/* Strike */}
                  <Select
                    value={leg.strike !== null ? String(leg.strike) : ''}
                    onValueChange={(v) => updateLeg(leg.id, 'strike', Number(v))}
                  >
                    <SelectTrigger className="w-[120px] h-8 text-xs">
                      <SelectValue placeholder="Strike" />
                    </SelectTrigger>
                    <SelectContent className="max-h-[300px]">
                      {strikes.map((s) => (
                        <SelectItem key={s} value={String(s)}>
                          {s}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>

                  {/* Option Type */}
                  <Select
                    value={leg.option_type}
                    onValueChange={(v) => updateLeg(leg.id, 'option_type', v)}
                  >
                    <SelectTrigger className="w-[75px] h-8 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="CE">CE</SelectItem>
                      <SelectItem value="PE">PE</SelectItem>
                    </SelectContent>
                  </Select>

                  {/* Leg label */}
                  <span className="text-xs text-muted-foreground hidden sm:inline">
                    {formatLegLabel(leg)}
                  </span>

                  {/* Remove */}
                  {legs.length > 1 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8 w-8 p-0 text-destructive hover:text-destructive"
                      onClick={() => removeLeg(leg.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Load / Refresh */}
          <div className="flex gap-2">
            <Button onClick={loadData} disabled={isLoading} className="text-sm">
              {isLoading ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-1 animate-spin" />
                  Loading...
                </>
              ) : (
                'Load Chart'
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Chart */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-lg flex items-center justify-between">
            <span>Combined Premium Chart</span>
            {chartData && (
              <div className="flex gap-2 text-xs font-normal">
                <button
                  type="button"
                  onClick={() => setShowCombined(!showCombined)}
                  className={`flex items-center gap-1 px-2 py-1 rounded transition-colors ${
                    showCombined
                      ? 'bg-green-500/20 text-green-500'
                      : 'bg-muted text-muted-foreground'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: showCombined ? chartColors.combined : '#888' }} />
                  Combined
                </button>
                <button
                  type="button"
                  onClick={() => setShowSpot(!showSpot)}
                  className={`flex items-center gap-1 px-2 py-1 rounded transition-colors ${
                    showSpot
                      ? 'bg-slate-500/20 text-slate-400'
                      : 'bg-muted text-muted-foreground'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: showSpot ? chartColors.spot : '#888' }} />
                  Spot
                </button>
              </div>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="relative">
          {!chartData && !isLoading && (
            <div
              className="flex items-center justify-center text-muted-foreground text-sm"
              style={{ height: CHART_HEIGHT }}
            >
              Configure legs and click "Load Chart" to view combined premium
            </div>
          )}
          {isLoading && (
            <div
              className="flex items-center justify-center text-muted-foreground text-sm"
              style={{ height: CHART_HEIGHT }}
            >
              <RefreshCw className="h-5 w-5 animate-spin mr-2" />
              Loading chart data...
            </div>
          )}
          <div
            ref={chartContainerRef}
            style={{ height: CHART_HEIGHT, display: chartData && !isLoading ? 'block' : 'none' }}
          />

          {/* Tooltip */}
          {tooltipData.visible && tooltipData.point && (
            <div
              className="absolute pointer-events-none z-10 bg-popover text-popover-foreground border rounded-lg shadow-lg p-3 text-xs"
              style={{
                left: Math.min(tooltipData.x + 16, (chartContainerRef.current?.clientWidth ?? 600) - 200),
                top: Math.max(tooltipData.y - 60, 0),
              }}
            >
              <div className="font-medium mb-1">
                {(() => {
                  const { date, time } = formatIST(tooltipData.point.time)
                  return `${date} ${time}`
                })()}
              </div>
              <div className="space-y-0.5">
                <div className="flex justify-between gap-4">
                  <span style={{ color: chartColors.combined }}>Combined:</span>
                  <span className="font-medium">{tooltipData.point.combined_premium.toFixed(2)}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span style={{ color: chartColors.spot }}>Spot:</span>
                  <span className="font-medium">{tooltipData.point.spot.toFixed(2)}</span>
                </div>
                {chartData?.legs && tooltipData.point.leg_prices.map((price, i) => (
                  <div key={chartData.legs[i]?.symbol || i} className="flex justify-between gap-4">
                    <span style={{ color: LEG_COLORS[i % LEG_COLORS.length] }}>
                      {chartData.legs[i]?.action === 'SELL' ? 'S' : 'B'}{' '}
                      {chartData.legs[i]?.strike} {chartData.legs[i]?.option_type}:
                    </span>
                    <span className="font-medium">{price !== null ? price.toFixed(2) : '—'}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Legs summary */}
      {chartData && chartData.legs.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Legs Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
              {chartData.legs.map((leg, i) => (
                <div
                  key={leg.symbol}
                  className="flex items-center gap-2 text-xs border rounded px-2 py-1.5"
                >
                  <span
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{ backgroundColor: LEG_COLORS[i % LEG_COLORS.length] }}
                  />
                  <span className={leg.action === 'SELL' ? 'text-red-500' : 'text-green-500'}>
                    {leg.action}
                  </span>
                  <span className="font-medium">{leg.strike} {leg.option_type}</span>
                  <span className="text-muted-foreground truncate">({leg.symbol})</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
