/**
 * Technical indicator calculations for chart overlays.
 * All functions expect sorted data (ascending by time).
 */

export interface TimeValue {
  time: number
  value: number
}

/**
 * Calculate Exponential Moving Average (EMA).
 * Uses SMA of the first `period` points as the seed value.
 */
export function calculateEMA(data: TimeValue[], period: number): TimeValue[] {
  if (data.length < period || period <= 0) return []

  const k = 2 / (period + 1)
  const result: TimeValue[] = []

  // Seed with SMA of first `period` values
  let sum = 0
  for (let i = 0; i < period; i++) {
    sum += data[i].value
  }
  let ema = sum / period
  result.push({ time: data[period - 1].time, value: ema })

  // EMA for remaining points
  for (let i = period; i < data.length; i++) {
    ema = data[i].value * k + ema * (1 - k)
    result.push({ time: data[i].time, value: ema })
  }

  return result
}

/**
 * Calculate VWAP (Volume-Weighted Average Price).
 * Since these chart series have no volume data, this computes
 * a cumulative average price (equal-weight VWAP / session average).
 */
export function calculateVWAP(data: TimeValue[]): TimeValue[] {
  if (data.length === 0) return []

  const result: TimeValue[] = []
  let cumSum = 0

  for (let i = 0; i < data.length; i++) {
    cumSum += data[i].value
    result.push({ time: data[i].time, value: cumSum / (i + 1) })
  }

  return result
}
