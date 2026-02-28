import { webClient } from './client'

export interface CombinePremiumLeg {
  strike: number
  option_type: 'CE' | 'PE'
  action: 'BUY' | 'SELL'
}

export interface CombinePremiumDataPoint {
  time: number
  spot: number
  combined_premium: number
  leg_prices: (number | null)[]
}

export interface CombinePremiumLegInfo {
  strike: number
  option_type: string
  action: string
  symbol: string
}

export interface CombinePremiumData {
  underlying: string
  underlying_ltp: number
  expiry_date: string
  interval: string
  days_to_expiry: number
  legs: CombinePremiumLegInfo[]
  series: CombinePremiumDataPoint[]
}

export interface CombinePremiumResponse {
  status: 'success' | 'error'
  message?: string
  data?: CombinePremiumData
}

export interface StrikesResponse {
  status: 'success' | 'error'
  message?: string
  data?: {
    strikes: number[]
  }
}

export interface IntervalsData {
  seconds: string[]
  minutes: string[]
  hours: string[]
}

export interface IntervalsResponse {
  status: 'success' | 'error'
  message?: string
  data?: IntervalsData
}

export const combinePremiumApi = {
  getData: async (params: {
    underlying: string
    exchange: string
    expiry_date: string
    interval: string
    days?: number
    legs: CombinePremiumLeg[]
  }): Promise<CombinePremiumResponse> => {
    const response = await webClient.post<CombinePremiumResponse>(
      '/combine-premium/api/data',
      params
    )
    return response.data
  },

  getStrikes: async (params: {
    underlying: string
    exchange: string
    expiry_date: string
  }): Promise<StrikesResponse> => {
    const response = await webClient.post<StrikesResponse>(
      '/combine-premium/api/strikes',
      params
    )
    return response.data
  },

  getIntervals: async (): Promise<IntervalsResponse> => {
    const response = await webClient.get<IntervalsResponse>('/combine-premium/api/intervals')
    return response.data
  },
}
