import type { OptionChainResponse } from '@/types/option-chain'
import { apiClient } from './client'

export interface ExpiryResponse {
  status: 'success' | 'error'
  data: string[]
  message?: string
}

export interface OptionSymbolResponse {
  status: 'success' | 'error'
  symbol?: string
  exchange?: string
  lotsize?: number
  tick_size?: number
  freeze_qty?: number
  underlying_ltp?: number
  message?: string
}

export const optionChainApi = {
  getOptionChain: async (
    apiKey: string,
    underlying: string,
    exchange: string,
    expiryDate: string,
    strikeCount?: number
  ): Promise<OptionChainResponse> => {
    const response = await apiClient.post<OptionChainResponse>('/optionchain', {
      apikey: apiKey,
      underlying,
      exchange,
      expiry_date: expiryDate,
      strike_count: strikeCount ?? 20,
    })
    return response.data
  },

  getExpiries: async (
    apiKey: string,
    symbol: string,
    exchange: string,
    instrumenttype: string = 'options'
  ): Promise<ExpiryResponse> => {
    const response = await apiClient.post<ExpiryResponse>('/expiry', {
      apikey: apiKey,
      symbol,
      exchange,
      instrumenttype,
    })
    return response.data
  },

  /**
   * Get option symbol with lot size, tick size, freeze qty and underlying LTP.
   * Uses POST /api/v1/optionsymbol — the standard OpenAlgo option symbol API.
   */
  getOptionSymbol: async (
    apiKey: string,
    underlying: string,
    exchange: string,
    expiryDate: string,
    offset: string = 'ATM',
    optionType: string = 'CE'
  ): Promise<OptionSymbolResponse> => {
    const response = await apiClient.post<OptionSymbolResponse>('/optionsymbol', {
      apikey: apiKey,
      underlying,
      exchange,
      expiry_date: expiryDate,
      offset,
      option_type: optionType,
    })
    return response.data
  },
}
