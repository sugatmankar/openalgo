/**
 * Scalper Bracket Order API
 * Client for the scalper bracket order management endpoints.
 * Uses webClient (session + CSRF auth) since these are web UI endpoints.
 */

import { webClient } from './client'

const BRACKET_BASE = '/scalper/api/bracket'

// ==================== Types ====================

export interface BracketOrder {
  id: number
  symbol: string
  exchange: string
  product: string
  action: string           // 'BUY' or 'SELL' (entry action)
  quantity: number
  entry_price: number
  bracket_mode: 'broker' | 'ui'
  sl_order_id: string | null
  sl_order_status: string
  sl_price: number
  target_price: number
  sl_points: number
  target_points: number
  trail_enabled: boolean
  trail_step: number | null
  best_price: number
  status: string
  triggered_at: string | null
  created_at: string | null
}

export interface PlaceSLRequest {
  symbol: string
  exchange: string
  product: string
  entry_action: 'BUY' | 'SELL'
  quantity: number
  entry_price: number
  sl_points: number
  target_points: number
  trail_enabled: boolean
  trail_step: number
  bracket_mode: 'broker' | 'ui'
}

export interface PlaceSLResponse {
  status: string
  message: string
  bracket_id?: number
  sl_order_id?: string
  sl_price?: number
  target_price?: number
  bracket_mode?: string
  total_quantity?: number
  entry_price?: number
  best_price?: number
}

export interface TrailSLRequest {
  symbol: string
  exchange: string
  product: string
  new_sl_price: number
  best_price: number
  new_target_price?: number
}

export interface CancelSLRequest {
  symbol: string
  exchange: string
  product: string
}

export interface PartialExitRequest {
  symbol: string
  exchange: string
  product: string
  quantity: number     // signed: +ve for long, -ve for short
  exit_qty: number     // always positive
}

export interface UpdateSLRequest {
  symbol: string
  exchange: string
  product: string
  new_sl_price: number
  current_ltp?: number
}

export interface TargetExitRequest {
  symbol: string
  exchange: string
  product: string
  quantity: number
}

export interface BracketStatusResponse {
  status: string
  brackets: BracketOrder[]
}

// ==================== API Functions ====================

export const scalperBracketApi = {
  /**
   * Place a bracket SL order after entry.
   * In 'broker' mode, places an actual SL order on the exchange.
   * In 'ui' mode, just stores the bracket in DB for frontend monitoring.
   */
  async placeSL(req: PlaceSLRequest): Promise<PlaceSLResponse> {
    const response = await webClient.post(`${BRACKET_BASE}/place-sl`, req)
    return response.data
  },

  /**
   * Trail (modify) an existing SL order's trigger price.
   * Called when price moves in favor by trail_step.
   */
  async trailSL(req: TrailSLRequest): Promise<{ status: string; message: string; new_sl_price?: number }> {
    const response = await webClient.post(`${BRACKET_BASE}/trail-sl`, req)
    return response.data
  },

  /**
   * Cancel a bracket order (and its broker SL order if active).
   */
  async cancelSL(req: CancelSLRequest): Promise<{ status: string; message: string }> {
    const response = await webClient.post(`${BRACKET_BASE}/cancel-sl`, req)
    return response.data
  },

  /**
   * Get all active bracket orders (with reconciliation).
   * Also auto-cleans orphaned brackets where position no longer exists.
   */
  async getStatus(): Promise<BracketStatusResponse> {
    const response = await webClient.post(`${BRACKET_BASE}/status`, {})
    return response.data
  },

  /**
   * Target hit: cancel the broker SL order and place a market exit.
   */
  async targetExit(req: TargetExitRequest): Promise<{ status: string; order_id?: string; message: string }> {
    const response = await webClient.post(`${BRACKET_BASE}/target-exit`, req)
    return response.data
  },

  /**
   * UI SL hit: place a market exit order (used only in 'ui' mode).
   */
  async slExit(req: TargetExitRequest): Promise<{ status: string; order_id?: string; message: string }> {
    const response = await webClient.post(`${BRACKET_BASE}/sl-exit`, req)
    return response.data
  },

  /**
   * Partial exit: exit a fraction (e.g. 50%, 75%) of the position.
   * Cancels existing SL, places partial exit, re-places SL with reduced qty.
   */
  async partialExit(req: PartialExitRequest): Promise<{ status: string; message: string; remaining_qty?: number; order_id?: string }> {
    const response = await webClient.post(`${BRACKET_BASE}/partial-exit`, req)
    return response.data
  },

  /**
   * Manually update (tighten) the SL price for an active bracket.
   */
  async updateSL(req: UpdateSLRequest): Promise<{ status: string; message: string; new_sl_price?: number }> {
    const response = await webClient.post(`${BRACKET_BASE}/update-sl`, req)
    return response.data
  },
}
