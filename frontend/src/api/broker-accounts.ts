// frontend/src/api/broker-accounts.ts

import { webClient } from './client'

export interface BrokerAccount {
  id: number
  user: string
  account_name: string
  broker: string
  broker_api_key: string
  broker_api_secret: string
  redirect_url: string
  broker_api_key_market: string
  broker_api_secret_market: string
  user_id: string
  password: string
  totp_key: string
  mobile_number: string
  date_of_birth: string
  year_of_birth: string
  connection_status: string
  error_message: string
  last_connected_at: string | null
  is_active: boolean
  is_authenticated: boolean
  created_at: string | null
  updated_at: string | null
}

export interface BrokerInfo {
  id: string
  name: string
  auth_type: 'oauth' | 'totp'
}

export interface CreateAccountPayload {
  account_name: string
  broker: string
  broker_api_key: string
  broker_api_secret: string
  redirect_url?: string
  broker_api_key_market?: string
  broker_api_secret_market?: string
  user_id?: string
  password?: string
  totp_key?: string
  mobile_number?: string
  date_of_birth?: string
  year_of_birth?: string
}

export interface UpdateAccountPayload {
  account_name?: string
  broker?: string
  broker_api_key?: string
  broker_api_secret?: string
  redirect_url?: string
  broker_api_key_market?: string
  broker_api_secret_market?: string
  user_id?: string
  password?: string
  totp_key?: string
  mobile_number?: string
  date_of_birth?: string
  year_of_birth?: string
}

interface ApiResponse<T> {
  status: 'success' | 'error'
  message?: string
  data: T
}

export const brokerAccountsApi = {
  /** List all broker accounts */
  list: async (): Promise<BrokerAccount[]> => {
    const response = await webClient.get<ApiResponse<BrokerAccount[]>>(
      '/api/broker-accounts'
    )
    return response.data.data
  },

  /** Get available brokers */
  getBrokers: async (): Promise<BrokerInfo[]> => {
    const response = await webClient.get<ApiResponse<BrokerInfo[]>>(
      '/api/broker-accounts/brokers'
    )
    return response.data.data
  },

  /** Create a new broker account */
  create: async (payload: CreateAccountPayload): Promise<{ id: number }> => {
    const response = await webClient.post<ApiResponse<{ id: number }>>(
      '/api/broker-accounts',
      payload,
      { headers: { 'Content-Type': 'application/json' } }
    )
    return response.data.data
  },

  /** Update a broker account */
  update: async (
    accountId: number,
    payload: UpdateAccountPayload
  ): Promise<void> => {
    await webClient.put(`/api/broker-accounts/${accountId}`, payload, {
      headers: { 'Content-Type': 'application/json' },
    })
  },

  /** Delete a broker account */
  delete: async (accountId: number): Promise<void> => {
    await webClient.delete(`/api/broker-accounts/${accountId}`)
  },

  /** Initiate authentication for a broker account */
  authenticate: async (
    accountId: number,
    extraData?: Record<string, string>
  ): Promise<{
    auth_type: 'oauth' | 'totp' | 'auto'
    auth_url?: string
    broker?: string
    account_id?: number
    message: string
  }> => {
    const response = await webClient.post(
      `/api/broker-accounts/${accountId}/authenticate`,
      extraData || {},
      { headers: { 'Content-Type': 'application/json' } }
    )
    return response.data
  },

  /** Set a broker account as the active one */
  setActive: async (
    accountId: number
  ): Promise<{
    account_id: number
    broker: string
    account_name: string
  }> => {
    const response = await webClient.post(
      `/api/broker-accounts/${accountId}/set-active`,
      {},
      { headers: { 'Content-Type': 'application/json' } }
    )
    return response.data.data
  },

  /** Get the currently active broker account */
  getActive: async (): Promise<BrokerAccount | null> => {
    const response = await webClient.get<ApiResponse<BrokerAccount | null>>(
      '/api/broker-accounts/active'
    )
    return response.data.data
  },
}
