// frontend/src/pages/BrokerAccounts.tsx

import {
  AlertCircle,
  Building2,
  ExternalLink,
  Loader2,
  Pencil,
  Plus,
  Power,
  Trash2,
  Wifi,
  WifiOff,
  Zap,
} from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import {
  type BrokerAccount,
  type BrokerInfo,
  type CreateAccountPayload,
  type UpdateAccountPayload,
  brokerAccountsApi,
} from '@/api/broker-accounts'
import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { showToast } from '@/utils/toast'

// XTS brokers that need market data credentials
const XTS_BROKERS = new Set([
  'compositedge',
  'fivepaisaxts',
  'ibulls',
  'iifl',
  'jainamxts',
  'wisdom',
])

// Per-broker extra field requirements for TOTP/auto-auth
// These define what additional fields to show in the form
interface BrokerFieldConfig {
  label: string
  field: keyof CreateAccountPayload
  type?: string
  placeholder?: string
  required?: boolean
}

const BROKER_EXTRA_FIELDS: Record<string, BrokerFieldConfig[]> = {
  angel: [
    { label: 'Client ID', field: 'user_id', placeholder: 'Angel One Client ID', required: true },
    { label: 'PIN', field: 'password', type: 'password', placeholder: 'Trading PIN', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
  fivepaisa: [
    { label: 'Client ID / Email', field: 'user_id', placeholder: 'Client ID or Email', required: true },
    { label: 'PIN', field: 'password', type: 'password', placeholder: 'Trading PIN', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
  firstock: [
    { label: 'User ID', field: 'user_id', placeholder: 'Firstock User ID', required: true },
    { label: 'Password', field: 'password', type: 'password', placeholder: 'Login Password', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
  fyers: [
    { label: 'Fyers ID', field: 'user_id', placeholder: 'Fyers Client ID (e.g. XY12345)', required: true },
    { label: 'PIN', field: 'password', type: 'password', placeholder: '4-digit login PIN', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)', required: true },
  ],
  shoonya: [
    { label: 'User ID', field: 'user_id', placeholder: 'Shoonya User ID', required: true },
    { label: 'Password', field: 'password', type: 'password', placeholder: 'Login Password', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
  zebu: [
    { label: 'User ID', field: 'user_id', placeholder: 'Zebu User ID', required: true },
    { label: 'Password', field: 'password', type: 'password', placeholder: 'Login Password', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
  kotak: [
    { label: 'Mobile Number', field: 'mobile_number', placeholder: 'Registered Mobile Number', required: true },
    { label: 'MPIN', field: 'password', type: 'password', placeholder: 'Trading MPIN', required: true },
    { label: 'Client Code (UCC)', field: 'user_id', placeholder: 'Unique Client Code (e.g. ABCDE)', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
  motilal: [
    { label: 'User ID', field: 'user_id', placeholder: 'Motilal User ID', required: true },
    { label: 'Password', field: 'password', type: 'password', placeholder: 'Login Password', required: true },
    { label: 'Date of Birth', field: 'date_of_birth', placeholder: 'DD/MM/YYYY', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
  mstock: [
    { label: 'Password', field: 'password', type: 'password', placeholder: 'Login Password', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
  nubra: [
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
  tradejini: [
    { label: 'Password', field: 'password', type: 'password', placeholder: 'Login Password', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
  samco: [
    { label: 'Year of Birth', field: 'year_of_birth', placeholder: 'YYYY', required: true },
  ],
  aliceblue: [
    { label: 'User ID', field: 'user_id', placeholder: 'AliceBlue User ID', required: true },
  ],
  flattrade: [
    { label: 'User ID', field: 'user_id', placeholder: 'FlatTrade User ID', required: true },
    { label: 'Password', field: 'password', type: 'password', placeholder: 'Login Password', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
  upstox: [
    { label: 'Mobile Number', field: 'mobile_number', placeholder: 'Registered Mobile Number', required: true },
    { label: 'Password', field: 'password', type: 'password', placeholder: 'Login Password', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
    { label: 'PIN', field: 'user_id', type: 'password', placeholder: '6-digit PIN', required: true },
  ],
  zerodha: [
    { label: 'Client ID', field: 'user_id', placeholder: 'Kite Client ID (e.g. AB1234)', required: true },
    { label: 'Password', field: 'password', type: 'password', placeholder: 'Login Password', required: true },
    { label: 'TOTP Key', field: 'totp_key', type: 'password', placeholder: 'TOTP secret (for auto-auth)' },
  ],
}

export default function BrokerAccounts() {

  // State
  const [accounts, setAccounts] = useState<BrokerAccount[]>([])
  const [brokers, setBrokers] = useState<BrokerInfo[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeAccountId, setActiveAccountId] = useState<number | null>(null)

  // Dialog state
  const [showAddDialog, setShowAddDialog] = useState(false)
  const [deleteAccountId, setDeleteAccountId] = useState<number | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [authenticatingId, setAuthenticatingId] = useState<number | null>(null)

  // Edit dialog state
  const [showEditDialog, setShowEditDialog] = useState(false)
  const [editingAccount, setEditingAccount] = useState<BrokerAccount | null>(null)
  const [editFormData, setEditFormData] = useState<UpdateAccountPayload>({})

  // Form state
  const [formData, setFormData] = useState<CreateAccountPayload>({
    account_name: '',
    broker: '',
    broker_api_key: '',
    broker_api_secret: '',
    redirect_url: '',
    broker_api_key_market: '',
    broker_api_secret_market: '',
    user_id: '',
    password: '',
    totp_key: '',
    mobile_number: '',
    date_of_birth: '',
    year_of_birth: '',
  })

  const selectedBrokerInfo = brokers.find((b) => b.id === formData.broker)
  const isXtsBroker = XTS_BROKERS.has(formData.broker)
  const extraFields = BROKER_EXTRA_FIELDS[formData.broker] || []
  const editExtraFields = editingAccount ? (BROKER_EXTRA_FIELDS[editingAccount.broker] || []) : []
  const isEditXtsBroker = editingAccount ? XTS_BROKERS.has(editingAccount.broker) : false

  // Load accounts and brokers
  const loadData = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const [accts, brkrs, active] = await Promise.all([
        brokerAccountsApi.list(),
        brokerAccountsApi.getBrokers(),
        brokerAccountsApi.getActive(),
      ])
      setAccounts(accts)
      setBrokers(brkrs)
      setActiveAccountId(active?.id ?? null)
    } catch (e: unknown) {
      const msg =
        e instanceof Error ? e.message : 'Failed to load broker accounts'
      setError(msg)
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    loadData()
  }, [loadData])

  const resetForm = () => {
    setFormData({
      account_name: '',
      broker: '',
      broker_api_key: '',
      broker_api_secret: '',
      redirect_url: '',
      broker_api_key_market: '',
      broker_api_secret_market: '',
      user_id: '',
      password: '',
      totp_key: '',
      mobile_number: '',
      date_of_birth: '',
      year_of_birth: '',
    })
  }

  // Handlers
  const handleCreate = async () => {
    if (!formData.account_name || !formData.broker || !formData.broker_api_key || !formData.broker_api_secret) {
      showToast.error('Please fill in all required fields')
      return
    }
    setSubmitting(true)
    try {
      await brokerAccountsApi.create(formData)
      showToast.success('Broker account created successfully')
      setShowAddDialog(false)
      resetForm()
      await loadData()
    } catch (e: unknown) {
      const errData = (e as { response?: { data?: { message?: string } } })
        .response?.data
      showToast.error(errData?.message || 'Failed to create account')
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteAccountId) return
    setSubmitting(true)
    try {
      await brokerAccountsApi.delete(deleteAccountId)
      showToast.success('Account deleted')
      setDeleteAccountId(null)
      await loadData()
    } catch (e: unknown) {
      const errData = (e as { response?: { data?: { message?: string } } })
        .response?.data
      showToast.error(errData?.message || 'Failed to delete account')
    } finally {
      setSubmitting(false)
    }
  }

  const handleAuthenticate = async (account: BrokerAccount) => {
    setAuthenticatingId(account.id)
    try {
      const result = await brokerAccountsApi.authenticate(account.id)
      if (result.auth_type === 'oauth' && result.auth_url) {
        // Redirect to broker OAuth page
        window.location.href = result.auth_url
      } else if (result.auth_type === 'auto') {
        // Auto-auth completed — reload to show updated status
        showToast.success(result.message || 'Auto-authenticated successfully')
        await loadData()
      } else if (result.auth_type === 'totp') {
        // Redirect to TOTP page
        window.location.href = `/broker/${account.broker}/totp`
      }
    } catch (e: unknown) {
      const errData = (e as { response?: { data?: { message?: string } } })
        .response?.data
      showToast.error(
        errData?.message || 'Failed to initiate authentication'
      )
      await loadData() // reload to show error status
    } finally {
      setAuthenticatingId(null)
    }
  }

  const handleSetActive = async (account: BrokerAccount) => {
    try {
      await brokerAccountsApi.setActive(account.id)
      setActiveAccountId(account.id)
      showToast.success(
        `Switched to "${account.account_name}" (${account.broker})`
      )
      await loadData()
    } catch (e: unknown) {
      const errData = (e as { response?: { data?: { message?: string } } })
        .response?.data
      showToast.error(errData?.message || 'Failed to switch account')
    }
  }

  const handleOpenEdit = (account: BrokerAccount) => {
    setEditingAccount(account)
    setEditFormData({
      account_name: account.account_name,
      redirect_url: account.redirect_url || '',
      date_of_birth: account.date_of_birth || '',
      year_of_birth: account.year_of_birth || '',
      // Secret fields start empty — user only fills what they want to change
    })
    setShowEditDialog(true)
  }

  const handleUpdate = async () => {
    if (!editingAccount) return

    // Only send fields with actual non-empty values
    const payload: UpdateAccountPayload = {}
    for (const [key, value] of Object.entries(editFormData)) {
      if (value && typeof value === 'string' && value.trim() !== '') {
        ;(payload as Record<string, string>)[key] = value.trim()
      }
    }

    if (Object.keys(payload).length === 0) {
      showToast.error('No changes to save')
      return
    }

    setSubmitting(true)
    try {
      await brokerAccountsApi.update(editingAccount.id, payload)
      showToast.success('Account updated successfully')
      setShowEditDialog(false)
      setEditingAccount(null)
      await loadData()
    } catch (e: unknown) {
      const errData = (e as { response?: { data?: { message?: string } } })
        .response?.data
      showToast.error(errData?.message || 'Failed to update account')
    } finally {
      setSubmitting(false)
    }
  }

  const getConnectionIcon = (status: string) => {
    switch (status) {
      case 'connected':
        return <Wifi className="h-3 w-3 mr-1" />
      case 'error':
        return <AlertCircle className="h-3 w-3 mr-1" />
      default:
        return <WifiOff className="h-3 w-3 mr-1" />
    }
  }

  const getConnectionBadge = (account: BrokerAccount) => {
    if (account.connection_status === 'connected') {
      return (
        <Badge variant="default" className="bg-green-600 hover:bg-green-700">
          {getConnectionIcon('connected')}
          Connected
        </Badge>
      )
    }
    if (account.connection_status === 'error') {
      return (
        <Badge variant="destructive" title={account.error_message || ''}>
          {getConnectionIcon('error')}
          Error
        </Badge>
      )
    }
    return (
      <Badge variant="secondary">
        {getConnectionIcon('disconnected')}
        Disconnected
      </Badge>
    )
  }

  // Helper: does this account have a TOTP key stored (for auto-auth badge)
  const hasAutoAuth = (account: BrokerAccount) => {
    return account.totp_key && account.totp_key !== '' && account.totp_key !== '****'
      && !account.totp_key.match(/^\*+$/)
  }

  // Render
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="container mx-auto max-w-5xl py-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            Broker Accounts
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage multiple broker accounts. Add accounts for same or different
            brokers, authenticate them, and switch between them.
          </p>
        </div>
        <Button onClick={() => setShowAddDialog(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Add Account
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Account list */}
      {accounts.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Building2 className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">
              No Broker Accounts Yet
            </h3>
            <p className="text-muted-foreground mb-4">
              Add your first broker account to start trading. You can add
              multiple accounts of the same broker.
            </p>
            <Button onClick={() => setShowAddDialog(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Add Your First Account
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4">
          {accounts.map((account) => (
            <Card
              key={account.id}
              className={
                activeAccountId === account.id
                  ? 'border-primary ring-1 ring-primary'
                  : ''
              }
            >
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 flex-wrap">
                    <CardTitle className="text-lg">
                      {account.account_name}
                    </CardTitle>
                    <Badge variant="secondary">{account.broker}</Badge>
                    {getConnectionBadge(account)}
                    {hasAutoAuth(account) && (
                      <Badge variant="outline" className="border-yellow-500 text-yellow-600">
                        <Zap className="h-3 w-3 mr-1" />
                        Auto-Auth
                      </Badge>
                    )}
                    {activeAccountId === account.id && (
                      <Badge variant="outline" className="border-primary text-primary">
                        Active
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    {account.is_authenticated &&
                      activeAccountId !== account.id && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleSetActive(account)}
                        >
                          <Power className="h-4 w-4 mr-1" />
                          Set Active
                        </Button>
                      )}
                    <Button
                      size="sm"
                      variant={
                        account.is_authenticated ? 'outline' : 'default'
                      }
                      onClick={() => handleAuthenticate(account)}
                      disabled={authenticatingId === account.id}
                    >
                      {authenticatingId === account.id ? (
                        <>
                          <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                          Authenticating...
                        </>
                      ) : (
                        <>
                          <ExternalLink className="h-4 w-4 mr-1" />
                          {account.is_authenticated
                            ? 'Re-Authenticate'
                            : 'Authenticate'}
                        </>
                      )}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleOpenEdit(account)}
                      title="Edit account credentials"
                    >
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => setDeleteAccountId(account.id)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
                <CardDescription>
                  API Key: {account.broker_api_key}
                  {account.user_id && account.user_id !== '' && !account.user_id.match(/^\*+$/) && (
                    <> &bull; User: {account.user_id}</>
                  )}
                  {account.last_connected_at && (
                    <> &bull; Last connected: {new Date(account.last_connected_at).toLocaleString()}</>
                  )}
                  {!account.last_connected_at && account.created_at && (
                    <> &bull; Added {new Date(account.created_at).toLocaleDateString()}</>
                  )}
                  {account.error_message && account.connection_status === 'error' && (
                    <span className="text-destructive block mt-1 text-xs">
                      Error: {account.error_message}
                    </span>
                  )}
                </CardDescription>
              </CardHeader>
            </Card>
          ))}
        </div>
      )}

      {/* Add Account Dialog */}
      <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
        <DialogContent className="sm:max-w-[550px] max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Broker Account</DialogTitle>
            <DialogDescription>
              Add a new broker account with its API credentials. You can add
              multiple accounts for the same broker.
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="account_name">Account Name *</Label>
              <Input
                id="account_name"
                placeholder="e.g. Zerodha Main, Angel Scalping"
                value={formData.account_name}
                onChange={(e) =>
                  setFormData({ ...formData, account_name: e.target.value })
                }
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="broker">Broker *</Label>
              <Select
                value={formData.broker}
                onValueChange={(value) =>
                  setFormData({ ...formData, broker: value })
                }
              >
                <SelectTrigger id="broker">
                  <SelectValue placeholder="Select a broker" />
                </SelectTrigger>
                <SelectContent>
                  {brokers.map((b) => (
                    <SelectItem key={b.id} value={b.id}>
                      {b.name} ({b.auth_type.toUpperCase()})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {selectedBrokerInfo && (
                <p className="text-xs text-muted-foreground">
                  Authentication type:{' '}
                  {selectedBrokerInfo.auth_type === 'oauth'
                    ? 'OAuth (browser redirect)'
                    : 'TOTP (auto or manual login)'}
                </p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="broker_api_key">Broker API Key *</Label>
              <Input
                id="broker_api_key"
                placeholder="Enter broker API key"
                value={formData.broker_api_key}
                onChange={(e) =>
                  setFormData({ ...formData, broker_api_key: e.target.value })
                }
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="broker_api_secret">Broker API Secret *</Label>
              <Input
                id="broker_api_secret"
                type="password"
                placeholder="Enter broker API secret"
                value={formData.broker_api_secret}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    broker_api_secret: e.target.value,
                  })
                }
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="redirect_url">Redirect URL (optional)</Label>
              <Input
                id="redirect_url"
                placeholder={`e.g. http://127.0.0.1:5001/${formData.broker || '<broker>'}/callback`}
                value={formData.redirect_url}
                onChange={(e) =>
                  setFormData({ ...formData, redirect_url: e.target.value })
                }
              />
              <p className="text-xs text-muted-foreground">
                Required for OAuth brokers. Leave empty to use default.
              </p>
            </div>

            {isXtsBroker && (
              <>
                <div className="grid gap-2">
                  <Label htmlFor="broker_api_key_market">
                    Market Data API Key
                  </Label>
                  <Input
                    id="broker_api_key_market"
                    placeholder="Enter market data API key"
                    value={formData.broker_api_key_market}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        broker_api_key_market: e.target.value,
                      })
                    }
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="broker_api_secret_market">
                    Market Data API Secret
                  </Label>
                  <Input
                    id="broker_api_secret_market"
                    type="password"
                    placeholder="Enter market data API secret"
                    value={formData.broker_api_secret_market}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        broker_api_secret_market: e.target.value,
                      })
                    }
                  />
                </div>
              </>
            )}

            {/* Dynamic broker-specific fields */}
            {extraFields.length > 0 && (
              <>
                <div className="border-t pt-4 mt-1">
                  <p className="text-sm font-medium text-muted-foreground mb-3">
                    Broker-Specific Credentials
                    {extraFields.some(f => f.field === 'totp_key') && (
                      <span className="block text-xs font-normal mt-1">
                        Provide your TOTP secret key for automatic one-click authentication.
                      </span>
                    )}
                  </p>
                </div>
                {extraFields.map((fieldConfig) => (
                  <div className="grid gap-2" key={fieldConfig.field}>
                    <Label htmlFor={fieldConfig.field}>
                      {fieldConfig.label}
                      {fieldConfig.required && ' *'}
                    </Label>
                    <Input
                      id={fieldConfig.field}
                      type={fieldConfig.type || 'text'}
                      placeholder={fieldConfig.placeholder}
                      value={(formData[fieldConfig.field] as string) || ''}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          [fieldConfig.field]: e.target.value,
                        })
                      }
                    />
                  </div>
                ))}
              </>
            )}
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowAddDialog(false)}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={submitting}>
              {submitting ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Creating...
                </>
              ) : (
                'Create Account'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Account Dialog */}
      <Dialog
        open={showEditDialog}
        onOpenChange={(open) => {
          if (!open) {
            setShowEditDialog(false)
            setEditingAccount(null)
          }
        }}
      >
        <DialogContent className="sm:max-w-[550px] max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Broker Account</DialogTitle>
            <DialogDescription>
              Update account credentials. Leave secret fields empty to keep
              their current values.
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label>Account Name</Label>
              <Input
                value={editFormData.account_name || ''}
                onChange={(e) =>
                  setEditFormData({
                    ...editFormData,
                    account_name: e.target.value,
                  })
                }
              />
            </div>

            <div className="grid gap-2">
              <Label>Broker</Label>
              <Input value={editingAccount?.broker || ''} disabled />
              <p className="text-xs text-muted-foreground">
                Broker cannot be changed. Delete and recreate to switch.
              </p>
            </div>

            <div className="grid gap-2">
              <Label>Broker API Key</Label>
              <Input
                placeholder="Leave empty to keep current"
                value={editFormData.broker_api_key || ''}
                onChange={(e) =>
                  setEditFormData({
                    ...editFormData,
                    broker_api_key: e.target.value,
                  })
                }
              />
              {editingAccount?.broker_api_key && (
                <p className="text-xs text-muted-foreground">
                  Current: {editingAccount.broker_api_key}
                </p>
              )}
            </div>

            <div className="grid gap-2">
              <Label>Broker API Secret</Label>
              <Input
                type="password"
                placeholder="Leave empty to keep current"
                value={editFormData.broker_api_secret || ''}
                onChange={(e) =>
                  setEditFormData({
                    ...editFormData,
                    broker_api_secret: e.target.value,
                  })
                }
              />
            </div>

            <div className="grid gap-2">
              <Label>Redirect URL</Label>
              <Input
                placeholder="Leave empty to keep current"
                value={editFormData.redirect_url || ''}
                onChange={(e) =>
                  setEditFormData({
                    ...editFormData,
                    redirect_url: e.target.value,
                  })
                }
              />
            </div>

            {isEditXtsBroker && (
              <>
                <div className="grid gap-2">
                  <Label>Market Data API Key</Label>
                  <Input
                    placeholder="Leave empty to keep current"
                    value={editFormData.broker_api_key_market || ''}
                    onChange={(e) =>
                      setEditFormData({
                        ...editFormData,
                        broker_api_key_market: e.target.value,
                      })
                    }
                  />
                </div>
                <div className="grid gap-2">
                  <Label>Market Data API Secret</Label>
                  <Input
                    type="password"
                    placeholder="Leave empty to keep current"
                    value={editFormData.broker_api_secret_market || ''}
                    onChange={(e) =>
                      setEditFormData({
                        ...editFormData,
                        broker_api_secret_market: e.target.value,
                      })
                    }
                  />
                </div>
              </>
            )}

            {/* Dynamic broker-specific fields */}
            {editExtraFields.length > 0 && (
              <>
                <div className="border-t pt-4 mt-1">
                  <p className="text-sm font-medium text-muted-foreground mb-3">
                    Broker-Specific Credentials
                    <span className="block text-xs font-normal mt-1">
                      Leave fields empty to keep current values.
                    </span>
                  </p>
                </div>
                {editExtraFields.map((fieldConfig) => (
                  <div className="grid gap-2" key={fieldConfig.field}>
                    <Label>{fieldConfig.label}</Label>
                    <Input
                      type={fieldConfig.type || 'text'}
                      placeholder="Leave empty to keep current"
                      value={
                        (editFormData[
                          fieldConfig.field as keyof UpdateAccountPayload
                        ] as string) || ''
                      }
                      onChange={(e) =>
                        setEditFormData({
                          ...editFormData,
                          [fieldConfig.field]: e.target.value,
                        })
                      }
                    />
                  </div>
                ))}
              </>
            )}
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowEditDialog(false)
                setEditingAccount(null)
              }}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button onClick={handleUpdate} disabled={submitting}>
              {submitting ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Saving...
                </>
              ) : (
                'Save Changes'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <AlertDialog
        open={deleteAccountId !== null}
        onOpenChange={(open) => !open && setDeleteAccountId(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Broker Account?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete this broker account and its
              authentication data. Any API keys associated with this account
              will also be removed. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={submitting}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              disabled={submitting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {submitting ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Deleting...
                </>
              ) : (
                'Delete Account'
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
