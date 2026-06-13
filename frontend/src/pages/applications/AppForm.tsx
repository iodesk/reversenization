import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useApp, useCreateApp, useUpdateApp } from '@/hooks/useApi'
import { Button } from '@/components/ui/button'
import { useToast } from '@/components/ui/toast'
import { Tabs } from '@/components/ui/tabs'
import {
  Plus,
  Shield,
  ShieldAlert,
  Globe,
  ChevronLeft,
  Save,
  Info,
  Settings,
  FileCode,
} from 'lucide-react'
import { IPAccessSection } from '@/components/ip-access/IPAccessSection'
import { AppRulesSection } from '@/components/rules/AppRulesSection'
import { BasicTab } from './tabs/BasicTab'
import { SecurityTab } from './tabs/SecurityTab'
import { AdvancedTab } from './tabs/AdvancedTab'
import type { AppCreateRequest, AppConfig } from '@/lib/api-client'

const defaultAppConfig: AppConfig = {
  upstreams: [
    { scheme: 'http', host: '', port: 80, weight: 1, enabled: true }
  ],
  lb_method: 'round-robin',
  use_global_rate_limit: true,
  rate_limits: [
    { type: 'BasicAccess', duration: 60, count: 100, action: 'challenge', challenge_sec: 300 },
    { type: 'Attack', duration: 1, count: 10, action: 'block', challenge_sec: 600 },
    { type: 'Error', duration: 1, count: 20, action: 'challenge', challenge_sec: 300 }
  ],
  use_global_waf: true,
  waf: { score_threshold: 20 },
  use_global_bot: true,
  bot: { enable_challenge: true, challenge_type: 'js', challenge_expiry: 300, challenge_wait: 5 },
  redirect_https: false,
  health_check: {
    enabled: false,
    path: '/health',
    interval: 30,
    threshold: 3,
  },
  advanced: {
    listen_ipv6: false,
    allow_websocket: false,
    modify_host_header: false,
    host_header_value: '$http_host',
    pass_x_forwarded_host: true,
    pass_x_forwarded_proto: true,
    allow_insecure_ssl: false,
    trusted_proxies: [],
    connect_timeout: 5,
    read_timeout: 60,
    send_timeout: 60,
    proxy_buffering: true,
    add_headers: [],
    request_size_limit: 0,
    cors: {
      enabled: false,
      allow_origins: [],
      allow_methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allow_headers: ['Content-Type', 'Authorization'],
      expose_headers: [],
      allow_credentials: false,
      max_age: 86400,
    },
    cache: {
      enabled: false,
      ttl: 3600,
    },
  }
}

export default function AppForm() {
  const { id } = useParams()
  const isEdit = !!id
  const navigate = useNavigate()
  const { addToast } = useToast()

  const { data: existingApp, isLoading: isAppLoading } = useApp(id || '')
  const createApp = useCreateApp()
  const updateApp = useUpdateApp()

  const [formData, setFormData] = useState<AppCreateRequest>({
    id: '',
    domain: '',
    description: '',
    config: { ...defaultAppConfig }
  })

  const [activeTab, setActiveTab] = useState('basic')

  useEffect(() => {
    if (isEdit && existingApp) {
      const config = existingApp.config || JSON.parse(JSON.stringify(defaultAppConfig))
      const sanitizedConfig = {
        ...config,
        upstreams: (config.upstreams || []).map((u: any) => ({
          ...u,
          weight: u.weight && u.weight >= 1 ? u.weight : 1,
        })),
        health_check: {
          enabled: config.health_check?.enabled || false,
          path: config.health_check?.path || '/health',
          interval: config.health_check?.interval > 0 ? config.health_check.interval : 30,
          threshold: config.health_check?.threshold > 0 ? config.health_check.threshold : 3,
        },
      }
      setFormData({
        id: existingApp.id,
        domain: existingApp.domain,
        description: existingApp.description || '',
        config: sanitizedConfig,
      })
    }
  }, [isEdit, existingApp])

  const updateConfig = (key: keyof AppConfig, value: any) => {
    setFormData(prev => ({
      ...prev,
      config: { ...prev.config, [key]: value }
    }))
  }

  const isStream = formData.config.upstreams.length > 0 &&
    (formData.config.upstreams[0].scheme === 'tcp' || formData.config.upstreams[0].scheme === 'udp')

  useEffect(() => {
    if (isStream && (activeTab === 'security' || activeTab === 'advanced' || activeTab === 'rules')) {
      setActiveTab('basic')
    }
  }, [isStream])

  const handleSave = async () => {
    const activeUpstreams = formData.config.upstreams.filter(u => u.enabled !== false)
    if (activeUpstreams.length === 0) {
      addToast('At least one upstream must be enabled', 'error')
      setActiveTab('basic')
      return
    }
    const invalidWeight = formData.config.upstreams.some(u => (u.weight ?? 1) < 1 || (u.weight ?? 1) > 100)
    if (invalidWeight) {
      addToast('Upstream weight must be between 1 and 100', 'error')
      setActiveTab('basic')
      return
    }
    try {
      if (isEdit) {
        const { id: _, ...updateData } = formData
        await updateApp.mutateAsync({ id: id!, data: updateData })
        addToast('Application updated successfully', 'success')
      } else {
        await createApp.mutateAsync(formData)
        addToast('Application created successfully', 'success')
      }
      navigate('/applications')
    } catch {
      addToast(`Failed to ${isEdit ? 'update' : 'create'} application`, 'error')
    }
  }

  if (isEdit && isAppLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-2 border-border border-t-foreground"></div>
      </div>
    )
  }

  const tabList = [
    { value: 'basic', label: 'Basic', icon: <Globe className="w-3.5 h-3.5" /> },
    {
      value: 'security',
      label: 'WAF',
      icon: <Shield className="w-3.5 h-3.5" />,
      disabled: isStream,
      disabledTooltip: 'WAF, Bot, and Rate Limit are not available for TCP/UDP applications'
    },
    {
      value: 'advanced',
      label: 'Advanced',
      icon: <Settings className="w-3.5 h-3.5" />,
      disabled: isStream,
      disabledTooltip: 'Advanced HTTP settings are not available for TCP/UDP applications'
    },
    {
      value: 'ip-access',
      label: 'IP Access',
      icon: <ShieldAlert className="w-3.5 h-3.5" />,
      disabled: !isEdit,
      disabledTooltip: 'Create the application first to configure IP access rules'
    },
    {
      value: 'rules',
      label: 'Security Rules',
      icon: <FileCode className="w-3.5 h-3.5" />,
      disabled: !isEdit || isStream,
      disabledTooltip: isStream
        ? 'Security rules are not available for TCP/UDP applications'
        : 'Create the application first to configure security rules'
    },
  ]

  return (
    <div className="animate-in pb-12">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border pb-5 mb-6">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/applications')} className="h-9 w-9 text-muted-foreground">
            <ChevronLeft className="w-5 h-5" />
          </Button>
          <div>
            <h1 className="text-xl font-bold text-foreground tracking-tight">
              {isEdit ? 'Edit Application' : 'Create Application'}
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              {isEdit ? `Updating ${formData.domain}` : 'Define domain and security rules for your application'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="ghost" onClick={() => navigate('/applications')} className="text-muted-foreground font-bold text-xs uppercase tracking-wider">Cancel</Button>
          <Button onClick={handleSave} className="shadow-none px-6">
            {isEdit ? <Save className="w-4 h-4 mr-2" /> : <Plus className="w-4 h-4 mr-2" />}
            {isEdit ? 'Save' : 'Create'}
          </Button>
        </div>
      </div>

      {/* Mobile: tabs horizontal on top */}
      <div className="lg:hidden mb-4">
        <Tabs value={activeTab} onValueChange={setActiveTab} tabs={tabList} />
        {!isEdit && (
          <div className="mt-3 flex items-start gap-2 p-3 bg-red-600/10 dark:bg-red-400/10 rounded-lg border border-red-600/20 dark:border-red-400/20">
            <Info className="w-4 h-4 text-red-600 dark:text-red-400 mt-0.5 shrink-0" />
            <p className="text-[11px] text-red-600 dark:text-red-400 leading-relaxed font-medium">
              {isStream
                ? <><strong className="font-bold">IP Access</strong> tab will be available after you create the application.</>
                : <><strong className="font-bold">IP Access</strong> and <strong className="font-bold">Security Rules</strong> tabs will be available after you create the application.</>
              }
            </p>
          </div>
        )}
      </div>

      {/* Desktop: tabs vertical on left, content on right */}
      <div className="flex gap-6 items-start">
        <div className="hidden lg:flex flex-col gap-2 w-60 shrink-0">
          <Tabs value={activeTab} onValueChange={setActiveTab} tabs={tabList} orientation="vertical" />
          {!isEdit && (
            <div className="flex items-start gap-2 p-3 bg-red-600/10 dark:bg-red-400/10 rounded-lg border border-red-600/20 dark:border-red-400/20">
              <Info className="w-3.5 h-3.5 text-red-600 dark:text-red-400 mt-0.5 shrink-0" />
              <p className="text-[10px] text-red-600 dark:text-red-400 leading-relaxed font-medium">
                {isStream
                  ? <><strong>IP Access</strong> available after creating.</>
                  : <><strong>IP Access</strong> and <strong>Security Rules</strong> available after creating.</>
                }
              </p>
            </div>
          )}
        </div>

        {/* Tab Content */}
        <div className="flex-1 min-w-0 animate-in fade-in duration-200">
          {activeTab === 'basic' && (
            <BasicTab
              formData={formData}
              isEdit={isEdit}
              setFormData={setFormData}
              updateConfig={updateConfig}
            />
          )}

          {activeTab === 'security' && (
            <SecurityTab
              config={formData.config}
              updateConfig={updateConfig}
            />
          )}

          {activeTab === 'advanced' && (
            <AdvancedTab
              config={formData.config}
              updateConfig={updateConfig}
            />
          )}

          {activeTab === 'ip-access' && isEdit && <IPAccessSection appId={id!} />}

          {activeTab === 'rules' && isEdit && <AppRulesSection appId={id!} />}
        </div>
      </div>
    </div>
  )
}
