import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Plus, Trash2, Info } from 'lucide-react'
import { TagInput } from './BasicTab'
import type { AppConfig } from '@/lib/api-client'

interface AdvancedTabProps {
  config: AppConfig
  updateConfig: (key: keyof AppConfig, value: any) => void
}

export function AdvancedTab({ config, updateConfig }: AdvancedTabProps) {
  const adv = config.advanced

  const updateAdv = (patch: Partial<NonNullable<AppConfig['advanced']>>) => {
    updateConfig('advanced', { ...adv, ...patch })
  }

  return (
    <div className="max-w-2xl space-y-8">
      {/* Listener */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-foreground">Listener</h2>
        <Card className="shadow-none border-border">
          <CardContent className="p-5 space-y-3">
            <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg border border-border">
              <div className="space-y-0.5">
                <Label className="text-xs font-bold">Listen IPv6</Label>
                <p className="text-[10px] text-muted-foreground">Accept connections over IPv6</p>
              </div>
              <Switch
                checked={adv?.listen_ipv6 || false}
                onCheckedChange={(c) => updateAdv({ listen_ipv6: c })}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Trusted Proxies */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-foreground">Trusted Proxies</h2>
        <Card className="shadow-none border-border">
          <CardContent className="p-5 space-y-3">
            <p className="text-[10px] text-muted-foreground">
              CIDR ranges of reverse proxies / CDN (e.g. Cloudflare, nginx) in front of this app.
              These IPs are skipped when extracting the real client IP from X-Forwarded-For.
            </p>
            <div className="space-y-1.5">
              <Label className="text-[10px] font-bold text-muted-foreground uppercase">Proxy CIDRs (one per line)</Label>
              <Textarea
                value={(adv?.trusted_proxies || []).join('\n')}
                onChange={(e) => {
                  const lines = e.target.value
                    .split('\n')
                    .map(l => l.trim())
                    .filter(l => l !== '');
                  updateAdv({ trusted_proxies: lines });
                }}
                placeholder={"173.245.48.0/20\n103.21.244.0/22\n10.0.0.0/8"}
                className="min-h-[120px] font-mono text-xs"
              />
              <p className="text-[9px] text-muted-foreground">
                One CIDR per line. Format: <span className="font-mono">1.2.3.0/24</span> or <span className="font-mono">::1/128</span>.
                For Cloudflare, see their <a href="https://www.cloudflare.com/ips/" target="_blank" rel="noopener noreferrer" className="underline text-primary">IP ranges</a>.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
{/* Upstream Connection */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-foreground">Upstream Connection</h2>
        <Card className="shadow-none border-border">
          <CardContent className="p-5 space-y-4">
            <div className="space-y-2">
              <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Timeouts (seconds)</p>
              <div className="grid grid-cols-3 gap-3">
                <div className="space-y-1.5">
                  <Label className="text-[10px] font-bold text-muted-foreground uppercase tracking-tighter">Connect</Label>
                  <Input
                    type="number"
                    value={adv?.connect_timeout ?? 5}
                    onChange={(e) => updateAdv({ connect_timeout: parseInt(e.target.value) || 5 })}
                    className="h-9 text-xs border-input font-mono"
                  />
                  <p className="text-[9px] text-muted-foreground">Establish conn.</p>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-[10px] font-bold text-muted-foreground uppercase tracking-tighter">Read</Label>
                  <Input
                    type="number"
                    value={adv?.read_timeout ?? 60}
                    onChange={(e) => updateAdv({ read_timeout: parseInt(e.target.value) || 60 })}
                    className="h-9 text-xs border-input font-mono"
                  />
                  <p className="text-[9px] text-muted-foreground">Read response</p>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-[10px] font-bold text-muted-foreground uppercase tracking-tighter">Send</Label>
                  <Input
                    type="number"
                    value={adv?.send_timeout ?? 60}
                    onChange={(e) => updateAdv({ send_timeout: parseInt(e.target.value) || 60 })}
                    className="h-9 text-xs border-input font-mono"
                  />
                  <p className="text-[9px] text-muted-foreground">Send request</p>
                </div>
              </div>
            </div>

            <div className="border-t border-border pt-4 space-y-3">
              <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg border border-border">
                <div className="space-y-0.5">
                  <Label className="text-xs font-bold">Proxy Buffering</Label>
                  <p className="text-[10px] text-muted-foreground">Buffer responses before sending to client. Disable for SSE / streaming.</p>
                </div>
                <Switch
                  checked={adv?.proxy_buffering ?? true}
                  onCheckedChange={(c) => updateAdv({ proxy_buffering: c })}
                />
              </div>
              {!(adv?.proxy_buffering ?? true) && (
                <div className="flex items-start gap-2 px-3 py-2 bg-muted/50 rounded-lg border border-border">
                  <Info className="w-3.5 h-3.5 text-blue-500 mt-0.5 shrink-0" />
                  <p className="text-[10px] text-muted-foreground">Streaming mode responses flow directly to client.</p>
                </div>
              )}
              <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg border border-border">
                <div className="space-y-0.5">
                  <Label className="text-xs font-bold text-foreground">Allow Insecure SSL</Label>
                  <p className="text-[10px] text-amber-700">Skip TLS certificate verification for upstream</p>
                </div>
                <Switch
                  checked={adv?.allow_insecure_ssl || false}
                  onCheckedChange={(c) => updateAdv({ allow_insecure_ssl: c })}
                />
              </div>
              <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg border border-border">
                <div className="space-y-0.5">
                  <Label className="text-xs font-bold">Allow WebSocket</Label>
                  <p className="text-[10px] text-muted-foreground">Enable WebSocket upgrade passthrough (bypasses WAF pipeline)</p>
                </div>
                <Switch
                  checked={adv?.allow_websocket || false}
                  onCheckedChange={(c) => updateAdv({ allow_websocket: c })}
                />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Request Headers */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-foreground">Request Headers</h2>
        <Card className="shadow-none border-border">
          <CardContent className="p-5 space-y-3">
            <div className="space-y-3 p-3 bg-muted/50 rounded-lg border border-border">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-xs font-bold">Modify Host Header</Label>
                  <p className="text-[10px] text-muted-foreground">Override Host header sent to upstream</p>
                </div>
                <Switch
                  checked={adv?.modify_host_header || false}
                  onCheckedChange={(c) => updateAdv({ modify_host_header: c })}
                />
              </div>
              {adv?.modify_host_header && (
                <div className="space-y-1.5 pt-1">
                  <Label className="text-[10px] font-bold text-muted-foreground uppercase">Host Header Value</Label>
                  <Input
                    value={adv?.host_header_value || '$http_host'}
                    onChange={(e) => updateAdv({ host_header_value: e.target.value })}
                    placeholder="$http_host"
                    className="h-9 text-xs border-input font-mono"
                  />
                  <p className="text-[9px] text-muted-foreground">Use $http_host for original or specify custom value</p>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg border border-border">
              <div className="space-y-0.5">
                <Label className="text-xs font-bold">Pass X-Forwarded-Host</Label>
                <p className="text-[10px] text-muted-foreground">Inject X-Forwarded-Host to upstream</p>
              </div>
              <Switch
                checked={adv?.pass_x_forwarded_host ?? true}
                onCheckedChange={(c) => updateAdv({ pass_x_forwarded_host: c })}
              />
            </div>

            <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg border border-border">
              <div className="space-y-0.5">
                <Label className="text-xs font-bold">Pass X-Forwarded-Proto</Label>
                <p className="text-[10px] text-muted-foreground">Inject X-Forwarded-Proto to upstream</p>
              </div>
              <Switch
                checked={adv?.pass_x_forwarded_proto ?? true}
                onCheckedChange={(c) => updateAdv({ pass_x_forwarded_proto: c })}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Response Headers */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground">Response Headers</h2>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => updateAdv({ add_headers: [...(adv?.add_headers || []), { name: '', value: '' }] })}
            className="h-7 text-[10px] font-bold btn-primary text-white hover:opacity-90 px-2"
          >
            <Plus className="w-3 h-3 mr-1" /> ADD
          </Button>
        </div>
        <Card className="shadow-none border-border">
          <CardContent className="p-5">
            {(adv?.add_headers || []).length === 0 ? (
              <div className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg border border-border">
                <Info className="w-4 h-4 text-muted-foreground mt-0.5 shrink-0" />
                <p className="text-[10px] text-muted-foreground leading-relaxed">
                  Inject headers into every response e.g. <span className="font-mono">X-Frame-Options</span>, <span className="font-mono">Strict-Transport-Security</span>, <span className="font-mono">Cache-Control</span>.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {(adv?.add_headers || []).map((header, index) => (
                  <div key={index} className="grid grid-cols-12 gap-3 items-center bg-muted/30 p-3 rounded-lg border border-border">
                    <div className="col-span-5 space-y-1">
                      <Label className="text-[9px] font-bold text-muted-foreground uppercase">Name</Label>
                      <Input
                        value={header.name}
                        onChange={(e) => {
                          const headers = [...(adv?.add_headers || [])]
                          headers[index] = { ...headers[index], name: e.target.value }
                          updateAdv({ add_headers: headers })
                        }}
                        placeholder="X-Frame-Options"
                        className="h-8 text-xs border-input font-mono"
                      />
                    </div>
                    <div className="col-span-6 space-y-1">
                      <Label className="text-[9px] font-bold text-muted-foreground uppercase">Value</Label>
                      <Input
                        value={header.value}
                        onChange={(e) => {
                          const headers = [...(adv?.add_headers || [])]
                          headers[index] = { ...headers[index], value: e.target.value }
                          updateAdv({ add_headers: headers })
                        }}
                        placeholder="DENY"
                        className="h-8 text-xs border-input font-mono"
                      />
                    </div>
                    <div className="col-span-1 flex justify-center pt-4">
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-muted-foreground hover:text-foreground hover:bg-muted"
                        onClick={() => {
                          const headers = [...(adv?.add_headers || [])]
                          headers.splice(index, 1)
                          updateAdv({ add_headers: headers })
                        }}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Request Size Limit */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-foreground">Request Size Limit</h2>
        <Card className="shadow-none border-border">
          <CardContent className="p-5 space-y-3">
            <div className="space-y-1.5">
              <Label className="text-[10px] font-bold text-muted-foreground uppercase">Max Body Size (MB)</Label>
              <Input
                type="number"
                value={adv?.request_size_limit ?? 0}
                onChange={(e) => updateAdv({ request_size_limit: parseInt(e.target.value) || 0 })}
                placeholder="0"
                className="h-9 text-xs border-input font-mono"
              />
              <p className="text-[9px] text-muted-foreground">Set to 0 to disable. Requests exceeding this limit return 413.</p>
            </div>
            {(adv?.request_size_limit ?? 0) > 0 && (
              <div className="flex items-start gap-2 p-2.5 bg-muted/50 rounded-lg border border-border">
                <Info className="w-3.5 h-3.5 text-blue-500 mt-0.5 shrink-0" />
                <p className="text-[10px] text-muted-foreground">
                  Limit: <span className="font-mono font-bold">{adv?.request_size_limit} MB</span>
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* CORS */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-foreground">CORS</h2>
        <Card className="shadow-none border-border">
          <CardContent className="p-5 space-y-3">
            <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg border border-border">
              <div className="space-y-0.5">
                <Label className="text-xs font-bold">Enable CORS</Label>
                <p className="text-[10px] text-muted-foreground">Inject CORS headers on responses</p>
              </div>
              <Switch
                checked={adv?.cors?.enabled || false}
                onCheckedChange={(c) => updateAdv({ cors: { allow_origins: [], allow_methods: [], allow_headers: [], expose_headers: [], allow_credentials: false, max_age: 86400, ...adv?.cors, enabled: c } })}
              />
            </div>
            {adv?.cors?.enabled && (
              <div className="space-y-3 pt-1">
                <div className="space-y-1.5">
                  <Label className="text-[10px] font-bold text-muted-foreground uppercase">Allow Origins</Label>
                  <TagInput
                    tags={adv?.cors?.allow_origins || []}
                    onChange={(tags) => updateAdv({ cors: { ...adv?.cors, allow_origins: tags } })}
                    placeholder="https://example.com"
                  />
                  <p className="text-[9px] text-muted-foreground">Enter then press Enter or comma. Use * to allow all.</p>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-[10px] font-bold text-muted-foreground uppercase">Allow Methods</Label>
                  <TagInput
                    tags={adv?.cors?.allow_methods || []}
                    onChange={(tags) => updateAdv({ cors: { ...adv?.cors, allow_methods: tags } })}
                    placeholder="GET"
                    uppercase
                  />
                  <p className="text-[9px] text-muted-foreground">Press Enter or comma to add.</p>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-[10px] font-bold text-muted-foreground uppercase">Allow Headers</Label>
                  <TagInput
                    tags={adv?.cors?.allow_headers || []}
                    onChange={(tags) => updateAdv({ cors: { ...adv?.cors, allow_headers: tags } })}
                    placeholder="Content-Type"
                  />
                  <p className="text-[9px] text-muted-foreground">Press Enter or comma to add.</p>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label className="text-[10px] font-bold text-muted-foreground uppercase">Max Age (sec)</Label>
                    <Input
                      type="number"
                      value={adv?.cors?.max_age ?? 86400}
                      onChange={(e) => updateAdv({ cors: { ...adv?.cors, max_age: parseInt(e.target.value) || 86400 } })}
                      className="h-9 text-xs border-input font-mono"
                    />
                  </div>
                  <div className="flex items-end pb-1">
                    <div className="flex items-center justify-between w-full p-2.5 bg-muted/50 rounded-lg border border-border">
                      <Label className="text-[10px] font-bold">Allow Credentials</Label>
                      <Switch
                        checked={adv?.cors?.allow_credentials || false}
                        onCheckedChange={(c) => updateAdv({ cors: { ...adv?.cors, allow_credentials: c } })}
                      />
                    </div>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Cache Control */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-foreground">Cache Control</h2>
        <Card className="shadow-none border-border">
          <CardContent className="p-5 space-y-3">
            <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg border border-border">
              <div className="space-y-0.5">
                <Label className="text-xs font-bold">Enable Cache Headers</Label>
                <p className="text-[10px] text-muted-foreground">Set Cache-Control on static asset responses</p>
              </div>
              <Switch
                checked={adv?.cache?.enabled || false}
                onCheckedChange={(c) => updateAdv({ cache: { ttl: 3600, ...adv?.cache, enabled: c } })}
              />
            </div>
            {adv?.cache?.enabled && (
              <div className="space-y-3 pt-1">
                <div className="space-y-1.5">
                  <Label className="text-[10px] font-bold text-muted-foreground uppercase">TTL (seconds)</Label>
                  <Input
                    type="number"
                    value={adv?.cache?.ttl ?? 3600}
                    onChange={(e) => updateAdv({ cache: { ...adv?.cache, ttl: parseInt(e.target.value) || 3600 } })}
                    className="h-9 text-xs border-input font-mono"
                  />
                  <p className="text-[9px] text-muted-foreground">
                    Applied as <span className="font-mono">Cache-Control: public, max-age={adv?.cache?.ttl ?? 3600}</span> on static assets (.js, .css, images, fonts).
                  </p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
