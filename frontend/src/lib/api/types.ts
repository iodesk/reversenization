export interface RateLimitProfile {
  type: string;
  duration: number;
  count: number;
  action: string;
  challenge_sec: number;
}

export interface WAFProfile {
  score_threshold: number;
  outbound_score_threshold?: number;
}

export interface BotProfile {
  enable_challenge: boolean;
  challenge_type: string;
  challenge_expiry: number;
  challenge_wait: number;
}

export interface Upstream {
  scheme: "http" | "https" | "tcp" | "udp";
  host: string;
  port: number;
  weight: number;
  enabled: boolean;
  healthy?: boolean;
}

export interface ResponseHeader {
  name: string;
  value: string;
}

export interface CORSConfig {
  enabled: boolean;
  allow_origins: string[];
  allow_methods: string[];
  allow_headers: string[];
  expose_headers: string[];
  allow_credentials: boolean;
  max_age: number;
}

export interface CacheConfig {
  enabled: boolean;
  ttl: number;
}

export interface AdvancedConfig {
  listen_ipv6: boolean;
  allow_websocket: boolean;
  modify_host_header: boolean;
  host_header_value: string;
  pass_x_forwarded_host: boolean;
  pass_x_forwarded_proto: boolean;
  allow_insecure_ssl: boolean;
  trusted_proxies: string[];
  connect_timeout: number;
  read_timeout: number;
  send_timeout: number;
  proxy_buffering: boolean;
  add_headers: ResponseHeader[];
  request_size_limit: number;
  cors: CORSConfig;
  cache: CacheConfig;
}

export interface HealthCheckConfig {
  enabled: boolean;
  path: string;
  interval: number;
  threshold: number;
}

export interface AppConfig {
  upstreams: Upstream[];
  lb_method: "round-robin" | "least-conn" | "ip-hash";
  listen_port?: number;
  use_global_rate_limit: boolean;
  rate_limits?: RateLimitProfile[];
  use_global_waf: boolean;
  waf?: WAFProfile;
  use_global_bot: boolean;
  bot?: BotProfile;
  redirect_https: boolean;
  health_check: HealthCheckConfig;
  advanced?: AdvancedConfig;
}

export interface AppStats {
  total_requests: number;
  clean_requests: number;
  blocked_requests: number;
  challenged_requests: number;
  managed_requests: number;
}

export interface App {
  id: string;
  domain: string;
  description?: string;
  config: AppConfig;
  under_attack_mode: boolean;
  created_at: string;
  updated_at: string;
  stats?: AppStats;
}

export interface AppCreateRequest {
  id: string;
  domain: string;
  description?: string;
  config: AppConfig;
}

export interface AppUpdateRequest {
  domain: string;
  description?: string;
  config: AppConfig;
}

export interface Rule {
  id: number;
  app_id?: string;
  name: string;
  scope: "app" | "managed";
  rule_group: "bot_protection" | "rate_limit" | "custom";
  expression_raw: string;
  expression_structure?: any;
  action: "allow" | "block" | "challenge" | "log" | "skip";
  skip_modules?: string[];
  priority: number;
  enabled: boolean;
  description: string;
}

export interface RuleCreateRequest {
  name: string;
  scope: "app" | "managed";
  app_id?: string;
  rule_group: "bot_protection" | "rate_limit" | "custom";
  expression_raw: string;
  action: "allow" | "block" | "challenge" | "log" | "skip";
  skip_modules?: string[];
  priority: number;
  enabled: boolean;
  description: string;
}

export type RuleUpdateRequest = RuleCreateRequest;

export interface ValidateExpressionRequest {
  expression: string;
}

export interface ValidateExpressionResponse {
  valid: boolean;
  error?: string;
}

export interface BotPattern {
  id: number;
  pattern_type: 'good_bot' | 'bad_bot' | 'suspicious_ua' | 'bad_referer';
  pattern: string;
  score: number;
  verify_ip: boolean;
  enabled: boolean;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface BotPatternRequest {
  pattern_type: 'good_bot' | 'bad_bot' | 'suspicious_ua' | 'bad_referer';
  pattern: string;
  score: number;
  verify_ip: boolean;
  enabled: boolean;
  description: string;
}

export interface ChallengeConfig {
  title: string;
  description: string;
  footer: string;
  custom_html: string;
  show_ray_id: boolean;
}

export interface ChallengeTrustLevel {
  level0_max: number;
  level1_max: number;
  level2_max: number;
  reductions: [number, number, number, number];
}

export interface BotConfig {
  threshold: number;
  action: string;
  challenge_duration: number;
  challenge_wait: number;
  rules: Record<string, number>;
  challenge: ChallengeConfig;
  trust_levels: ChallengeTrustLevel;
}

export interface WAFConfig {
  paranoia_level: number;
  anomaly_threshold: number;
  outbound_anomaly_threshold: number;
  allowed_methods: string[];
  disabled_rules: number[];
  custom_rules: string;
  modules?: Record<string, string>;
}

export interface LogEntry {
  ts: string;
  ip: string;
  host: string;
  path: string;
  ua: string;
  action: "allow" | "block" | "challenge" | "challenge_solved" | "challenge_failed";
  reason: string;
  status: number;
  latency: number;
  pipeline_latency: number;
  upstream_latency: number;
  app_id: string;
  country: string;
  asn: number;
  asn_org: string;
  device_type: string;
  os: string;
  pipeline_trace?: string;
}

export interface LogQueryParams {
  limit?: number;
  action?: "allow" | "block" | "challenge";
  app_id?: string;
  q?: string;
  days?: number;
  reason_like?: string;
  trace_like?: string;
  offset?: number;
}

export interface ErrorResponse {
  error: string;
  message?: string;
}

export interface SuccessResponse {
  success: boolean;
  message?: string;
}

export interface HealthResponse {
  status: string;
}

export interface RateLimitConfig {
  enabled: boolean;
  duration: number;
  count: number;
  action: string;
  challenge_sec: number;
}

export interface RateLimitResponse {
  basic: RateLimitConfig;
  attack: RateLimitConfig;
  error: RateLimitConfig;
}

export interface RateLimitUpdateRequest {
  basic?: RateLimitConfig;
  attack?: RateLimitConfig;
  error?: RateLimitConfig;
}

export interface IPAccessRule {
  id: number;
  app_id: string;
  ip_range: string;
  description: string;
  action: "allow" | "block" | "challenge";
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface IPAccessRuleCreateRequest {
  ip_range: string;
  description: string;
  action: "allow" | "block" | "challenge";
  enabled: boolean;
  app_id?: string;
}

export interface IPAccessRuleUpdateRequest {
  ip_range?: string;
  description?: string;
  action?: "allow" | "block" | "challenge";
  enabled?: boolean;
}

export interface TrafficDataPoint {
  timestamp: string;
  label: string;
  allow: number;
  block: number;
  challenge: number;
}

export interface TrafficAnalyticsResponse {
  range: string;
  data: TrafficDataPoint[];
  summary: {
    total: number;
    allow: number;
    block: number;
    block_waf: number;
    block_bot: number;
    challenge: number;
  };
}

export interface TrafficAnalyticsParams {
  range: '1d' | '7d' | '30d';
  app_id?: string;
}

export interface Certificate {
  domain: string;
  status: string;
  issuer: string;
  expires_at: string;
  days_until_expiry: number;
  auto_renew: boolean;
  is_expiring_soon: boolean;
  last_renew_at?: string;
  last_renew_status: string;
}

export interface CertificateLog {
  id: number;
  domain: string;
  action: string;
  status: string;
  message: string;
  created_at: string;
}

export interface ToggleAutoRenewRequest {
  enabled: boolean;
}

export interface ScoringThresholds {
  block: number;
  challenge: number;
}

export interface CategoryWeight {
  enabled: boolean;
  max_score: number;
  multiplier: number;
}

export interface ScoringWeights {
  ip_reputation: CategoryWeight;
  bot_detection: CategoryWeight;
  waf_anomaly: CategoryWeight;
  protocol_anomaly: CategoryWeight;
}

export interface TrustReductionConfig {
  trusted_history: number;
  trusted_history_threshold: number;
  stable_session: number;
  good_bot: number;
}

export interface ScoringConfig {
  thresholds: ScoringThresholds;
  weights: ScoringWeights;
  trust: TrustReductionConfig;
}

export interface BotIPRange {
  id: number;
  name: string;
  source_type: 'json_url' | 'manual';
  url: string;
  ip_ranges: string[];
  enabled: boolean;
  description: string;
  last_fetched: string | null;
  created_at: string;
  updated_at: string;
}

export interface BotIPRangeRequest {
  name: string;
  source_type: 'json_url' | 'manual';
  url: string;
  ip_ranges: string[];
  enabled: boolean;
  description: string;
}

export interface ProtocolAnomalyConfig {
  rules: Record<string, number>;
}

export interface ThreatIPEntry {
  ip: string;
  country: string;
  asn_org: string;
  total: number;
  blocked: number;
  challenged: number;
  block_rate: number;
}

export interface ThreatIPResponse {
  items: ThreatIPEntry[];
  total_ips: number;
  total_events: number;
}

export interface WAFRuleEntry {
  rule_id: string;
  total: number;
  blocked: number;
  challenged: number;
  allowed: number;
}

export interface WAFRuleIntelResponse {
  items: WAFRuleEntry[];
}

export interface CustomRuleEntry {
  rule_id: string;
  rule_name: string;
  total: number;
  blocked: number;
  challenged: number;
  allowed: number;
}

export interface CustomRuleIntelResponse {
  items: CustomRuleEntry[];
}

export interface ScoreBucket {
  range: string;
  count: number;
}

export interface CategoryTrend {
  label: string;
  ip_reputation: number;
  bot_detection: number;
  waf_anomaly: number;
  protocol_anomaly: number;
}

export interface CategoryAverage {
  ip_reputation: number;
  bot_detection: number;
  waf_anomaly: number;
  protocol_anomaly: number;
}

export interface ThreatSummaryResponse {
  score_distribution: ScoreBucket[];
  category_trend: CategoryTrend[];
  category_avg: CategoryAverage;
}


export interface IPReputationEntry {
  id: number;
  entry_type: 'ip' | 'asn';
  value: string;
  score: number;
  category: string;
  description: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface IPReputationEntryRequest {
  entry_type: 'ip' | 'asn';
  value?: string;
  values?: string[];
  score: number;
  category?: string;
  description: string;
  enabled: boolean;
  auto_detect_provider?: boolean;
}

export interface IPReputationConfig {
  maxmind_dc_score: number;
  maxmind_asn_score: number;
  spamhaus_ip_score: number;
  spamhaus_asn_score: number;
}
