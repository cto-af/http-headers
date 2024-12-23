export interface Header<Name extends string> {
  kind: Name; // Lowercase
  value: string;
  name?: string; // Original, if parsed as a full header
}

export interface UnknownHeader {
  kind: string; // Lowercase
  value: string;
  name: string; // Original, if parsed as a full header
  unknown: true;
}

export interface Parameters {
  [name: string]: string;
}
export interface MediaRange {
  type: string;
  subtype: string;
  parameters: Parameters;
  weight: number;
}
export interface Accept extends Header<'accept'> {
  ranges: MediaRange[];
}

export interface Accept_CH extends Header<'accept-ch'> {
  hints: string[];
}

export interface Charset {
  charset: string;
  weight: number;
}
export interface Accept_Charset extends Header<'accept-charset'> {
  charsets: Charset[];
}

export interface Encoding {
  coding: string;
  weight: number;
}
export interface Accept_Encoding extends Header<'accept-encoding'> {
  encodings: Encoding[];
}

export interface Language {
  range: string[];
  weight: number;
}
export interface Accept_Language extends Header<'accept-language'> {
  languages: Language[];
}

export interface Accept_Ranges extends Header<'accept-ranges'> {
  ranges: string[];
}

export interface Access_Control_Allow_Credentials extends Header<'access-control-allow-credentials'> {
  allow: boolean;
}
export interface Access_Control_Allow_Headers extends Header<'access-control-allow-headers'> {
  fields: string[];
}
export interface Access_Control_Allow_Methods extends Header<'access-control-allow-methods'> {
  methods: string[];
}
export interface Access_Control_Allow_Origin extends Header<'access-control_allow-origin'> {
  origin: string;
}
export interface Access_Control_Expose_Headers extends Header<'access-control-expose-headers'> {
  fields: string[];
}
export interface Access_Control_Max_Age extends Header<'access-control-max-age'> {
  age: number;
}
export interface Access_Control_Request_Headers extends Header<'access-control-request-headers'> {
  fields: string[];
}
export interface Access_Control_Request_Method extends Header<'access-control-request-method'> {
  method: string;
}

export interface Age extends Header<'age'> {
  secs: number;
}

export interface Allow extends Header<'allow'> {
  methods: string[];
}

export interface ALPN extends Header<'alpn'> {
  protocols: string[];
}

export interface Service {
  protocol: string;
  authority: string;
  parameters: Parameters;
}
export interface Alt_Svc extends Header<'alt-svc'> {
  services?: Service[];
  clear?: true;
}

export interface AuthParam {
  name: string;
  value: string;
}
export interface Authentication_Info extends Header<'authentication-info'> {
  params: AuthParam[];
}

export interface Authorization extends Header<'authorization'> {
  scheme: string;
  params?: AuthParam[];
  token68?: string;
}

export type CacheDirective = [
  name: string,
  value: string | string[] | number | null,
];
export interface Cache_Control extends Header<'cache-control'> {
  controls: CacheDirective[];
}

export interface Connection extends Header<'connection'> {
  opts: string[];
}

export interface LanguageTag {
  language: string | null;
  script: string | null;
  region: string | null;
  variant: string[];
  extension: string[];
  privateuse: string | null;
}
export interface Content_Language extends Header<'content-language'> {
  tags: LanguageTag[];
}

export interface Content_Length extends Header<'content-length'> {
  length: number;
}

export interface Content_Location extends Header<'content-location'> {
  uri: string;
  absolute: boolean;
}

export interface Content_Range extends Header<'content-range'> {
  units: string;
  complete: number; // NaN if unknown
  first?: number;
  last?: number;
  unsatisfied?: boolean; // True if no first/last
}

export interface CSPValue {
  kind: 'scheme' | 'keyword' | 'nonce' | 'hash' | 'host' | 'token' | 'unknown';
  value: string;
}
export interface CSPDirective {
  name: string;
  values: CSPValue[];
  unknown?: true;
}
export interface Content_Security_Policy extends Header<'content-security-policy'> {
  directives: CSPDirective[];
}

export interface Content_Security_Policy_Report_Only extends Header<'content-security-policy-report-only'> {
  directives: CSPDirective[];
}

export interface Content_Type extends Header<'content-type'> {
  type: string;
  subtype: string;
  parameters: Parameters;
}

export interface CoopPolicyItem {
  item: string;
  params?: {
    [name: string]: string;
  };
}
export interface Cross_Origin_Embedder_Policy extends Header<'cross-origin-embedder-policy'> {
  policy: CoopPolicyItem;
}
export interface Cross_Origin_Embedder_Policy_Report_Only extends Header<'cross-origin-embedder-policy-report-only'> {
  policy: CoopPolicyItem;
}
export interface Cross_Origin_Opener_Policy extends Header<'cross-origin-opener-policy'> {
  policy: CoopPolicyItem;
}
export interface Cross_Origin_Opener_Policy_Report_Only extends Header<'cross-origin-opener-policy-report-only'> {
  policy: CoopPolicyItem;
}

export interface Cross_Origin_Resource_Policy extends Header<'cross-origin-resource-policy'> {
  policy: string;
}

export interface Date extends Header<'date'> {
  date: Date;
}

export interface ETag extends Header<'etag'> {
  etag: string;
}

export interface Expectation {
  token: string; // Mostly 100-continue
  value?: string; // Not used yet to my knowledge
  parameters?: Parameters; // Not used yet to my knowledge
}
export interface Expect extends Header<'expect'> {
  expectations: Expectation[];
}

export interface Expires extends Header<'expires'> {
  date: Date;
}

export interface From extends Header<'from'> {
  address: string;
}

export interface Host extends Header<'host'> {
  host: string;
  port: number | null;
}

export interface If_Match extends Header<'if-match'> {
  etags: string[];
}

export interface If_Modified_Since extends Header<'if-modified-since'> {
  date: Date;
}

export interface If_None_Match extends Header<'if-none-match'> {
  etags: string[];
}

export interface If_Range extends Header<'if-range'> {
  etag?: string;
  date?: Date;
}

export interface If_Unmodified_Since extends Header<'if-unmodified-since'> {
  date: Date;
}

export interface Last_Modified extends Header<'last-modified'> {
  date: Date;
}

export interface LinkValue {
  uri: URL;
  params: {
    [name: string]: string;
  };
}
export interface Link extends Header<'link'> {
  links: LinkValue[];
}

export interface Location extends Header<'location'> {
  uri: string;
}

export interface Max_Forwards extends Header<'max-forwards'> {
  max: number;
}

export interface NEL extends Header<'nel'> {
  json: unknown[];
}

export interface PermissionsPolicyItem {
  item?: string;
  params?: {
    [name: string]: string;
  };
}
export interface PermissionsPolicyItems {
  items: PermissionsPolicyItem[];
  params?: {
    [name: string]: string;
  };
}
export interface Permissions_Policy extends Header<'permissions-policy'> {
  directives: [name: string, items: PermissionsPolicyItems][];
}

export interface Challenge {
  scheme: string;
  params?: AuthParam[];
  token68?: string;
}
export interface Proxy_Authenticate extends Header<'proxy-authenticate'> {
  challenges: Challenge[];
}

export interface Proxy_Authentication_Info extends Header<'proxy-authentication-info'> {
  params: AuthParam[];
}

export interface Proxy_Authorization extends Header<'proxy-authorization'> {
  scheme: string;
  params?: AuthParam[];
  token68?: string;
}

export interface RangeSpec {
  first?: number | null;
  last?: number | null;
  other?: string;
}

export interface Range extends Header<'range'> {
  units: string;
  ranges: RangeSpec[];
}

export interface Referer extends Header<'referer'> {
  uri: string;
  absolute: boolean;
}

export interface Referrer_Policy extends Header<'referer-policy'> {
  tokens: string[];
}

export interface Reporting_Endpoints extends Header<'reporting-endpoints'> {
  endpoints: [name: string, uri: string][];
}

export interface Retry_After extends Header<'retry-after'> {
  date?: Date;
  seconds?: number;
}

export interface Product {
  product: string;
  version: string;
}
export interface Comment {
  comment: string;
}
export interface Server extends Header<'server'> {
  products: (Product | Comment)[];
}

export interface TimingMetric {
  metric: string;
  params: {
    [name: string]: string;
  };
}
export interface Server_Timing extends Header<'server-timing'> {
  metrics: TimingMetric[];
}

export type CookieAttribute = [
  name: string,
  value: string | number | Date | null,
];
export interface Set_Cookie extends Header<'set-cookie'> {
  cookieName: string;
  cookieValue: string;
  attributes: CookieAttribute[];
}

export type STSDirective = [
  name: string,
  value: string | number | null,
];
export interface Strict_Transport_Security extends Header<'strict-transport-security'> {
  directives: STSDirective[];
}

export interface TransferEncoding {
  encoding: string;
  parameters: Parameters;
  weight: number;
}
export interface TE extends Header<'te'> {
  trailers: boolean;
  codings: TransferEncoding[];
}

export interface Trailer extends Header<'trailer'> {
  fields: string[];
}

export interface Protocol {
  name: string;
  version: string | null;
}
export interface Upgrade extends Header<'upgrade'> {
  protocols: Protocol[];
}

export interface User_Agent extends Header<'user-agent'> {
  products: (Product | Comment)[];
}

export interface Vary extends Header<'vary'> {
  fields: string[];
}

export interface Path {
  protocol: string | null;
  version: string;
  name: string;
  port: number | null;
}
export interface Via extends Header<'via'> {
  path: Path[];
}

export interface WWW_Authenticate extends Header<'www-authenticate'> {
  challenges: Challenge[];
}

export type AnyHeader
  = Accept
  | Accept_CH
  | Accept_Charset
  | Accept_Encoding
  | Accept_Language
  | Accept_Ranges
  | Access_Control_Allow_Credentials
  | Access_Control_Allow_Headers
  | Access_Control_Allow_Methods
  | Access_Control_Allow_Origin
  | Access_Control_Expose_Headers
  | Access_Control_Max_Age
  | Access_Control_Request_Headers
  | Access_Control_Request_Method
  | Age
  | Allow
  | ALPN
  | Alt_Svc
  | Authentication_Info
  | Authorization
  | Cache_Control
  | Connection
  | Content_Encoding
  | Content_Language
  | Content_Length
  | Content_Location
  | Content_Range
  | Content_Security_Policy
  | Content_Security_Policy_Report_Only
  | Content_Type
  | Cross_Origin_Embedder_Policy
  | Cross_Origin_Embedder_Policy_Report_Only
  | Cross_Origin_Opener_Policy
  | Cross_Origin_Opener_Policy_Report_Only
  | Cross_Origin_Resource_Policy
  | Date
  | ETag
  | Expect
  | Expires
  | From
  | Host
  | If_Match
  | If_Modified_Since
  | If_None_Match
  | If_Range
  | If_Unmodified_Since
  | Last_Modified
  | Link
  | Location
  | Max_Forwards
  | NEL
  | Permissions_Policy
  | Proxy_Authenticate
  | Proxy_Authentication_Info
  | Proxy_Authorization
  | Range
  | Referer
  | Referrer_Policy
  | Reporting_Endpoints
  | Retry_After
  | Server
  | Server_Timing
  | Set_Cookie
  | Strict_Transport_Security
  | TE
  | Trailer
  | Upgrade
  | User_Agent
  | Vary
  | Via
  | WWW_Authenticate
  | UnknownHeader;

export type Headers = AnyHeader[];
