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

export interface Charset {
  charset: string;
  weight: number;
}
export interface Accept_Charset extends Header<'accept_charset'> {
  charsets: Charset[];
}

export interface Encoding {
  coding: string;
  weight: number;
}
export interface Accept_Encoding extends Header<'accept_encoding'> {
  encodings: Encoding[];
}

export interface Language {
  range: string[];
  weight: number;
}
export interface Accept_Language extends Header<'accept_language'> {
  languages: Language[];
}

export interface Accept_Ranges extends Header<'accept_ranges'> {
  ranges: string[];
}

export interface Allow extends Header<'allow'> {
  methods: string[];
}

export interface AuthParam {
  name: string;
  value: string;
}
export interface Authentication_Info extends Header<'authentication_info'> {
  params: AuthParam[];
}

export interface Authorization extends Header<'credentials'> {
  scheme: string;
  params?: AuthParam[];
  token68?: string;
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
export interface Content_Language extends Header<'content_language'> {
  tags: LanguageTag[];
}

export interface Content_Length extends Header<'content_length'> {
  length: number;
}

export interface Content_Location extends Header<'content_location'> {
  uri: string;
}

export interface Content_Range extends Header<'content_range'> {
  units: string;
  complete: number; // NaN if unknown
  first?: number;
  last?: number;
  unsatisfied?: boolean; // True if no first/last
}

export interface Content_Type extends Header<'content_type'> {
  type: string;
  subtype: string;
  parameters: Parameters;
}

export interface Date extends Date<'date'> {
  date: Date;
}

export type AnyHeader
  = Accept
  | Accept_Charset
  | Accept_Encoding
  | Accept_Language
  | Accept_Ranges
  | Allow
  | Authentication_Info
  | Authorization
  | Connection
  | Content_Encoding
  | Content_Language
  | Content_Length
  | Content_Location
  | Content_Range
  | Content_Type
  | Date
  // | ["ETag", ETag]
  // | ["Expect", Expect]
  // | ["From", From]
  // | ["Host", Host]
  // | ["If-Match", If_Match]
  // | ["If-Modified-Since", If_Modified_Since]
  // | ["If-None-Match", If_None_Match]
  // | ["If-Range", If_Range]
  // | ["If-Unmodified-Since", If_Unmodified_Since]
  // | ["Last-Modified", Last_Modified]
  // | ["Location", Location]
  // | ["Max-Forwards", Max_Forwards]
  // | ["Proxy-Authenticate", Proxy_Authenticate]
  // | ["Proxy-Authentication-Info", Proxy_Authentication_Info]
  // | ["Proxy-Authorization", Proxy_Authorization]
  // | ["Range", Range]
  // | ["Referer", Referer]
  // | ["Retry-After", Retry_After]
  // | ["Server", Server]
  // | ["TE", TE]
  // | ["Trailer", Trailer]
  // | ["Upgrade", Upgrade]
  // | ["User-Agent", User_Agent]
  // | ["Vary", Vary]
  // | ["Via", Via]
  // | ["WWW-Authenticate", WWW_Authenticate]
  | UnknownHeader;

export type Headers = AnyHeader[];
