Headers
  = (Header CRLF)+ CRLF

Headers_Loose
  = (Header CR? LF)+ CR? LF

Header
  = "Accept"i COWS Accept
  / "Accept-CH"i COWS Accept_CH
  / "Accept-Charset"i COWS Accept_Charset
  / "Accept-Encoding"i COWS Accept_Encoding
  / "Accept-Language"i COWS Accept_Language
  / "Accept-Ranges"i COWS Accept_Ranges
  / "Age"i COWS Age
  / "Allow"i COWS Allow
  / "ALPN"i COWS ALPN
  / "Alt-Svc"i COWS Alt_Svc
  / "Authentication-Info"i COWS Authentication_Info
  / "Authorization"i COWS Authorization
  / "Cache-Control"i COWS Cache_Control
  / "Connection"i COWS Connection
  / "Content-Encoding"i COWS Content_Encoding
  / "Content-Language"i COWS Content_Language
  / "Content-Length"i COWS Content_Length
  / "Content-Location"i COWS Content_Location
  / "Content-Range"i COWS Content_Range
  / "Content-Security-Policy"i COWS Content_Security_Policy
  / "Content-Security-Policy-Report-Only"i COWS Content_Security_Policy_Report_Only
  / "Content-Type"i COWS Content_Type
  / "Date"i COWS Date
  / "ETag"i COWS ETag
  / "Expect"i COWS Expect
  / "Expires"i COWS Expires
  / "From"i COWS From
  / "Host"i COWS Host
  / "If-Match"i COWS If_Match
  / "If-Modified-Since"i COWS If_Modified_Since
  / "If-None-Match"i COWS If_None_Match
  / "If-Range"i COWS If_Range
  / "If-Unmodified-Since"i COWS If_Unmodified_Since
  / "IMF-fixdate"i COWS IMF_fixdate
  / "Last-Modified"i COWS Last_Modified
  / "Location"i COWS Location
  / "Max-Forwards"i COWS Max_Forwards
  / "NEL"i COWS NEL
  / "Permissions-Policy"i COWS Permissions_Policy
  / "Proxy-Authenticate"i COWS Proxy_Authenticate
  / "Proxy-Authentication-Info"i COWS Proxy_Authentication_Info
  / "Proxy-Authorization"i COWS Proxy_Authorization
  / "Range"i COWS Range
  / "Referer"i COWS Referer
  / "Referrer-Policy"i COWS Referrer_Policy
  / "Retry-After"i COWS Retry_After
  / "Server-Timing"i COWS Server_Timing
  / "Server"i COWS Server
  / "Set-Cookie"i COWS set_cookie_string
  / "Strict-Transport-Security"i COWS Strict_Transport_Security
  / "TE"i COWS TE
  / "Trailer"i COWS Trailer
  / "Upgrade"i COWS Upgrade
  / "User-Agent"i COWS User_Agent
  / "Vary"i COWS Vary
  / "Via"i COWS Via
  / "WWW-Authenticate"i COWS WWW_Authenticate
  / Unknown_Header

CRLF
  = CR LF

CR
  = "\r"

LF
  = "\n"

COWS
  = ":" OWS

Accept
  = ((media_range weight?) (OWS "," OWS (media_range weight?))*)?

Accept_CH
  = sf_list

Accept_Charset
  = (((token / "*") weight?) (OWS "," OWS ((token / "*") weight?))*)?

Accept_Encoding
  = ((codings weight?) (OWS "," OWS (codings weight?))*)?

Accept_Language
  = ((language_range weight?) (OWS "," OWS (language_range weight?))*)?

Accept_Ranges
  = acceptable_ranges

Age
  = delta_seconds

Allow
  = (method (OWS "," OWS method)*)?

ALPN
  = @count:(some:(protocol_id?)|.., [ \t]* "," [ \t]*| {return some.filter(s => s)}) &{ return (count.length >= 1) }

Alt_Svc
  = clear
  / @count:(some:(alt_value?)|.., [ \t]* "," [ \t]*| {return some.filter(s => s)}) &{ return (count.length >= 1) }

Authentication_Info
  = (auth_param (OWS "," OWS auth_param)*)?

Authorization
  = credentials

Cache_Control
  = some:(cache_directive?)|.., [ \t]* "," [ \t]*| {return some.filter(s => s)}

Connection
  = (connection_option (OWS "," OWS connection_option)*)?

Content_Encoding
  = (content_coding (OWS "," OWS content_coding)*)?

Content_Language
  = (language_tag (OWS "," OWS language_tag)*)?

Content_Length
  = DIGIT+

Content_Location
  = absolute_URI
  / partial_URI

Content_Range
  = range_unit SP (range_resp / unsatisfied_range)

Content_Security_Policy
  = @count:(some:(serialized_policy?)|.., [ \t]* "," [ \t]*| {return some.filter(s => s)}) &{ return (count.length >= 1) }

Content_Security_Policy_Report_Only
  = @count:(some:(serialized_policy?)|.., [ \t]* "," [ \t]*| {return some.filter(s => s)}) &{ return (count.length >= 1) }

Content_Type
  = media_type

Date
  = HTTP_date

ETag
  = entity_tag

Expect
  = (expectation (OWS "," OWS expectation)*)?

Expires
  = HTTP_date

From
  = mailbox

Host
  = uri_host (":" port)?

If_Match
  = "*"
  / (entity_tag (OWS "," OWS entity_tag)*)?

If_Modified_Since
  = HTTP_date

If_None_Match
  = "*"
  / (entity_tag (OWS "," OWS entity_tag)*)?

If_Range
  = entity_tag
  / HTTP_date

If_Unmodified_Since
  = HTTP_date

IMF_fixdate
  = day_name "," SP date1 SP time_of_day SP GMT

Last_Modified
  = HTTP_date

Location
  = URI_reference

Max_Forwards
  = DIGIT+

NEL
  = json_field_value

Permissions_Policy
  = sf_dictionary

Proxy_Authenticate
  = (challenge (OWS "," OWS challenge)*)?

Proxy_Authentication_Info
  = (auth_param (OWS "," OWS auth_param)*)?

Proxy_Authorization
  = credentials

Range
  = ranges_specifier

Referer
  = absolute_URI
  / partial_URI

Referrer_Policy
  = @count:(some:(policy_token?)|.., [ \t]* "," [ \t]*| {return some.filter(s => s)}) &{ return (count.length >= 1) }

Retry_After
  = HTTP_date
  / delay_seconds

Server_Timing
  = some:(server_timing_metric?)|.., [ \t]* "," [ \t]*| {return some.filter(s => s)}

Server
  = product (RWS (product / comment))*

set_cookie_string
  = cookie_pair (";" SP cookie_av)*

Strict_Transport_Security
  = directive? (";" directive?)*

TE
  = (t_codings (OWS "," OWS t_codings)*)?

Trailer
  = (field_name (OWS "," OWS field_name)*)?

Upgrade
  = (protocol (OWS "," OWS protocol)*)?

User_Agent
  = product (RWS (product / comment))*

Vary
  = (("*" / field_name) (OWS "," OWS ("*" / field_name))*)?

Via
  = ((received_protocol RWS received_by (RWS comment)?) (OWS "," OWS (received_protocol RWS received_by (RWS comment)?))*)?

WWW_Authenticate
  = (challenge (OWS "," OWS challenge)*)?

Unknown_Header
  = field_name COWS field_content

OWS
  = (SP / HTAB)*

media_range
  = ("*/*" / (type "/*") / (type "/" subtype)) parameters

weight
  = OWS ";" OWS "q="i qvalue

sf_list
  = list_member (OWS "," OWS list_member)*

token
  = tchar+

codings
  = content_coding
  / "identity"i
  / "*"

language_range
  = (ALPHA|1..8| ("-" alphanum|1..8|)*)
  / "*"

acceptable_ranges
  = range_unit (OWS "," OWS range_unit)*

delta_seconds
  = DIGIT+

method
  = token

protocol_id
  = token

clear
  = "clear"

alt_value
  = alternative (OWS ";" OWS alt_parameter)*

auth_param
  = token BWS "=" BWS (token / quoted_string)

credentials
  = auth_scheme (SP+ (token68 / (auth_param (OWS "," OWS auth_param)*)?))?

cache_directive
  = token ("=" (token / quoted_string))?

connection_option
  = token

content_coding
  = token

language_tag
  = langtag
  / privateuse
  / grandfathered

DIGIT
  = [\x30-\x39]

absolute_URI
  = scheme ":" hier_part ("?" query)?

partial_URI
  = relative_part ("?" query)?

range_unit
  = token

SP
  = " "

range_resp
  = incl_range "/" (complete_length / "*")

unsatisfied_range
  = "*/" complete_length

serialized_policy
  = serialized_directive (optional_ascii_whitespace ";" (optional_ascii_whitespace serialized_directive)?)*

media_type
  = type "/" subtype parameters

HTTP_date
  = IMF_fixdate
  / obs_date

entity_tag
  = weak? opaque_tag

expectation
  = token ("=" (token / quoted_string) parameters)?

mailbox
  = name_addr
  / addr_spec

uri_host
  = IP_literal
  / IPv4address
  / reg_name

port
  = DIGIT*

day_name
  = "Mon"
  / "Tue"
  / "Wed"
  / "Thu"
  / "Fri"
  / "Sat"
  / "Sun"

date1
  = day SP month SP year

time_of_day
  = hour ":" minute ":" second

GMT
  = "GMT"

URI_reference
  = URI
  / relative_ref

json_field_value
  = some:(json_field_item?)|.., [ \t]* "," [ \t]*| {return some.filter(s => s)}

sf_dictionary
  = sf_dict_member (OWS "," OWS sf_dict_member)*

challenge
  = auth_scheme (SP+ (token68 / (auth_param (OWS "," OWS auth_param)*)?))?

ranges_specifier
  = range_unit "=" OWS range_set

policy_token
  = "no-referrer"i
  / "no-referrer-when-downgrade"i
  / "strict-origin"i
  / "strict-origin-when-cross-origin"i
  / "same-origin"i
  / "origin"i
  / "origin-when-cross-origin"i
  / "unsafe-url"i

delay_seconds
  = DIGIT+

server_timing_metric
  = metric_name (OWS ";" OWS server_timing_param)*

product
  = token ("/" product_version)?

RWS
  = (SP / HTAB)+

comment
  = "(" (ctext / quoted_pair / comment)* ")"

cookie_pair
  = cookie_name "=" cookie_value

cookie_av
  = expires_av
  / max_age_av
  / domain_av
  / path_av
  / secure_av
  / httponly_av
  / extension_av

directive
  = directive_name ("=" directive_value)?

t_codings
  = "trailers"i
  / (transfer_coding weight?)

field_name
  = token

protocol
  = protocol_name ("/" protocol_version)?

received_protocol
  = (protocol_name "/")? protocol_version

received_by
  = pseudonym (":" port)?

field_content
  = field_vchar ((SP / HTAB / field_vchar)+ field_vchar)?

HTAB
  = "\t"

type
  = token

subtype
  = token

parameters
  = (OWS ";" OWS parameter?)*

qvalue
  = ("0" ("." DIGIT|..3|)?)
  / ("1" ("." "0"|..3|)?)

list_member
  = sf_item
  / sf_inner_list

tchar
  = "!"
  / "#"
  / "$"
  / "%"
  / "&"
  / "'"
  / "*"
  / "+"
  / "-"
  / "."
  / "^"
  / "_"
  / "`"
  / "|"
  / "~"
  / DIGIT
  / ALPHA

ALPHA
  = [\x41-\x5a]
  / [\x61-\x7a]

alphanum
  = ALPHA
  / DIGIT

alternative
  = protocol_id "=" alt_authority

alt_parameter
  = token "=" (token / quoted_string)

BWS
  = OWS

quoted_string
  = DQUOTE (qdtext / quoted_pair)* DQUOTE

auth_scheme
  = token

token68
  = (ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/")+ "="*

langtag
  = language ("-" script)? ("-" region)? ("-" variant)* ("-" extension)* ("-" privateuse)?

privateuse
  = "x"i ("-" (alphanum|1..8|))+

grandfathered
  = irregular
  / regular

scheme
  = ALPHA (ALPHA / DIGIT / "+" / "-" / ".")*

hier_part
  = "//" authority path_abempty
  / path_absolute
  / path_rootless
  / path_empty

query
  = (pchar / "/" / "?")*

relative_part
  = "//" authority path_abempty
  / path_absolute
  / path_noscheme
  / path_empty

incl_range
  = first_pos "-" last_pos

complete_length
  = DIGIT+

serialized_directive
  = "child-src"i required_ascii_whitespace serialized_source_list
  / "connect-src"i required_ascii_whitespace serialized_source_list
  / "default-src"i required_ascii_whitespace serialized_source_list
  / "font-src"i required_ascii_whitespace serialized_source_list
  / "frame-src"i required_ascii_whitespace serialized_source_list
  / "img-src"i required_ascii_whitespace serialized_source_list
  / "manifest-src"i required_ascii_whitespace serialized_source_list
  / "media-src"i required_ascii_whitespace serialized_source_list
  / "object-src"i required_ascii_whitespace serialized_source_list
  / "script-src"i required_ascii_whitespace serialized_source_list
  / "script-src-attr"i required_ascii_whitespace serialized_source_list
  / "style-src"i required_ascii_whitespace serialized_source_list
  / "style-src-elem"i required_ascii_whitespace serialized_source_list
  / "style-src-attr"i required_ascii_whitespace serialized_source_list
  / "webrtc"i required_ascii_whitespace ("'allow'"i / "'block'"i)
  / "worker-src"i required_ascii_whitespace serialized_source_list
  / "base-uri"i required_ascii_whitespace serialized_source_list
  / "sandbox"i required_ascii_whitespace ("" / token (required_ascii_whitespace token)*)
  / "form-action"i required_ascii_whitespace serialized_source_list
  / "frame-ancestors"i required_ascii_whitespace ancestor_source_list
  / "report-uri"i required_ascii_whitespace URI_reference (required_ascii_whitespace URI_reference)*
  / "report-to"i required_ascii_whitespace token
  / csp_directive_name (required_ascii_whitespace csp_directive_value)?

optional_ascii_whitespace
  = ("\t" / "\n" / "\x0c" / "\r" / " ")*

obs_date
  = rfc850_date
  / asctime_date

weak
  = "W/"

opaque_tag
  = DQUOTE etagc* DQUOTE

name_addr
  = display_name? angle_addr

addr_spec
  = local_part "@" domain

IP_literal
  = "[" (IPv6address / IPvFuture) "]"

IPv4address
  = dec_octet "." dec_octet "." dec_octet "." dec_octet

reg_name
  = (unreserved / pct_encoded / sub_delims)*

day
  = DIGIT|2|

month
  = "Jan"
  / "Feb"
  / "Mar"
  / "Apr"
  / "May"
  / "Jun"
  / "Jul"
  / "Aug"
  / "Sep"
  / "Oct"
  / "Nov"
  / "Dec"

year
  = DIGIT|4|

hour
  = DIGIT|2|

minute
  = DIGIT|2|

second
  = DIGIT|2|

URI
  = scheme ":" hier_part ("?" query)? ("#" fragment)?

relative_ref
  = relative_part ("?" query)? ("#" fragment)?

json_field_item
  = VCHAR+

sf_dict_member
  = sf_member_key (sf_parameters / ("=" sf_member_value))

range_set
  = range_spec (OWS "," OWS range_spec)*

metric_name
  = token

server_timing_param
  = server_timing_param_name OWS "=" OWS server_timing_param_value

product_version
  = token

ctext
  = HTAB
  / SP
  / [\x21-\x27]
  / [\x2a-\x5b]
  / [\x5d-\x7e]
  / obs_text

quoted_pair
  = "\\" (HTAB / SP / VCHAR / obs_text)

cookie_name
  = token

cookie_value
  = cookie_octet*
  / (DQUOTE cookie_octet* DQUOTE)

expires_av
  = "Expires="i sane_cookie_date

max_age_av
  = "Max-Age="i non_zero_digit DIGIT*

domain_av
  = "Domain="i domain_value

path_av
  = "Path="i path_value

secure_av
  = "Secure"i

httponly_av
  = "HttpOnly"i

extension_av
  = . { error(`Can't convert prose description to peggy grammar: "any CHAR except CTLs or ";""`) }

directive_name
  = token

directive_value
  = token
  / quoted_string

transfer_coding
  = token (OWS ";" OWS transfer_parameter)*

protocol_name
  = token

protocol_version
  = token

pseudonym
  = token

field_vchar
  = VCHAR
  / obs_text

parameter
  = parameter_name "=" parameter_value

sf_item
  = sf_bare_item sf_parameters

sf_inner_list
  = "(" SP* (sf_item (SP+ sf_item)* SP*)? ")" sf_parameters

alt_authority
  = quoted_string

DQUOTE
  = "\""

qdtext
  = HTAB
  / SP
  / "!"
  / [\x23-\x5b]
  / [\x5d-\x7e]
  / obs_text

language
  = ALPHA|2..3| ("-" extlang)?
  / ALPHA|4|
  / ALPHA|5..8|

script
  = ALPHA|4|

region
  = ALPHA|2|
  / DIGIT|3|

variant
  = alphanum|5..8|
  / (DIGIT alphanum|3|)

extension
  = singleton ("-" (alphanum|2..8|))+

irregular
  = "en-GB-oed"i
  / "i-ami"i
  / "i-bnn"i
  / "i-default"i
  / "i-enochian"i
  / "i-hak"i
  / "i-klingon"i
  / "i-lux"i
  / "i-mingo"i
  / "i-navajo"i
  / "i-pwn"i
  / "i-tao"i
  / "i-tay"i
  / "i-tsu"i
  / "sgn-BE-FR"i
  / "sgn-BE-NL"i
  / "sgn-CH-DE"i

regular
  = "art-lojban"i
  / "cel-gaulish"i
  / "no-bok"i
  / "no-nyn"i
  / "zh-guoyu"i
  / "zh-hakka"i
  / "zh-min"i
  / "zh-min-nan"i
  / "zh-xiang"i

authority
  = (userinfo "@")? uri_host (":" port)?

path_abempty
  = ("/" segment)*

path_absolute
  = "/" (segment_nz ("/" segment)*)?

path_rootless
  = segment_nz ("/" segment)*

path_empty
  = (. { error(`Can't convert prose description to peggy grammar: "pchar"`) })

pchar
  = unreserved
  / pct_encoded
  / sub_delims
  / ":"
  / "@"

path_noscheme
  = segment_nz_nc ("/" segment)*

first_pos
  = DIGIT+

last_pos
  = DIGIT+

required_ascii_whitespace
  = ("\t" / "\n" / "\x0c" / "\r" / " ")+

serialized_source_list
  = (source_expression (required_ascii_whitespace source_expression)*)
  / "'none'"i

ancestor_source_list
  = (ancestor_source (required_ascii_whitespace ancestor_source)*)
  / "'none'"i

csp_directive_name
  = (ALPHA / DIGIT / "-")+

csp_directive_value
  = (required_ascii_whitespace / ([\x21-\x2b] / [\x2d-\x3a] / [\x3c-\x7e]))*

rfc850_date
  = day_name_l "," SP date2 SP time_of_day SP GMT

asctime_date
  = day_name SP date3 SP time_of_day SP year

etagc
  = "!"
  / [\x23-\x7e]
  / obs_text

display_name
  = phrase

angle_addr
  = CFWS? "<" addr_spec ">" CFWS?
  / obs_angle_addr

local_part
  = dot_atom
  / email_quoted_string
  / obs_local_part

domain
  = dot_atom
  / domain_literal
  / obs_domain

IPv6address
  = (h16 ":")|6| ls32
  / "::" (h16 ":")|5| ls32
  / h16? "::" (h16 ":")|4| ls32
  / ((h16 ":")? h16)? "::" (h16 ":")|3| ls32
  / ((h16 ":")|..2| h16)? "::" (h16 ":")|2| ls32
  / ((h16 ":")|..3| h16)? "::" h16 ":" ls32
  / ((h16 ":")|..4| h16)? "::" ls32
  / ((h16 ":")|..5| h16)? "::" h16
  / ((h16 ":")|..6| h16)? "::"

IPvFuture
  = "v"i HEXDIG+ "." (unreserved / sub_delims / ":")+

dec_octet
  = DIGIT
  / [\x31-\x39] DIGIT
  / "1" DIGIT|2|
  / "2" [\x30-\x34] DIGIT
  / "25" [\x30-\x35]

unreserved
  = ALPHA
  / DIGIT
  / "-"
  / "."
  / "_"
  / "~"

pct_encoded
  = "%" HEXDIG HEXDIG

sub_delims
  = "!"
  / "$"
  / "&"
  / "'"
  / "("
  / ")"
  / "*"
  / "+"
  / ","
  / ";"
  / "="

fragment
  = (pchar / "/" / "?")*

VCHAR
  = [\x21-\x7e]

sf_member_key
  = sf_key

sf_parameters
  = (";" SP* sf_parameter)*

sf_member_value
  = sf_item
  / sf_inner_list

range_spec
  = int_range
  / suffix_range
  / other_range

server_timing_param_name
  = token

server_timing_param_value
  = token
  / quoted_string

obs_text
  = [\x80-\xff]

cookie_octet
  = "!"
  / [\x23-\x2b]
  / [\x2d-\x3a]
  / [\x3c-\x5b]
  / [\x5d-\x7e]

sane_cookie_date
  = HTTP_date

non_zero_digit
  = [\x31-\x39]

domain_value
  = . { error(`Can't convert prose description to peggy grammar: "subdomain"`) }

path_value
  = . { error(`Can't convert prose description to peggy grammar: "any CHAR except CTLs or ";""`) }

transfer_parameter
  = token BWS "=" BWS (token / quoted_string)

parameter_name
  = token

parameter_value
  = (token / quoted_string)

sf_bare_item
  = sf_integer
  / sf_decimal
  / sf_string
  / sf_token
  / sf_binary
  / sf_boolean

extlang
  = ALPHA|3| ("-" ALPHA|3|)|..2|

singleton
  = DIGIT
  / [\x41-\x57]
  / [\x59-\x5a]
  / [\x61-\x77]
  / [\x79-\x7a]

userinfo
  = (unreserved / pct_encoded / sub_delims / ":")*

segment
  = pchar*

segment_nz
  = pchar+

segment_nz_nc
  = (unreserved / pct_encoded / sub_delims / "@")+

source_expression
  = scheme_source
  / host_source
  / keyword_source
  / nonce_source
  / hash_source

ancestor_source
  = scheme_source
  / host_source
  / "'self'"i

day_name_l
  = "Monday"
  / "Tuesday"
  / "Wednesday"
  / "Thursday"
  / "Friday"
  / "Saturday"
  / "Sunday"

date2
  = day "-" month "-" DIGIT|2|

date3
  = month SP (DIGIT|2| / (SP DIGIT))

phrase
  = word+
  / obs_phrase

CFWS
  = ((FWS? email_comment)+ FWS?)
  / FWS

obs_angle_addr
  = CFWS? "<" obs_route addr_spec ">" CFWS?

dot_atom
  = CFWS? dot_atom_text CFWS?

email_quoted_string
  = CFWS? DQUOTE (FWS? qcontent)* FWS? DQUOTE CFWS?

obs_local_part
  = word ("." word)*

domain_literal
  = CFWS? "[" (FWS? dtext)* FWS? "]" CFWS?

obs_domain
  = atom ("." atom)*

h16
  = HEXDIG|1..4|

ls32
  = (h16 ":" h16)
  / IPv4address

HEXDIG
  = DIGIT
  / "A"i
  / "B"i
  / "C"i
  / "D"i
  / "E"i
  / "F"i

sf_key
  = (lcalpha / "*") (lcalpha / DIGIT / "_" / "-" / "." / "*")*

sf_parameter
  = sf_param_key ("=" sf_param_value)?

int_range
  = first_pos "-" last_pos?

suffix_range
  = "-" suffix_length

other_range
  = ([\x21-\x2b] / [\x2d-\x7e])+

sf_integer
  = "-"? DIGIT|1..15|

sf_decimal
  = "-"? DIGIT|1..12| "." DIGIT|1..3|

sf_string
  = DQUOTE sf_chr* DQUOTE

sf_token
  = (ALPHA / "*") (tchar / ":" / "/")*

sf_binary
  = ":" (sf_base64)* ":"

sf_boolean
  = "?" ("0" / "1")

scheme_source
  = scheme_part ":"

host_source
  = (scheme_part "://")? host_part (":" port_part)? path_part?

keyword_source
  = "'self'"i
  / "'unsafe-inline'"i
  / "'unsafe-eval'"i
  / "'strict-dynamic'"i
  / "'unsafe-hashes'"i
  / "'report-sample'"i
  / "'unsafe-allow-redirects'"i
  / "'wasm-unsafe-eval'"i

nonce_source
  = "'nonce-"i base64_value "'"

hash_source
  = "'" hash_algorithm "-" base64_value "'"

word
  = atom
  / email_quoted_string

obs_phrase
  = word (word / "." / CFWS)*

FWS
  = ((WSP* CRLF)? WSP+)
  / obs_FWS

email_comment
  = "(" (FWS? ccontent)* FWS? ")"

obs_route
  = obs_domain_list ":"

dot_atom_text
  = atext+ ("." atext+)*

qcontent
  = qtext
  / email_quoted_pair

dtext
  = [\x21-\x5a]
  / [\x5e-\x7e]
  / obs_dtext

atom
  = CFWS? atext+ CFWS?

lcalpha
  = [\x61-\x7a]

sf_param_key
  = sf_key

sf_param_value
  = sf_bare_item

suffix_length
  = DIGIT+

sf_chr
  = sf_unescaped
  / sf_escaped

sf_base64
  = ALPHA
  / DIGIT
  / "+"
  / "/"
  / "="

scheme_part
  = scheme

host_part
  = "*"
  / "*."? host_char+ ("." host_char+)* "."?

port_part
  = DIGIT+
  / "*"

path_part
  = path_absolute

base64_value
  = (ALPHA / DIGIT / "+" / "/" / "-" / "_")+ ("=")|..2|

hash_algorithm
  = "sha256"i
  / "sha384"i
  / "sha512"i

WSP
  = SP
  / HTAB

obs_FWS
  = WSP+ (CRLF WSP+)*

ccontent
  = email_ctext
  / email_quoted_pair
  / email_comment

obs_domain_list
  = (CFWS / ",")* "@" domain ("," CFWS? ("@" domain)?)*

atext
  = ALPHA
  / DIGIT
  / "!"
  / "#"
  / "$"
  / "%"
  / "&"
  / "'"
  / "*"
  / "+"
  / "-"
  / "/"
  / "="
  / "?"
  / "^"
  / "_"
  / "`"
  / "{"
  / "|"
  / "}"
  / "~"

qtext
  = "!"
  / [\x23-\x5b]
  / [\x5d-\x7e]
  / obs_qtext

email_quoted_pair
  = ("\\" (VCHAR / WSP))
  / obs_qp

obs_dtext
  = obs_NO_WS_CTL
  / email_quoted_pair

sf_unescaped
  = [\x20-\x21]
  / [\x23-\x5b]
  / [\x5d-\x7e]

sf_escaped
  = "\\" (DQUOTE / "\\")

host_char
  = ALPHA
  / DIGIT
  / "-"

email_ctext
  = [\x21-\x27]
  / [\x2a-\x5b]
  / [\x5d-\x7e]
  / obs_ctext

obs_qtext
  = obs_NO_WS_CTL

obs_qp
  = "\\" ("\x00" / obs_NO_WS_CTL / LF / CR)

obs_NO_WS_CTL
  = [\x01-\x08]
  / "\x0B"
  / "\x0c"
  / [\x0e-\x1f]
  / "\x7f"

obs_ctext
  = obs_NO_WS_CTL

