Headers
  = (Header CRLF)+ CRLF

Headers_Loose
  = (Header CR? LF)+ CR? LF

Header
  = "Accept"i COWS Accept
  / "Accept-Charset"i COWS Accept_Charset
  / "Accept-Encoding"i COWS Accept_Encoding
  / "Accept-Language"i COWS Accept_Language
  / "Accept-Ranges"i COWS Accept_Ranges
  / "Allow"i COWS Allow
  / "Alt-Svc"i COWS Alt_Svc
  / "Authentication-Info"i COWS Authentication_Info
  / "Authorization"i COWS Authorization
  / "Connection"i COWS Connection
  / "Content-Encoding"i COWS Content_Encoding
  / "Content-Language"i COWS Content_Language
  / "Content-Length"i COWS Content_Length
  / "Content-Location"i COWS Content_Location
  / "Content-Range"i COWS Content_Range
  / "Content-Type"i COWS Content_Type
  / "Date"i COWS Date
  / "ETag"i COWS ETag
  / "Expect"i COWS Expect
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
  / "Proxy-Authenticate"i COWS Proxy_Authenticate
  / "Proxy-Authentication-Info"i COWS Proxy_Authentication_Info
  / "Proxy-Authorization"i COWS Proxy_Authorization
  / "Range"i COWS Range
  / "Referer"i COWS Referer
  / "Retry-After"i COWS Retry_After
  / "Server"i COWS Server
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

Accept_Charset
  = (((token / "*") weight?) (OWS "," OWS ((token / "*") weight?))*)?

Accept_Encoding
  = ((codings weight?) (OWS "," OWS (codings weight?))*)?

Accept_Language
  = ((language_range weight?) (OWS "," OWS (language_range weight?))*)?

Accept_Ranges
  = acceptable_ranges

Allow
  = (method (OWS "," OWS method)*)?

Alt_Svc
  = clear
  / @count:(some:(alt_value?)|.., [ \t]* "," [ \t]*| {return some.filter(s => s)}) &{ return (count.length >= 1) }

Authentication_Info
  = (auth_param (OWS "," OWS auth_param)*)?

Authorization
  = credentials

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

Content_Type
  = media_type

Date
  = HTTP_date

ETag
  = entity_tag

Expect
  = (expectation (OWS "," OWS expectation)*)?

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

Retry_After
  = HTTP_date
  / delay_seconds

Server
  = product (RWS (product / comment))*

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

method
  = token

clear
  = "clear"

alt_value
  = alternative (OWS ";" OWS alt_parameter)*

auth_param
  = token BWS "=" BWS (token / quoted_string)

credentials
  = auth_scheme (SP+ (token68 / (auth_param (OWS "," OWS auth_param)*)?))?

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

challenge
  = auth_scheme (SP+ (token68 / (auth_param (OWS "," OWS auth_param)*)?))?

ranges_specifier
  = range_unit "=" OWS range_set

delay_seconds
  = DIGIT+

product
  = token ("/" product_version)?

RWS
  = (SP / HTAB)+

comment
  = "(" (ctext / quoted_pair / comment)* ")"

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

range_set
  = range_spec (OWS "," OWS range_spec)*

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

protocol_id
  = token

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

range_spec
  = int_range
  / suffix_range
  / other_range

obs_text
  = [\x80-\xff]

VCHAR
  = [\x21-\x7e]

transfer_parameter
  = token BWS "=" BWS (token / quoted_string)

parameter_name
  = token

parameter_value
  = (token / quoted_string)

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

int_range
  = first_pos "-" last_pos?

suffix_range
  = "-" suffix_length

other_range
  = ([\x21-\x2b] / [\x2d-\x7e])+

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

suffix_length
  = DIGIT+

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

