Headers
  = @(@Header CRLF)+ CRLF

Headers_Loose
  = @(@Header CR? LF)+ CR? LF

Header
  = name:"Accept"i COWS h:Accept EOL { h.name = name; return h }
  / name:"Accept-Charset"i COWS h:Accept_Charset EOL { h.name = name; return h }
  / name:"Accept-Encoding"i COWS h:Accept_Encoding EOL { h.name = name; return h }
  / name:"Accept-Language"i COWS h:Accept_Language EOL { h.name = name; return h }
  / name:"Accept-Ranges"i COWS h:Accept_Ranges EOL { h.name = name; return h }
  / name:"Allow"i COWS h:Allow EOL { h.name = name; return h }
  / name:"Authentication-Info"i COWS h:Authentication_Info EOL { h.name = name; return h }
  / name:"Authorization"i COWS h:Authorization EOL { h.name = name; return h }
  / name:"Connection"i COWS h:Connection EOL { h.name = name; return h }
  / name:"Content-Encoding"i COWS h:Content_Encoding EOL { h.name = name; return h }
  / name:"Content-Language"i COWS h:Content_Language EOL { h.name = name; return h }
  / name:"Content-Length"i COWS h:Content_Length EOL { h.name = name; return h }
  / name:"Content-Location"i COWS h:Content_Location EOL { h.name = name; return h }
  / name:"Content-Range"i COWS h:Content_Range EOL { h.name = name; return h }
  / name:"Content-Type"i COWS h:Content_Type EOL { h.name = name; return h }
  / name:"Date"i COWS h:Date EOL { h.name = name; return h }
  / name:"ETag"i COWS h:ETag EOL { h.name = name; return h }
  / name:"Expect"i COWS h:Expect EOL { h.name = name; return h }
  / name:"From"i COWS h:From EOL { h.name = name; return h }
  / name:"Host"i COWS h:Host EOL { h.name = name; return h }
  / name:"If-Match"i COWS h:If_Match EOL { h.name = name; return h }
  / name:"If-Modified-Since"i COWS h:If_Modified_Since EOL { h.name = name; return h }
  / name:"If-None-Match"i COWS h:If_None_Match EOL { h.name = name; return h }
  / name:"If-Range"i COWS h:If_Range EOL { h.name = name; return h }
  / name:"If-Unmodified-Since"i COWS h:If_Unmodified_Since EOL { h.name = name; return h }
  / name:"Last-Modified"i COWS h:Last_Modified EOL { h.name = name; return h }
  / name:"Location"i COWS h:Location EOL { h.name = name; return h }
  / name:"Max-Forwards"i COWS h:Max_Forwards EOL { h.name = name; return h }
  / name:"Proxy-Authenticate"i COWS h:Proxy_Authenticate EOL { h.name = name; return h }
  / name:"Proxy-Authentication-Info"i COWS h:Proxy_Authentication_Info EOL { h.name = name; return h }
  / name:"Proxy-Authorization"i COWS h:Proxy_Authorization EOL { h.name = name; return h }
  / name:"Range"i COWS h:Range EOL { h.name = name; return h }
  / name:"Referer"i COWS h:Referer EOL { h.name = name; return h }
  / name:"Retry-After"i COWS h:Retry_After EOL { h.name = name; return h }
  / name:"Server"i COWS h:Server EOL { h.name = name; return h }
  / name:"TE"i COWS h:TE EOL { h.name = name; return h }
  / name:"Trailer"i COWS h:Trailer EOL { h.name = name; return h }
  / name:"Upgrade"i COWS h:Upgrade EOL { h.name = name; return h }
  / name:"User-Agent"i COWS h:User_Agent EOL { h.name = name; return h }
  / name:"Vary"i COWS h:Vary EOL { h.name = name; return h }
  / name:"Via"i COWS h:Via EOL { h.name = name; return h }
  / name:"WWW-Authenticate"i COWS h:WWW_Authenticate EOL { h.name = name; return h }
  / Unknown_Header

Unknown_Header
  = name:field_name COWS value:field_content {
    return {
      kind: name.toLowerCase(),
      name,
      value,
      unknown: true,
    }
  }

// ABNF is wrong. Can't see trailing field-vchar because 1* eats it
// field-content  = field-vchar
//                  [ 1*( SP / HTAB / field-vchar ) field-vchar ]
field_content = c:$(field_vchar ( SP / HTAB / field_vchar )*) {
  return c.trim();
}
field_vchar = VCHAR / obs_text

COWS = ":" OWS

OWS
  = (SP / HTAB)*

// From 9110, s5.6.1.2
// #element => [ element ] *( OWS "," OWS [ element ] )

//  Accept = #( media-range [ weight ] )
Accept
  = ranges:(media_range?)|.., OWS "," OWS| {
    return {
      kind: 'accept',
      value: text(),
      ranges: ranges.filter(r => r),
    }
  }

//  Accept-Charset = #( ( token / "*" ) [ weight ] )
Accept_Charset
  = charsets:((charset:(token / "*") weight:weight? {
    return {
      charset,
      weight: weight ?? 1,
    };
  })?)|.., OWS "," OWS| {
    return {
      kind: 'accept_charset',
      value: text(),
      charsets: charsets.filter(c => c),
    }
  }

// Accept-Encoding  = #( codings [ weight ] )
Accept_Encoding
  = encodings:((coding:codings weight:weight? {
    return {
      coding,
      weight: weight ?? 1,
    }
  })?)|.., OWS "," OWS| {
    return {
      kind: 'accept_encoding',
      value: text(),
      encodings: encodings.filter(e => e),
    }
  }

// Accept-Language = #( language-range [ weight ] )
Accept_Language
  = languages:((range:language_range weight:weight? {
    return {
      range,
      weight: weight ?? 1,
    };
  })?)|.., OWS "," OWS| {
    return {
      kind: 'accept_language',
      value: text(),
      languages: languages.filter(l => l),
    }
  }

Accept_Ranges
  = ranges:acceptable_ranges {
    return {
      kind: 'accept_ranges',
      value: text(),
      ranges,
    };
  }

// Allow = #method
Allow
  = methods:(method?)|.., OWS "," OWS| {
    return {
      kind: 'allow',
      value: text(),
      methods: methods.filter(m => m),
    };
  }

// Authentication-Info = #auth-param
Authentication_Info
  = params:(auth_param?)|.., OWS "," OWS| {
    return {
      kind: 'authentication_info',
      value: text(),
      params: params.filter(p => p),
    }
  }

Authorization
  = credentials:credentials {
    return {
      kind: 'authorization',
      value: text(),
      ...credentials,
    }
  }

// Connection = #connection-option
Connection
  = opts:(connection_option?)|.., OWS "," OWS| {
    return {
      kind: 'connection',
      value: text(),
      opts: opts.filter(o => o),
    }
  }

//  Content-Encoding = #content-coding
Content_Encoding
  = codings:(content_coding?)|.., OWS "," OWS| {
    return {
      kind: 'content_encoding',
      value: text(),
      encodings: codings.filter(c => c),
    };
  }

// Content-Language = #language-tag
Content_Language
  = tags:(language_tag?)|.., OWS "," OWS| {
    return {
      kind: 'content_language',
      value: text(),
      tags: tags.filter(t => t),
    };
  }

Content_Length
  = num:$DIGIT+ {
      return {
        kind: 'content_length',
        value: text(),
        length: parseInt(num, 10),
      };
    }

Content_Location
  = absolute:(absolute_URI { return true } / partial_URI { return false }) {
      const value = text();
      return {
        kind: 'content_location',
        value,
        uri: value,
        absolute,
      };
    }

Content_Range
  = units:range_unit SP range:(range_resp / unsatisfied_range) {
    return {
      kind: 'content_range',
      value: text(),
      units,
      ...range,
    }
  }

Content_Type
  = mt:media_type {
    return {
      kind: 'content_type',
      value: text(),
      ...mt,
    }
  }

Date
  = date:HTTP_date {
    return {
      kind: 'date',
      value: text(),
      date,
    }
  }

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
  = dt:$(day_name "," SP date1 SP time_of_day SP GMT) {
    return new Date(dt);
  }

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
  = challenge |1.., OWS "," OWS|

SP
  = " "

HTAB
  = "\t"

media_range
  = ts:((@"*" "/" @"*")
  / (@type "/" @"*")
  / (@type "/" @subtype)) parms:parameters {
    // Recipients SHOULD process any parameter named "q" as weight, regardless
    // of parameter ordering
    const parameters = Object.fromEntries(parms);
    const weight = parseFloat(parameters.q ?? '1');
    delete parameters.q;
    return {
      type: ts[0],
      subtype: ts[1],
      parameters,
      weight,
    }
  }

weight
  = OWS ";" OWS "q="i @qvalue

token
  = $tchar+

codings
  = content_coding
  / "identity"i
  / "*"

language_range
  = ($ALPHA|1..8|)|1.., "-"|
  / "*" { return ['*']; }

// acceptable-ranges = 1#range-unit
acceptable_ranges
  = units:(range_unit?)|.., OWS "," OWS| {
    const res = units.filter(u => u);
    if (res.length < 1) {
      error('At least one range required');
    }
    return res;
  }

method
  = token

auth_param
  = name:token BWS "=" BWS value:(token / quoted_string) {
    return {
      name,
      value,
    }
  }

credentials
  = scheme:auth_scheme t:(SP+ @auth_params_or_token68)? {
    return {
      scheme,
      ...t
    };
  }

auth_params_or_token68
  = auth_params
  / token68

// Note: the ABNF is wrong.
// Also, having empty params or 0 params can not work.
// credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
auth_params
  = params:auth_param|1.., OWS "," OWS| {
    return {
      params,
    };
  }

connection_option
  = token

content_coding
  = token

language_tag
  // These aren't valid langtags, but prefixes might match, so they have to
  // come first.
  = language:irregular {
      return {
        language,
        script: null,
        region: null,
        variant: [],
        extension: [],
        privateuse: null,
      };
    }
  / langtag
  / privateuse:privateuse {
      return {
        language: null,
        script: null,
        region: null,
        variant: [],
        extension: [],
        privateuse,
      };
    }
  // grandfathered: The irregular ones have to come first, and the regular
  // ones are matched by langtag.


DIGIT
  = [\x30-\x39]

absolute_URI
  = scheme ":" hier_part ("?" query)?

partial_URI
  = relative_part ("?" query)?

range_unit
  = token

range_resp
  = incl:incl_range "/" complete:(complete_length / "*" { return NaN }) {
    return {
      first: incl[0],
      last: incl[1],
      complete,
    }
  }

unsatisfied_range
  = "*/" complete:complete_length {
    return {
      complete,
      unsatisfied: true,
    };
  }

media_type
  = type:type "/" subtype:subtype parameters:parameters {
    return {
      type,
      subtype,
      parameters: Object.fromEntries(parameters),
    }
  }

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
  = @hour ":" @minute ":" @second

GMT
  = "GMT"

URI_reference
  = URI
  / relative_ref

challenge
  = auth_scheme (SP+ @((auth_param|1..,OWS "," OWS|)? / token68))?

ranges_specifier
  = @range_unit "=" OWS @range_set

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

type
  = tok:token { return tok.toLowerCase() }

subtype
  = tok:token { return tok.toLowerCase() }

parameters
  = (OWS ";" OWS @parameter?)*

qvalue
  = num:$("0" ("." DIGIT|..3|)?) { return parseFloat(num); }
  / num:$("1" ("." "0"|..3|)?) { return parseFloat(num); }

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

BWS
  = OWS

quoted_string
  = DQUOTE t:(qdtext / quoted_pair)* DQUOTE {
    return t.join('');
  }

auth_scheme
  = token

token68 "base64(e.g.)"
  = value:$((ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/")+ "="*) {
    return {
      token68: value,
    };
  }

langtag
  = language:language script:("-" @script)? region:("-" @region)? variant:("-" @variant)* extension:("-" @extension)* privateuse:("-" @privateuse)? {
    return {
      language,
      script,
      region,
      variant,
      extension,
      privateuse,
    };
  }

privateuse
  = $("x"i ("-" (alphanum|1..8|))+)

// grandfathered
//   = irregular:irregular { return {irregular}; }
//   / regular

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
  = @first_pos "-" @last_pos

complete_length
  = num:$DIGIT+ { return parseInt(num, 10) }

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
  = num:$DIGIT|2| { return parseInt(num, 10) }

month
  = "Jan" { return 0 }
  / "Feb" { return 1 }
  / "Mar" { return 2 }
  / "Apr" { return 3 }
  / "May" { return 4 }
  / "Jun" { return 5 }
  / "Jul" { return 6 }
  / "Aug" { return 7 }
  / "Sep" { return 8 }
  / "Oct" { return 9 }
  / "Nov" { return 10 }
  / "Dec" { return 11 }

year
  = num:$DIGIT|4| { return parseInt(num, 10); }

hour
  = num:$DIGIT|2| { return parseInt(num, 10); }

minute
  = num:$DIGIT|2| { return parseInt(num, 10); }

second
  = num:$DIGIT|2| { return parseInt(num, 10); }

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
  = "\\" @(HTAB / SP / VCHAR / obs_text)

transfer_coding
  = token (OWS ";" OWS transfer_parameter)*

protocol_name
  = token

protocol_version
  = token

pseudonym
  = token

parameter
  = name:parameter_name "=" value:parameter_value {
    // TODO: look through all of
    // https://www.iana.org/assignments/media-type-sub-parameters/media-type-sub-parameters.xhtml
    // to see if there are any other case-insensitive parameters.
    switch (name) {
      case 'charset':
        value = value.toLowerCase();
        break;
    }
    return [name, value];
  }

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
  = $(ALPHA|2..3| ("-" extlang)?)
  / $ALPHA|4|
  / $ALPHA|5..8|

script
  = @$ALPHA|4| !ALPHA

region
  = @$ALPHA|2| !ALPHA
  / $DIGIT|3|

variant
  = $alphanum|5..8|
  / $(DIGIT alphanum|3|)

extension
  = $(singleton ("-" (alphanum|2..8|))+)

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
  = num:$DIGIT+ { return parseInt(num, 10) }

last_pos
  = num:$DIGIT+ { return parseInt(num, 10) }

rfc850_date
  = dt:$(day_name_l "," SP date2 SP time_of_day SP GMT) {
    return new Date(dt);
  }

asctime_date
  = day_name SP d:date3 SP t:time_of_day SP y:year {
    return new Date(Date.UTC(y, d[0], d[1], t[0], t[1], t[2]))
  }

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
  = tok:token { return tok.toLowerCase() }

// Don't do lowerCase here, as case sensitivity depends on the parameter name
parameter_value
  = (token / quoted_string)

extlang
  = ALPHA|3| !ALPHA ("-" ALPHA|3| !ALPHA)|..2|

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
  = month:month SP day:$($DIGIT|2| / (SP @$DIGIT)) {
    return [month, parseInt(day, 10)]
  }

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

CRLF
  = CR LF

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

CR
  = "\r"

LF
  = "\n"

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

EOL
  = [\r\n] / !.
