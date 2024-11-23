Headers
  = @(@Header CRLF)+ CRLF

Headers_Loose
  = @(@Header CR? LF)+ CR? LF

Header
  = name:"Accept"i COWS h:Accept { h.name = name; return h }
  / name:"Age"i COWS h:Age { h.name = name; return h }
  / name:"Accept-Charset"i COWS h:Accept_Charset { h.name = name; return h }
  / name:"Accept-Encoding"i COWS h:Accept_Encoding { h.name = name; return h }
  / name:"Accept-Language"i COWS h:Accept_Language { h.name = name; return h }
  / name:"Accept-Ranges"i COWS h:Accept_Ranges { h.name = name; return h }
  / name:"Allow"i COWS h:Allow { h.name = name; return h }
  / name:"ALPN"i COWS h:ALPN { h.name = name; return h }
  / name:"Alt-Svc"i COWS h:Alt_Svc { h.name = name; return h }
  / name:"Authentication-Info"i COWS h:Authentication_Info { h.name = name; return h }
  / name:"Authorization"i COWS h:Authorization { h.name = name; return h }
  / name:"Cache-Control"i COWS h:Cache_Control { h.name = name; return h }
  / name:"Connection"i COWS h:Connection { h.name = name; return h }
  / name:"Content-Encoding"i COWS h:Content_Encoding { h.name = name; return h }
  / name:"Content-Language"i COWS h:Content_Language { h.name = name; return h }
  / name:"Content-Length"i COWS h:Content_Length { h.name = name; return h }
  / name:"Content-Location"i COWS h:Content_Location { h.name = name; return h }
  / name:"Content-Range"i COWS h:Content_Range { h.name = name; return h }
  / name:"Content-Type"i COWS h:Content_Type { h.name = name; return h }
  / name:"Date"i COWS h:Date { h.name = name; return h }
  / name:"ETag"i COWS h:ETag { h.name = name; return h }
  / name:"Expect"i COWS h:Expect { h.name = name; return h }
  / name:"Expires"i COWS h:Expires { h.name = name; return h }
  / name:"From"i COWS h:From { h.name = name; return h }
  / name:"Host"i COWS h:Host { h.name = name; return h }
  / name:"If-Match"i COWS h:If_Match { h.name = name; return h }
  / name:"If-Modified-Since"i COWS h:If_Modified_Since { h.name = name; return h }
  / name:"If-None-Match"i COWS h:If_None_Match { h.name = name; return h }
  / name:"If-Range"i COWS h:If_Range { h.name = name; return h }
  / name:"If-Unmodified-Since"i COWS h:If_Unmodified_Since { h.name = name; return h }
  / name:"Last-Modified"i COWS h:Last_Modified { h.name = name; return h }
  / name:"Location"i COWS h:Location { h.name = name; return h }
  / name:"Max-Forwards"i COWS h:Max_Forwards { h.name = name; return h }
  / name:"Proxy-Authenticate"i COWS h:Proxy_Authenticate { h.name = name; return h }
  / name:"Proxy-Authentication-Info"i COWS h:Proxy_Authentication_Info { h.name = name; return h }
  / name:"Proxy-Authorization"i COWS h:Proxy_Authorization { h.name = name; return h }
  / name:"Range"i COWS h:Range { h.name = name; return h }
  / name:"Referer"i COWS h:Referer { h.name = name; return h }
  / name:"Retry-After"i COWS h:Retry_After { h.name = name; return h }
  / name:"Server"i COWS h:Server { h.name = name; return h }
  / name:"TE"i COWS h:TE { h.name = name; return h }
  / name:"Set-Cookie"i COWS h:Set_Cookie { h.name = name; return h }
  / name:"Strict-Transport-Security"i COWS h:Strict_Transport_Security { h.name = name; return h }
  / name:"Trailer"i COWS h:Trailer { h.name = name; return h }
  / name:"Upgrade"i COWS h:Upgrade { h.name = name; return h }
  / name:"User-Agent"i COWS h:User_Agent { h.name = name; return h }
  / name:"Vary"i COWS h:Vary { h.name = name; return h }
  / name:"Via"i COWS h:Via { h.name = name; return h }
  / name:"WWW-Authenticate"i COWS h:WWW_Authenticate { h.name = name; return h }
  / Unknown_Header

Unknown_Header
  = name:field_name COWS value:field_content &EOL {
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
field_content
  = c:$(field_vchar ( SP / HTAB / field_vchar )*) {
    return c.trim();
  }

field_vchar
  = VCHAR
  / obs_text

COWS = ":" OWS

OWS
  = (SP / HTAB)*

// From 9110, s5.6.1.2
// #element => [ element ] *( OWS "," OWS [ element ] )

//  Accept = #( media-range [ weight ] )
Accept
  = ranges:(media_range?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'accept',
      value: text(),
      ranges: ranges.filter(r => r),
    }
  }

//  Accept-Charset = #( ( token / "*" ) [ weight ] )
Accept_Charset
  = charsets:((charset:("*" / token) weight:weight? {
    return {
      charset,
      weight: weight ?? 1,
    };
  })?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'accept-charset',
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
  })?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'accept-encoding',
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
  })?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'accept-language',
      value: text(),
      languages: languages.filter(l => l),
    }
  }

Accept_Ranges
  = ranges:acceptable_ranges &EOL {
    return {
      kind: 'accept-ranges',
      value: text(),
      ranges,
    };
  }

// Allow = #method
Allow
  = methods:(method?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'allow',
      value: text(),
      methods: methods.filter(m => m),
    };
  }

ALPN
  = protocols:(some:(aprotocol_id?)|.., OWS "," OWS| {return some.filter(s => s)}) &EOL &{ return (protocols.length >= 1) } {
    return {
      kind: 'alpn',
      value: text(),
      protocols,
    }
  }

Age
  = secs:delta_seconds &EOL {
    return {
      kind: 'age',
      value: text(),
      secs,
    };
  }

Alt_Svc
  = clear &EOL {
    return {
      kind: 'alt-svc',
      value: text(),
      clear: true,
    }
  }
  / services:(some:(alt_value?)|.., OWS "," OWS| {return some.filter(s => s)}) &{
    return (services.length >= 1)
  } &EOL {
    return {
      kind: 'alt-svc',
      value: text(),
      services,
    }
  }

// Authentication-Info = #auth-param
Authentication_Info
  = params:(auth_param?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'authentication-info',
      value: text(),
      params: params.filter(p => p),
    }
  }

Authorization
  = credentials:credentials &EOL {
    return {
      kind: 'authorization',
      value: text(),
      ...credentials,
    }
  }

Cache_Control
  = some:(cache_directive?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'cache-control',
      value: text(),
      controls: some.filter(s => s)
    }
  }

// Connection = #connection-option
Connection
  = opts:(connection_option?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'connection',
      value: text(),
      opts: opts.filter(o => o),
    }
  }

//  Content-Encoding = #content-coding
Content_Encoding
  = codings:(content_coding?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'content-encoding',
      value: text(),
      encodings: codings.filter(c => c),
    };
  }

// Content-Language = #language-tag
Content_Language
  = tags:(language_tag?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'content-language',
      value: text(),
      tags: tags.filter(t => t),
    };
  }

Content_Length
  = num:$DIGIT+ &EOL {
      return {
        kind: 'content-length',
        value: text(),
        length: parseInt(num, 10),
      };
    }

Content_Location
  = absolute:(absolute_URI { return true } / partial_URI { return options.failContentLocation ? peg$FAILED : false }) &EOL {
      const value = text();
      return {
        kind: 'content-location',
        value,
        uri: value,
        absolute,
      };
    }

Content_Range
  = units:range_unit SP range:(range_resp / unsatisfied_range) &EOL {
    return {
      kind: 'content-range',
      value: text(),
      units,
      ...range,
    }
  }

Content_Type
  = mt:media_type {
    return {
      kind: 'content-type',
      value: text(),
      ...mt,
    }
  }

Date
  = date:HTTP_date &EOL {
    return {
      kind: 'date',
      value: text(),
      date,
    }
  }

ETag
  = etag:entity_tag &EOL {
    return {
      kind: 'etag',
      value: text(),
      etag,
    };
  }

// Expect = #expectation
Expect
  = expectations:(expectation?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'expect',
      value: text(),
      expectations: expectations.filter(e => e),
    };
  }

Expires
  = date:HTTP_date &EOL {
    return {
      kind: 'expires',
      value: text(),
      date,
    }
  }

From
  = address:mailbox &EOL {
    return {
      kind: 'from',
      value: text(),
      address,
    };
  }

Host
  = host:uri_host port:(":" @port)? &EOL {
    return {
      kind: 'host',
      value: text(),
      host,
      port,
    };
  }

//  If-Match = "*" / #entity-tag
If_Match
  = etags:(etags_star / etags_list) &EOL {
    return {
      kind: 'if-match',
      value: text(),
      etags: etags.filter(e => e),
    };
  }

etags_star
  = "*" { return ['*'] }

etags_list
  = (entity_tag?)|.., OWS "," OWS|

If_Modified_Since
  = date:HTTP_date &EOL {
    return {
      kind: 'if-modified-since',
      value: text(),
      date,
    }
  }

// If-None-Match = "*" / #entity-tag
If_None_Match
  = etags:(etags_star / etags_list) &EOL {
    return {
      kind: 'if-none-match',
      value: text(),
      etags: etags.filter(e => e),
    };
  }

If_Range
  = etag:entity_tag &EOL {
    return {
      kind: 'if-range',
      value: text(),
      etag
    }
  }
  / date:HTTP_date &EOL {
    return {
      kind: 'if-range',
      value: text(),
      date,
    };
  }

If_Unmodified_Since
  = date:HTTP_date &EOL {
    return {
      kind: 'if-unmodified-since',
      value: text(),
      date,
    };
  }

IMF_fixdate
  = dt:$(day_name "," SP date1 SP time_of_day SP GMT) {
    return new Date(dt);
  }

Last_Modified
  = date:HTTP_date &EOL {
    return {
      kind: 'last-modified',
      value: text(),
      date,
    };
  }

Location
  = uri:URI_reference &EOL {
    return {
      kind: 'location',
      value: text(),
      uri,
    }
  }

Max_Forwards
  = num:$DIGIT+ &EOL {
    return {
      kind: 'max-forwards',
      value: text(),
      max: parseInt(num, 10)
    }
  }

// Proxy-Authenticate = #challenge
Proxy_Authenticate
  = challenges:(challenge?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'proxy-authenticate',
      value: text(),
      challenges: challenges.filter(c => c),
    }
  }

Proxy_Authentication_Info
  = params:(auth_param?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'proxy-authentication-info',
      value: text(),
      params: params.filter(p => p),
    }
  }

Proxy_Authorization
  = credentials:credentials &EOL {
    return {
      kind: 'proxy-authorization',
      value: text(),
      ...credentials,
    }
  }

Range
  = spec:ranges_specifier &EOL {
    return {
      kind: 'range',
      value: text(),
      ...spec,
    }
  }

Referer
  = absolute:(absolute_URI {return true} / partial_URI {return options.failReferer ? peg$FAILED : false}) &EOL {
    const value = text();
    return {
      kind: 'referer',
      value,
      uri: value,
      absolute,
    };
  }

Retry_After
  = date:HTTP_date &EOL {
    return {
      kind: 'retry-after',
      value: text(),
      date,
    }
  }
  / seconds:delay_seconds &EOL {
    return {
      kind: 'retry-after',
      value: text(),
      seconds,
    }
  }

Server
  = first:product last:(RWS @(product / comment))* &EOL {
    return {
      kind: 'server',
      value: text(),
      products: [first, ...last],
    }
  }

Set_Cookie
  = pair:cookie_pair attributes:(";" SP @cookie_av)* &EOL {
    return {
      kind: 'set-cookie',
      value: text(),
      ...pair,
      attributes,
    }
  }

Strict_Transport_Security
  = directives:(directive?)|.., OWS ";" OWS| &EOL {
    return {
      kind: 'strict-transport-security',
      value: text(),
      directives: directives.filter(d => d),
    };
  }

TE
  = codings:(t_codings?)|.., OWS "," OWS| &EOL {
    const trailers = codings.some(t => t?.trailers);
    return {
      kind: 'te',
      value: text(),
      trailers,
      codings: codings.filter(c => c && !c.trailers),
    };
  }

Trailer
  = fields:(field_name?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'trailer',
      value: text(),
      fields: fields.filter(f => f).map(f => f.toLowerCase()),
    }
  }

Upgrade
  = protocols:(protocol?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'upgrade',
      value: text(),
      protocols: protocols.filter(p => p),
    }
  }

User_Agent
  = first:product last:(RWS @(product / comment))* &EOL {
    return {
      kind: 'user-agent',
      value: text(),
      products: [first, ...last],
    }
  }

Vary
  = fields:(("*" / field_name)?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'vary',
      value: text(),
      fields: fields.filter(f => f).map(f => f.toLowerCase()),
    }
  }

Via
  = via:((proto:received_protocol RWS by:received_by comment:(RWS @comment)? {
    return {...proto, ...by, ...comment}
  })?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'via',
      value: text(),
      path: via.filter(v => v),
    }
  }

WWW_Authenticate
  = challenges:(challenge?)|.., OWS "," OWS| &EOL {
    return {
      kind: 'www-authenticate',
      value: text(),
      challenges: challenges.filter(c => c),
    }
  }

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

token "token"
  = $tchar+

codings
  = "identity"i
  / "*"
  / content_coding

language_range
  = ($ALPHA|1..8|)|1.., "-"|
  / "*" { return ['*']; }

// acceptable-ranges = 1#range-unit
acceptable_ranges
  = @units:(un:(range_unit?)|.., OWS "," OWS| {return un.filter(u => u)}) &{
    return units.length > 0
  }

method
  = token

clear
  = "clear"

alt_value
  = alt:alternative params:(OWS ";" OWS @alt_parameter)* {
    return {
      ...alt,
      parameters: Object.fromEntries(params),
    }
  }

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

cache_directive
  = "max-age"i "=" sec:delta_seconds { return ['max-age', sec] }
  / "no-cache"i fields:("=" @quoted_fields)? {
    return ['no-cache', fields?.filter(f => f) ?? []]
  }
  / "private"i fields:("=" @quoted_fields)? {
    return ['private', fields?.filter(f => f) ?? []]
  }
  / "s-maxage"i "=" sec:delta_seconds { return ['s-maxage', sec] }
  / token:token value:("=" @(token / quoted_string))? {
    return [token.toLowerCase(), value];
  }

quoted_fields
  = DQUOTE @((n:field_name {return n.toLowerCase()})?)|.., OWS "," OWS| DQUOTE

aprotocol_id
  = chars:(pct_encoded / tchar)+ { return chars.join('') }

delta_seconds
  = num:$DIGIT+ {return parseInt(num, 10)}

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

cookie_pair
  = cookieName:cookie_name "=" cookieValue:cookie_value {
    return {cookieName, cookieValue}
  }

cookie_av
  = expires_av
  / max_age_av
  / domain_av
  / path_av
  / secure_av
  / httponly_av
  / equals_av
  / extension_av

cookie_name
  = token

cookie_value
  = DQUOTE @$cookie_octet* DQUOTE
  / $cookie_octet*

expires_av
  = "Expires="i date:sane_cookie_date {
    return ['expires', date]
  }

max_age_av
  = "Max-Age="i n:$(non_zero_digit DIGIT*) {
    return ['max-age', parseInt(n, 10)];
  }

domain_av
  = "Domain="i val:domain_value {
    return ['domain', val];
  }

path_av
  = "Path="i path:$path_value {
    return ['path', path];
  }

secure_av
  = "Secure"i { return ['secure', null] }

httponly_av
  = "HttpOnly"i { return ['httponly', null] }

equals_av
  = name:$cookie_any_equals+ value:("=" @$cookie_any+) {
    return [name.toLowerCase(), value];
  }

extension_av
  = $cookie_any+

// any CHAR except CTLs or ";" (\x3b)
cookie_any
  = [\x20-\x3a\x3c-\x7e\x80-\xff]

// any CHAR except CTLs, ";" (\x3b), or "=" (\x3d)
cookie_any_equals
  =  [\x20-\x3a\x3c\x3e-\x7e\x80-\xff]

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

// (Note that a leading %x2E ("."), if present,
//  is ignored even though that character is not permitted, but a
//  trailing %x2E ("."), if present, will cause the user agent to ignore
//  the attribute.)
domain_value
  = d:$("."? domain) { return d.toLowerCase() }

path_value
  = $cookie_any+

HTTP_date
  = IMF_fixdate
  / obs_date

entity_tag
  = $(weak? opaque_tag)

expectation
  = token:token p:("=" @(token / quoted_string) @parameters)? {
    const res = {
      token: token.toLowerCase(),
    };
    if (p) {
      res.value = p[0];
      res.parameters = Object.fromEntries(p[1]);
    }
    return res;
  }

mailbox
  = name_addr
  / addr_spec

uri_host
  = $IP_literal
  / $IPv4address
  / reg_name

port
  = num:$DIGIT* { return parseInt(num, 10) }

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
  // This re-parses, but the first is for conformance with this spec, the
  // second is the loose WHATWG style.
  = u:$URI { return new URL(u) }
  / $relative_ref

challenge
  = scheme:auth_scheme t:(SP+ @auth_params_or_token68)? {
    return {
      scheme,
      ...t
    }
  }

ranges_specifier
  = units:range_unit "=" OWS ranges:range_set {
    return {units, ranges};
  }

delay_seconds
  = num:$DIGIT+ { return parseInt(num, 10) }

product
  = product:token version:("/" @product_version)? {
    return {product, version}
  }

RWS
  = (SP / HTAB)+

comment
  = "(" c:(ctext / quoted_pair / comment)* ")" {
    let cmt = c.reduce((t, v) => {
      if (t.length && (typeof v === 'string') && (typeof t[t.length - 1] === 'string')) {
        t[t.length - 1] += v;
      } else {
        t.push(v)
      }
      return t;
    }, []);
    if ((cmt.length === 1) && (typeof cmt[0] === 'string')) {
      cmt = cmt[0];
    }
    return { comment: cmt }
  }

directive
  = "max-age"i OWS "=" OWS secs:delta_seconds { return ['max-age', secs] }
  / name:directive_name OWS value:("=" OWS @directive_value)? {
    return [name.toLowerCase(), value]
  }

directive_name
  = token

directive_value
  = token
  / quoted_string

t_codings
  = "trailers"i { return {trailers: true} }
  / coding:transfer_coding {
    const weight = parseFloat(coding.parameters.q ?? '1');
    coding.weight = weight;
    delete coding.parameters.q;
    return coding;
  }

field_name
  = token

protocol
  = name:protocol_name version:("/" @protocol_version)? {
    return {name, version}
  }

received_protocol
  = protocol:(@protocol_name "/")? version:protocol_version {
    return {protocol, version};
  }

received_by
  = name:pseudonym port:(":" @port)? {
    return {name, port}
  }

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

alternative
  = protocol:protocol_id "=" authority:alt_authority {
    return {protocol, authority};
  }

alt_parameter
  = @token "=" @(token / quoted_string)

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
  = $(ALPHA (ALPHA / DIGIT / "+" / "-" / ".")*)

hier_part
  = (("//" authority path_abempty)
  / path_absolute
  / path_rootless)?

query
  = (pchar / "/" / "?")*

relative_part
  = ("//" authority path_abempty
  / path_absolute
  / path_noscheme)?

incl_range
  = @first_pos "-" @last_pos

complete_length
  = num:$DIGIT+ { return parseInt(num, 10) }

obs_date
  = OBS @(rfc850_date / asctime_date)

weak
  = "W/"

opaque_tag
  = DQUOTE etagc* DQUOTE

name_addr
  = display_name? @angle_addr

addr_spec
  = $(local_part "@" domain)

IP_literal
  = "[" (IPv6address / IPvFuture) "]"

IPv4address
  = dec_octet "." dec_octet "." dec_octet "." dec_octet

reg_name
  = parts:(unreserved / pct_encoded / sub_delims)* { return parts.join('') }

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

// range-set = 1#range-spec
range_set
  = @ranges:(rs:(range_spec?)|.., OWS "," OWS| {return rs.filter(r => r)}) &{
    return ranges.length > 0
  }

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
  = encoding:token params:(OWS ";" OWS @transfer_parameter)* {
    return {
      encoding,
      parameters: Object.fromEntries(params),
    }
  }

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
  = $ALPHA|5..8|
  / $ALPHA|4|
  / $(ALPHA|2..3| ("-" extlang)?)

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

// All of these are parseable
// regular
//   = "art-lojban"i
//   / "cel-gaulish"i
//   / "no-bok"i
//   / "no-nyn"i
//   / "zh-guoyu"i
//   / "zh-hakka"i
//   / "zh-min"i
//   / "zh-min-nan"i
//   / "zh-xiang"i

authority
  = (@userinfo "@")? uri_host (":" port)?

path_abempty
  = ("/" segment)*

path_absolute
  = "/" @(segment_nz ("/" @segment)*)?

path_rootless
  = segment_nz ("/" segment)*

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
  = CFWS? "<" @addr_spec ">" CFWS?
  / obs_angle_addr

local_part
  = dot_atom
  / email_quoted_string &"@"
  / obs_local_part

domain
  = obs_domain
  / dot_atom
  / domain_literal

IPv6address
  = (h16 ":")|6| ls32
  / "::" (h16 ":")|5| ls32
  / h16? "::" (h16 ":")|4| ls32
  / h16|..2, ":"| "::" (h16 ":")|3| ls32
  / h16|..3, ":"| "::" (h16 ":")|2| ls32
  / h16|..4, ":"| "::" h16 ":" ls32
  / h16|..5, ":"| "::" ls32
  / h16|..6, ":"| "::" h16
  / h16|..7, ":"| "::"

IPvFuture
  = "v"i HEXDIG+ "." (unreserved / sub_delims / ":")+

dec_octet
  = "25" [\x30-\x35]
  / "2" [\x30-\x34] DIGIT
  / "1" DIGIT|2|
  / [\x31-\x39] DIGIT
  / DIGIT

unreserved
  = ALPHA
  / DIGIT
  / "-"
  / "."
  / "_"
  / "~"

pct_encoded
  = "%" hex:$(HEXDIG HEXDIG) { return String.fromCodePoint(parseInt(hex, 16)) }

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
  = $(pchar / "/" / "?")*

range_spec
  = int_range
  / suffix_range
  / other_range

obs_text
  = OBS @[\x80-\xff]

VCHAR
  = [\x21-\x7e]

transfer_parameter
  = token:token BWS "=" BWS value:(token / quoted_string) {
    return [token.toLowerCase(), value];
  }

parameter_name
  = tok:token { return tok.toLowerCase() }

// Don't do lowerCase here, as case sensitivity depends on the parameter name
parameter_value
  = (token / quoted_string)

extlang
  = ALPHA|3| !ALPHA langextss

langextss = ("-" ALPHA|3| !ALPHA)|..2|

singleton
  = DIGIT
  / [\x41-\x57]
  / [\x59-\x5a]
  / [\x61-\x77]
  / [\x79-\x7a]

userinfo
  = c:(unreserved / pct_encoded / sub_delims / ":")* { return c.join('') }

segment
  = $pchar*

segment_nz
  = $pchar+

segment_nz_nc
  = char:(unreserved / pct_encoded / sub_delims / "@")+ { return char.join('') }

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
  = obs_phrase
  / word+

CFWS
  = ((FWS? email_comment)+ FWS?)
  / FWS

obs_angle_addr
  = OBS CFWS? "<" obs_route @addr_spec ">" CFWS?

dot_atom
  = CFWS? dot_atom_text CFWS?

email_quoted_string
  = CFWS? DQUOTE @$(FWS? @qcontent)* FWS? DQUOTE CFWS?

obs_local_part
  = OBS @word|.., "."|

domain_literal
  = CFWS? "[" (FWS? dtext)* FWS? "]" CFWS?

obs_domain
  = OBS @atom|1.., "."|

h16
  = HEXDIG|1..4|

ls32
  = h16 ":" h16
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
  = first:first_pos "-" last:last_pos? &(OWS "," / EOL) &{ return (last === null) || (first <= last)} {
    return { first, last };
  }

suffix_range
  = "-" last:suffix_length &(OWS "," / EOL) {
    return {first: null, last};
  }

other_range // VCHAR excluding comma
  = other:$([\x21-\x2b] / [\x2d-\x7e])+ {
    return {other};
  }

word
  = atom
  / email_quoted_string

obs_phrase
  = OBS word (word / "." / CFWS)*

FWS
  = ((WSP* CRLF)? WSP+)
  / obs_FWS

email_comment
  = "(" (FWS? ccontent)* FWS? ")"

obs_route
  = obs_domain_list ":"

dot_atom_text
  = $(atext+)|1.., "."|

qcontent
  = qtext
  / email_quoted_pair

dtext
  = [\x21-\x5a]
  / [\x5e-\x7e]
  / obs_dtext

atom
  = CFWS? @$atext+ CFWS?

suffix_length
  = num:$DIGIT+ { return parseInt(num, 10); }

WSP
  = SP
  / HTAB

CRLF
  = CR LF

obs_FWS
  = OBS @$(WSP+)|1.., CRLF|

ccontent
  = email_ctext
  / email_quoted_pair
  / email_comment

obs_domain_list
  = OBS (CFWS / ",")* "@" @domain|1.., "," CFWS? "@"|

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
  = "\\" @(VCHAR / WSP)
  / obs_qp

obs_dtext
  = OBS @(obs_NO_WS_CTL / email_quoted_pair)

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
  = OBS @obs_NO_WS_CTL

obs_qp
  = OBS "\\" @$("\x00" / obs_NO_WS_CTL / LF / CR)

obs_NO_WS_CTL
  = [\x01-\x08]
  / "\x0B"
  / "\x0c"
  / [\x0e-\x1f]
  / "\x7f"

obs_ctext
  = OBS @obs_NO_WS_CTL

EOL
  = [\r\n] / !.

OBS = &{ return Boolean(options.obsolete); }
