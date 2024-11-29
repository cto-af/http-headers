{{
/**
 * Convert from Base64 to bytes in an unexciting way.
 *
 * @param base64 Base64-encoded string.
 * @returns String decoded into bytes.
 */
function base64ToBytes(base64) {
  const binString = atob(base64);
  return Uint8Array.from(
    binString,
    m => m.codePointAt(0)
  );
}
}}
Headers
  = @(@Header CRLF)+ CRLF

Headers_Loose
  = @(@Header CR? LF)+ CR? LF

Header
  = kn:Known_Header { kn[1].name = kn[0]; return kn[1] }
  / Unknown_Header

Known_Header
  = @"Accept"i COWS @Accept
  / @"Accept-CH"i COWS @Accept_CH
  / @"Age"i COWS @Age
  / @"Accept-Charset"i COWS @Accept_Charset
  / @"Accept-Encoding"i COWS @Accept_Encoding
  / @"Accept-Language"i COWS @Accept_Language
  / @"Accept-Ranges"i COWS @Accept_Ranges
  / @"Allow"i COWS @Allow
  / @"ALPN"i COWS @ALPN
  / @"Alt-Svc"i COWS @Alt_Svc
  / @"Authentication-Info"i COWS @Authentication_Info
  / @"Authorization"i COWS @Authorization
  / @"Cache-Control"i COWS @Cache_Control
  / @"Connection"i COWS @Connection
  / @"Content-Encoding"i COWS @Content_Encoding
  / @"Content-Language"i COWS @Content_Language
  / @"Content-Length"i COWS @Content_Length
  / @"Content-Location"i COWS @Content_Location
  / @"Content-Range"i COWS @Content_Range
  / @"Content-Security-Policy"i COWS @Content_Security_Policy
  / @"Content-Type"i COWS @Content_Type
  / @"Date"i COWS @Date
  / @"ETag"i COWS @ETag
  / @"Expect"i COWS @Expect
  / @"Expires"i COWS @Expires
  / @"From"i COWS @From
  / @"Host"i COWS @Host
  / @"If-Match"i COWS @If_Match
  / @"If-Modified-Since"i COWS @If_Modified_Since
  / @"If-None-Match"i COWS @If_None_Match
  / @"If-Range"i COWS @If_Range
  / @"If-Unmodified-Since"i COWS @If_Unmodified_Since
  / @"Last-Modified"i COWS @Last_Modified
  / @"Location"i COWS @Location
  / @"Max-Forwards"i COWS @Max_Forwards
  / @"NEL"i COWS @NEL
  / @"Permissions-Policy"i COWS @Permissions_Policy
  / @"Proxy-Authentication-Info"i COWS @Proxy_Authentication_Info
  / @"Proxy-Authenticate"i COWS @Proxy_Authenticate
  / @"Proxy-Authorization"i COWS @Proxy_Authorization
  / @"Range"i COWS @Range
  / @"Referer"i COWS @Referer
  / @"Retry-After"i COWS @Retry_After
  / @"Server"i COWS @Server
  / @"TE"i COWS @TE
  / @"Set-Cookie"i COWS @Set_Cookie
  / @"Strict-Transport-Security"i COWS @Strict_Transport_Security
  / @"Trailer"i COWS @Trailer
  / @"Upgrade"i COWS @Upgrade
  / @"User-Agent"i COWS @User_Agent
  / @"Vary"i COWS @Vary
  / @"Via"i COWS @Via
  / @"WWW-Authenticate"i COWS @WWW_Authenticate

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

// See: https://www.rfc-editor.org/rfc/rfc8942.html#section-3.1
// Ignore parameters, inner lists, etc.
Accept_CH
  = hints:sf_list &EOL {
    return {
      kind: 'accept-ch',
      value: text(),
      hints: hints.filter(h => h?.item).map(h => h.item),
    };
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

Content_Security_Policy
  = policies:(some:(serialized_policy?)|.., optional_ascii_whitespace "," optional_ascii_whitespace| {return some.filter(s => s)}) &{ return (policies.length >= 1) } &EOL {
    return {
      kind: 'content-security-policy',
      value: text(),
      directives: policies.filter(p => p).flat(1),
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

// See: https://www.w3.org/TR/network-error-logging/
NEL
  = json:JSON &EOL {
    return {
      kind: 'nel',
      value: text(),
      json,
    };
  }

// See: https://w3c.github.io/webappsec-permissions-policy/#ascii-serialization
Permissions_Policy
  = directives:sf_dictionary &EOL {
    directives = directives.map(
      ([name, items]) => (items?.item != null) ? [name, { items: [items]}] : [name, items ?? {items: []}]
    );
    for (const [name, items] of directives) {
      if (items.items) {
        items.items = items.items.filter(i => typeof i.item === 'string');
      }
    }
    return {
      kind: 'permissions-policy',
      value: text(),
      directives,
    }
  }

sf_list
  = list_member|1.., OWS "," OWS|

list_member
  = sf_item
  / sf_inner_list

sf_dictionary
  = sf_dict_member|1.., OWS "," OWS|

sf_dict_member
  = sf_member_key ("=" @sf_member_value / sf_parameters)

sf_member_key
  = sf_key

sf_parameters
  = params:(";" SP* @sf_parameter)* {
    if (params.length) {
      return {params: Object.fromEntries(params)};
    }
    return null;
  }

sf_member_value
  = sf_inner_list
  / sf_item

sf_item
  = item:sf_bare_item params:sf_parameters {
    return {item, ...params};
  }

sf_bare_item
  = sf_boolean
  / sf_decimal
  / sf_integer
  / sf_string
  / sf_token
  / sf_binary

sf_integer
  = num:$("-"? DIGIT|1..15|) { return parseInt(num, 10) }

sf_decimal
  = num:$("-"? DIGIT|1..12| "." DIGIT|1..3|) { return parseFloat(num) }

sf_string
  = DQUOTE str:sf_chr* DQUOTE { return str.join('') }

sf_token
  = $((ALPHA / "*") (tchar / ":" / "/")*)

sf_binary
  = ":" b64:(txt:$sf_base64* { return {txt}}) ":" &{
    try {
      b64.bin = base64ToBytes(b64.txt)
    } catch (e) {
      return false;
    }
    return true;
  } { return b64.bin }

sf_chr
  = sf_escaped
  / sf_unescaped

sf_unescaped
  = [\x20-\x21]
  / [\x23-\x5b]
  / [\x5d-\x7e]

sf_escaped
  = "\\" @(DQUOTE / "\\" )

sf_base64
  = ALPHA
  / DIGIT
  / "+"
  / "/"
  / "="

sf_boolean
  = "?" @("0" {return false} / "1" { return true} )

sf_inner_list
  = "(" SP* items:(@sf_item|1.., SP+| SP*)? ")" params:sf_parameters {
    const ret = {
      items: items ?? [],
      ...params
    };
    return ret;
  }

sf_key
  = $((lcalpha / "*") (lcalpha / DIGIT / "_" / "-" / "." / "*")*)

sf_parameter
  = sf_param_key ("=" @sf_param_value)?

lcalpha
  = [\x61-\x7a]

sf_param_key
  = sf_key

sf_param_value
  = sf_bare_item

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

// Note:
// - the space is required in the spec but some sites don't always include it.
// - the spec does not allow a trailing semi, but some sites add it.
Set_Cookie
  = pair:cookie_pair attributes:(";" SP? @cookie_av)* ";"? &EOL {
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

serialized_policy
  = @directives:(some:(serialized_directive?)|.., optional_ascii_whitespace ";" optional_ascii_whitespace| { return some.filter(s => s) }) &{return directives.length > 0}

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

uri_host_csp
  = $IP_literal
  / $IPv4address
  / reg_name_csp

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

URI_reference_csp
  // This re-parses, but the first is for conformance with this spec, the
  // second is the loose WHATWG style.
  = u:$URI_csp { return new URL(u) }
  / $relative_ref_csp

JSON
  = json:(txt:$(VCHAR / SP)* {return {txt}}) &{
    // Hack to make sure we only JSON_parse once.
    try {
      json.parsed = JSON.parse(`[${json.txt}]`);
    } catch (_ignored) {
      return false
    }
    return true
  } {
    return json.parsed
  }

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

hier_part_csp
  = (("//" authority_csp path_abempty_csp)
  / path_absolute_csp
  / path_rootless_csp)?

query
  = (pchar / "/" / "?")*

query_csp
  = (pchar_csp / "/" / "?")*

relative_part
  = ("//" authority path_abempty
  / path_absolute
  / path_noscheme)?

relative_part_csp
  = ("//" authority_csp path_abempty_csp
  / path_absolute_csp
  / path_noscheme_csp)?

incl_range
  = @first_pos "-" @last_pos

complete_length
  = num:$DIGIT+ { return parseInt(num, 10) }

serialized_directive
  = name:source_list_directive required_ascii_whitespace list:serialized_source_list {
    return {name: name.toLowerCase(), values: list}
  }
  / webrtc_directive
  / sandbox_directive
  / frame_ancestors_directive
  / report_uri_directive
  / report_to_directive
  / require_trusted_types_directive
  / trusted_types_directive
  / upgrade_insecure_directive
  / name:csp_directive_name value:(required_ascii_whitespace @csp_directive_value)? {
    return {name: name.toLowerCase(), values: value ? [{kind: 'unknown', value}] : [], unknown: true};
  }

// See: https://www.w3.org/TR/upgrade-insecure-requests/#delivery
upgrade_insecure_directive
  = "upgrade-insecure-requests"i {
    return { name: 'upgrade-insecure-requests', values: [] };
  }

// See: https://w3c.github.io/trusted-types/dist/spec/#require-trusted-types-for-csp-directive
require_trusted_types_directive
   = "require-trusted-types-for"i required_ascii_whitespace values:"'script'"|1.., required_ascii_whitespace| {
    return {
      name: 'require-trusted-types-for',
      values: values.filter(v => v).map(value => ({kind: 'keyword', value})),
    };
   }

trusted_types_directive
  = "trusted-types"i required_ascii_whitespace values:serialized_tt_configuration {
    return {
      name: 'trusted-types',
      values
    };
  }

serialized_tt_configuration
  = tt_expression|1.., required_ascii_whitespace|

tt_expression
  = value:tt_keyword { return {kind: 'keyword', value: value.toLowerCase()} }
  / tt_wildcard { return {kind: 'token', value: '*'} }
  / value:tt_policy_name { return {kind: 'token', value} }

tt_policy_name
  = $(ALPHA / DIGIT / "-" / "#" / "=" / "_" / "/" / "@" / "." / "%")+

tt_keyword
  = "'allow-duplicates'"i
  / "'none'"i

tt_wildcard
  = "*"

webrtc_directive
  = "webrtc"i required_ascii_whitespace value:("'allow'"i / "'block'"i) {
    return {name: 'webrtc', values: [{kind: 'keyword', value:value.toLowerCase()}]}
  }

sandbox_directive
  = "sandbox"i required_ascii_whitespace value:(token|0.., required_ascii_whitespace|) {
    return {name: 'sandbox', values: [{kind: 'keyword', value}]};
  }

frame_ancestors_directive
  = "frame-ancestors"i required_ascii_whitespace values:ancestor_source_list {
    return {name: 'frame-ancestors', values }
  }

report_uri_directive
  = "report-uri"i required_ascii_whitespace values:URI_reference_csp|1.., required_ascii_whitespace| {
    return {name: 'report-uri', values: values.map(value => ({kind: 'host', value: value.toString()}))}
  }

report_to_directive
  = "report-to"i required_ascii_whitespace value:token {
    return {name: 'report-to', values: [{kind: 'token', value}] }
  }

source_list_directive
  = "base-uri"i
  / "child-src"i
  / "connect-src"i
  / "default-src"i
  / "font-src"i
  / "form-action"i
  / "frame-src"i
  / "img-src"i
  / "manifest-src"i
  / "media-src"i
  / "object-src"i
  / "script-src-attr"i
  / "script-src"i
  / "style-src-attr"i
  / "style-src-elem"i
  / "style-src"i
  / "worker-src"i

optional_ascii_whitespace
  // = ("\t" / "\n" / "\x0c" / "\r" / " ")*
  = [\f\t ]*

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

reg_name_csp
  = parts:(unreserved / pct_encoded / sub_delims_csp)* { return parts.join('') }

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

URI_csp
  = scheme ":" hier_part_csp ("?" query_csp)? ("#" fragment_csp)?

relative_ref
  = relative_part ("?" query)? ("#" fragment)?

relative_ref_csp
  = relative_part_csp ("?" query_csp)? ("#" fragment_csp)?

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

authority_csp
  = (@userinfo "@")? uri_host_csp (":" port)?

path_abempty
  = ("/" segment)*

path_abempty_csp
  = ("/" segment_csp)*

path_absolute
  = "/" @(segment_nz ("/" @segment)*)?

path_absolute_csp
  = "/" @(segment_nz_csp ("/" @segment_csp)*)?

path_rootless
  = segment_nz ("/" segment)*

path_rootless_csp
  = segment_nz_csp ("/" segment_csp)*

pchar
  = unreserved
  / pct_encoded
  / sub_delims
  / ":"
  / "@"

pchar_csp
  = unreserved
  / pct_encoded
  / sub_delims_csp
  / ":"
  / "@"

path_noscheme
  = segment_nz_nc ("/" segment)*

path_noscheme_csp
  = segment_nz_nc_csp ("/" segment_csp)*

first_pos
  = num:$DIGIT+ { return parseInt(num, 10) }

last_pos
  = num:$DIGIT+ { return parseInt(num, 10) }

csp_directive_name
  = $(ALPHA / DIGIT / "-")+

required_ascii_whitespace
  // Inclulding \r and \n has got to be a mistake, or there's no way
  // to find the end of a CSP
  // = ("\t" / "\n" / "\x0c" / "\r" / " ")+
  = [\f\t ]+

serialized_source_list
  = "'none'"i { return [ {kind: 'keyword', value: "'none'"} ] }
  / source_expression|1.., required_ascii_whitespace|

ancestor_source_list
  = "'none'"i { return [ {kind: 'keyword', value: "'none'"} ] }
  / ancestor_source|1.., required_ascii_whitespace|

csp_directive_value
  = value:$(required_ascii_whitespace / ([\x21-\x2b] / [\x2d-\x3a] / [\x3c-\x7e]))* {
    // Could be ''
    return value || null;
  }

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

sub_delims_csp
  = "!"
  / "$"
  / "&"
  / "'"
  / "("
  / ")"
  / "*"
  / "+"
  / "="
  // Except "," and ";"
  // ","
  // ";"

fragment
  = $(pchar / "/" / "?")*

fragment_csp
  = $(pchar_csp / "/" / "?")*

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

segment_csp
  = $pchar_csp*

segment_nz
  = $pchar+

segment_nz_csp
  = $pchar_csp+

segment_nz_nc
  = char:(unreserved / pct_encoded / sub_delims / "@")+ { return char.join('') }

segment_nz_nc_csp
  = char:(unreserved / pct_encoded / sub_delims_csp / "@")+ { return char.join('') }

source_expression
  = value:scheme_source { return { kind: 'scheme', value } }
  / value:keyword_source { return { kind: 'keyword', value } }
  / value:nonce_source { return { kind: 'nonce', value } }
  / value:hash_source { return { kind: 'hash', value } }
  / value:host_source { return { kind: 'host', value } }

ancestor_source
  = "'self'"i { return {kind: 'keyword', value: 'self'} }
  / value:scheme_source { return { kind: 'scheme', value } }
  / value:host_source { return { kind: 'host', value } }

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

scheme_source
  = @$(scheme_part ":") &(required_ascii_whitespace / ";" / EOL)

host_source
  = $((scheme_part "://")? host_part (":" port_part)? path_part?)

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
  = $("'nonce-"i base64_value "'")

hash_source
  = $("'" hash_algorithm "-" base64_value "'")

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

scheme_part
  = scheme

host_part
  = "*."? (host_char+)|1.., "."| "."?
  / "*"

port_part
  = DIGIT+
  / "*"

path_part
  = path_absolute_csp

base64_value
  = $((ALPHA / DIGIT / "+" / "/" / "-" / "_")+ ("=")|..2|)

hash_algorithm
  = "sha256"i
  / "sha384"i
  / "sha512"i

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

host_char
  = ALPHA
  / DIGIT
  / "-"

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
