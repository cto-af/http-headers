# @cto.af/http-headers

Parse HTTP headers from RFC 9110 (and a bunch of others) using the full ABNF.

If there is a specified and non-deprecated header you want parsed and it is
not yet supported, please file an issue.  I won't be tracking all of the
revisions to all of the docs, but I will fix issues if they are pointed out to
me.

This code was tested against the headers returned by the top 50 websites as
reported by
[wikipedia](https://en.wikipedia.org/wiki/List_of_most-visited_websites) on
the day that I looked in November 2024.  I made sure that all of the
non-custom headers that were in use that day by 3 or more of those sites was
supported here.

## Installation

```sh
npm install @cto.af/http-headers
```

## Caveats

- Check for max headers size *before* calling this parser.  Many servers
  choose 8k or 16k as their maximum.
- Check the `unknown` property of headers.  Headers that are supported, but
  have syntax errors, are treated as if they are unknown, un-parseable
  headers.  They will have always have these properties:
  - kind: lowercased header name
  - name: original header name
  - value: full text of the header, to the first newline
  - unknown: true
- The option `obsolete: true` can be passed in to the parse function to enable
  a bunch of obsolete rules in processing email addresses (and a few other
  `obs_*` productions).  Hopefully none of those productions have never
  actually been used on the web, but I have included them for completeness,
  and left the `obsolete` flag in place mostly for testing purposes.
- I've tried to stay as faithful to the ABNF for each header as possible.
  However, the definitions are rife with different understandings of how ABNF
  works.  In particular, Parser Expression Grammars (PEGs) parse by trying
  each alternate successively until one matches.  If an alternate always
  matches (e.g. *"foo", which matches the empty string), then none of the
  subsequent alternates are ever checked.  Similarly, if one of two alternates
  is the prefix for another (e.g. "foo" and "foobar"), the longer prefix must
  be checked first.  There are several places where look-ahead assertions were
  required to deal with these sorts of issues, or to ensure testability.

## API

Example:

```js
import {parse} from '@cto.af/http-headers';

// By default, the parser is strict about carriage-return/newline pairs.
const headers = parse('Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n\r\n');
// [
//   {
//     kind: 'date',
//     value: 'Sun, 06 Nov 1994 08:49:37 GMT',
//     date: 1994-11-06T08:49:37.000Z,
//     name: 'Date'
//   }
// ]

// Rules named for a header (camel-case, with dashes turned into underscores)
// parse everything after the colon+whitespace for the specified header.
// Use the "startRule" option to select a specific header type.
const contentType = parse('text/html;charset=utf8', {
  startRule: 'Content_Type',
});

// {
//   kind: 'content_type',
//   value: 'text/html;charset=utf8',
//   type: 'text',
//   subtype: 'html',
//   parameters: { charset: 'utf8' }
// }

// Unknown headers, or headers that had invalid values will have 'unknown: true'
// in their parsed version.
const unknownHeader = parse('Foo: bar=baz', {startRule: 'Header'});
// {
//   kind: 'foo',
//   name: 'Foo',
//   value: 'bar=baz',
//   unknown: true
// }
```

See the [Peggy docs](https://peggyjs.org/documentation.html#using-the-parser)
for more information on the `parse` function.

Here are the supported values for `startRule`:

  - 'Headers': default
  - 'Headers_Loose': Accept "\r\n" or "\n" at the end of lines
  - 'Header': Any single header line
  - 'Accept'
  - 'Accept_CH'
  - 'Accept_Charset'
  - 'Accept_Encoding'
  - 'Accept_Language'
  - 'Accept_Ranges'
  - 'Access-Control-Allow-Credentials'
  - 'Access-Control-Allow-Headers'
  - 'Access-Control-Allow-Methods'
  - 'Access-Control-Allow-Origin'
  - 'Access-Control-Expose-Headers'
  - 'Access-Control-Max-Age'
  - 'Access-Control-Request-Headers'
  - 'Access-Control-Request-Method'
  - 'Age'
  - 'Allow'
  - 'ALPN'
  - 'Alt_Svc'
  - 'Authentication_Info'
  - 'Authorization'
  - 'Cache_Control'
  - 'Connection'
  - 'Content_Encoding'
  - 'Content_Language'
  - 'Content_Length'
  - 'Content_Location'
  - 'Content_Range'
  - 'Content_Security_Policy'
  - 'Content_Security_Policy_Report_Only'
  - 'Content_Type'
  - 'Cross_Origin_Embedder_Policy'
  - 'Cross_Origin_Embedder_Policy_Report_Only'
  - 'Cross_Origin_Opener_Policy'
  - 'Cross_Origin_Opener_Policy_Report_Only'
  - 'Cross_Origin_Resource_Policy'
  - 'Date'
  - 'ETag'
  - 'Expect'
  - 'Expires'
  - 'From'
  - 'Host'
  - 'If_Match'
  - 'If_Modified_Since'
  - 'If_None_Match'
  - 'If_Range'
  - 'If_Unmodified_Since'
  - 'Last_Modified'
  - 'Location'
  - 'Link'
  - 'Max_Forwards'
  - 'NEL'
  - 'Permissions_Policy'
  - 'Proxy_Authenticate'
  - 'Proxy_Authentication_Info'
  - 'Proxy_Authorization'
  - 'Range'
  - 'Referer'
  - 'Referrer_Policy'
  - 'Reporting_Endpoints'
  - 'Retry_After'
  - 'Server'
  - 'Server_Timing'
  - 'Set_Cookie'
  - 'Strict_Transport_Security'
  - 'TE'
  - 'Trailer'
  - 'Upgrade'
  - 'User_Agent'
  - 'Vary'
  - 'Via'
  - 'WWW_Authenticate'
  - 'Unknown_Header'

# Development

To try a rule out without having to rebuild, do a variation of this:

```sh
curl -si --head https://github.com/ | \
  tail -n +2 | \
  node_modules/.bin/peggy src/index.peggy --format es -T- -S Headers_Loose
```

---
[![Tests](https://github.com/cto-af/http-headers/actions/workflows/node.js.yml/badge.svg)](https://github.com/cto-af/http-headers/actions/workflows/node.js.yml)
<!-- no coverage stats for generated files -->
<!-- [![codecov](https://codecov.io/gh/cto-af/http-headers/graph/badge.svg?token=R4kYlgO3hF)](https://codecov.io/gh/cto-af/http-headers) -->
