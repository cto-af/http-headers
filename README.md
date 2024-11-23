# @cto.af/http-headers

Parse HTTP headers from RFC 9110 using the full ABNF.

## Installation

```sh
npm install @cto.af/http-headers
```

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
const contentType = parse('text/html;charset=utf8', {startRule: 'Content_Type'});
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
  - 'Accept_Charset'
  - 'Accept_Encoding'
  - 'Accept_Language'
  - 'Accept_Ranges'
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
  - 'Content_Type'
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
  - 'Max_Forwards'
  - 'Proxy_Authenticate'
  - 'Proxy_Authentication_Info'
  - 'Proxy_Authorization'
  - 'Range'
  - 'Referer'
  - 'Retry_After'
  - 'Server'
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
