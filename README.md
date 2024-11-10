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

const headers = parse('Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n\r\n');
// [
//   {
//     kind: 'date',
//     value: 'Sun, 06 Nov 1994 08:49:37 GMT',
//     date: 1994-11-06T08:49:37.000Z,
//     name: 'Date'
//   }
// ]

const contentType = parse('text/html;charset=utf8', {startRule: 'Content_Type'});
// {
//   kind: 'content_type',
//   value: 'text/html;charset=utf8',
//   type: 'text',
//   subtype: 'html',
//   parameters: { charset: 'utf8' }
// }
```

---
[![Tests](https://github.com/cto-af/http-headers/actions/workflows/node.js.yml/badge.svg)](https://github.com/cto-af/http-headers/actions/workflows/node.js.yml)
[![codecov](https://codecov.io/gh/cto-af/http-headers/graph/badge.svg?token=R4kYlgO3hF)](https://codecov.io/gh/cto-af/http-headers)
