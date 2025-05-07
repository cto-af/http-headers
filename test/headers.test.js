import assert from 'node:assert';
import {inspect} from 'node:util';
import {parse} from '../lib/index.js';
import test from 'node:test';

let count = 0;
function known(input, startRule, obsolete = true) {
  const source = `known_${count++}`;
  let obj = undefined;
  try {
    obj = parse(input, {startRule, grammarSource: source, obsolete});
  } catch (e) {
    if (e.format) {
      e.message = e.format([{source, text: input}]);
    }
    throw e;
  }
  assert(obj, input);
  assert.equal(typeof obj, 'object', input);
  assert.notEqual(obj.unknown, true, input);
  return obj;
}

function unknown(input, startRule, obsolete = true) {
  const source = `unknown_${count++}`;
  let obj = undefined;
  try {
    obj = parse(input, {startRule, grammarSource: source, obsolete});
  } catch (e) {
    if (e.format) {
      e.message = e.format([{source, text: input}]);
    }
    throw e;
  }
  assert(obj, input);
  assert.equal(typeof obj, 'object', input);
  assert.equal(obj.unknown, true, inspect(obj));
  return obj;
}

// For debugging
// eslint-disable-next-line no-unused-vars
function out(s) {
  // eslint-disable-next-line no-console
  console.log(inspect(s, {
    colors: process.stdout.isTTY,
    depth: Infinity,
    maxArrayLength: Infinity,
    maxStringLength: Infinity,
  }));
}
function fails(input, startRule, obsolete = true) {
  count++;
  assert.throws(
    () => parse(input, {startRule, obsolete}),
    input
  );
}

test.after(() => {
  // eslint-disable-next-line no-console
  console.log(`Headers: ${count} tests`);
});

test('Header: known', () => {
  const startRule = 'Header';
  // Minimal syntax-valid headers
  assert.deepEqual(parse('Accept: ,', {startRule, obsolete: true}), {
    kind: 'accept',
    name: 'Accept',
    ranges: [],
    value: ',',
  });
  known('Accept-CH: foo', startRule);
  known('Accept-CH: foo, bar', startRule);
  known('Accept-Charset: ,', startRule);
  unknown('Accept-Charset: ,\x80', startRule);
  known('Accept-Encoding: ,', startRule);
  known('Accept-Encoding: identity,', startRule);
  known('Accept-Language: ,', startRule);
  known('Accept-Language: *', startRule);
  unknown('Accept-Language: abcdefghi', startRule);
  unknown('Accept-Language: aaa-abcdefghi', startRule);
  unknown('Accept-Language: aaa-', startRule);
  known('Accept-Ranges: bytes', startRule);
  unknown('Accept-Ranges: bytes\x80', startRule);

  known('Access-Control-Allow-Credentials: true', startRule);
  known('Access-Control-Allow-Credentials: false', startRule);
  known('Access-Control-Allow-Headers: X', startRule);
  known('Access-Control-Allow-Methods: GET', startRule);
  known('Access-Control-Allow-Origin: *', startRule);
  known('Access-Control-Allow-Origin: null', startRule);
  known('Access-Control-Allow-Origin: http://localhost:9000', startRule);
  known('Access-Control-Expose-Headers: X', startRule);
  known('Access-Control-Max-Age: 12', startRule);
  known('Access-Control-Request-Headers: X', startRule);
  known('Access-Control-Request-Method: GET', startRule);
  known('Age: 12', startRule);
  known('Allow: ,', startRule);
  known('Alt-Svc: clear', startRule);
  unknown('Alt-Svc: clear\x80', startRule);
  known('ALPN: h2, http%%2F1.1', startRule);
  known('Authentication-Info: ,', startRule);
  known('Authorization: basic Zm9vOmJhcg==', startRule);
  unknown('Authorization: basic Zm9vOmJhcg==\x80', startRule);
  known('Cache-Control: ,', startRule);
  known('Connection: ,', startRule);
  known('Content-Encoding: ,', startRule);
  known('Content-Language: ,', startRule);
  known('Content-Length: 0', startRule);
  unknown('Content-Length: 0\x80', startRule);
  known('Content-Location: ,', startRule);
  unknown('Content-Location: :', startRule);
  known('Content-Range: bytes */0', startRule);
  unknown('Content-Range: bytes */0\x80', startRule);
  known('Content-Security-Policy: foo', startRule);
  known('Content-Security-Policy-Report-Only: foo', startRule);
  known('Content-Type: foo/bar', startRule);
  fails('Content-Type: foo/bar\x80', startRule);
  known('cross-origin-embedder-policy: require-corp', startRule);
  known('cross-origin-embedder-policy: require-corp; report-to="youtube_main"', startRule);
  known('cross-origin-embedder-policy-report-only: require-corp', startRule);
  known('cross-origin-embedder-policy-report-only: require-corp; report-to="youtube_main"', startRule);
  known('cross-origin-opener-policy: same-origin-allow-popups', startRule);
  known('cross-origin-opener-policy: same-origin-allow-popups; report-to="youtube_main"', startRule);
  known('cross-origin-opener-policy-report-only: same-origin-allow-popups', startRule);
  known('cross-origin-opener-policy-report-only: same-origin-allow-popups; report-to="youtube_main"', startRule);
  known('cross-origin-resource-policy: cross-origin', startRule);
  known('cross-origin-resource-policy: same-origin', startRule);
  known('cross-origin-resource-policy: same-site', startRule);
  known('Date: Sun, 06 Nov 1994 08:49:37 GMT', startRule);
  unknown('Date: Sun, 06 Nov 1994 08:49:37 GMT\x80', startRule);
  known('ETag: ""', startRule);
  unknown('ETag: ""\x80', startRule);
  known('Expect: ,', startRule);
  known('Expires: Sun, 06 Nov 1994 08:49:37 GMT', startRule);
  known('Expires: 0', startRule);
  known('Expires: -1', startRule);
  known('From: a@b', startRule);
  unknown('From: a@b\x80', startRule);
  known('Host: ,', startRule);
  known('Host: ', startRule); // Can't fail
  known('If-Match: ,', startRule);
  known('If-Match: ', startRule); // Can't fail
  known('If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT', startRule);
  unknown('If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\x80', startRule);
  known('If-None-Match: ,', startRule);
  known('If-None-Match: ', startRule); // Can't fail
  known('If-Range: ""', startRule);
  unknown('If-Range: ""\x80', startRule);
  known('If-Unmodified-Since: Sun, 06 Nov 1994 08:49:37 GMT', startRule);
  unknown('If-Unmodified-Since: Sun, 06 Nov 1994 08:49:37 GMT\x80', startRule);
  known('Last-Modified: Sun, 06 Nov 1994 08:49:37 GMT', startRule);
  unknown('Last-Modified: Sun, 06 Nov 1994 08:49:37 GMT\x80', startRule);
  known('Link: ,', startRule);
  known('Location: /', startRule);
  known('Location: ', startRule); // Can't fail
  known('Max-Forwards: 0', startRule);
  unknown('Max-Forwards: 0\x80', startRule);
  known('NEL: ""', startRule);
  known('Permissions-Policy: a', startRule);
  known('Proxy-Authenticate: ,', startRule);
  known('Proxy-Authentication-Info: ,', startRule);
  known('Proxy-Authorization: basic Zm9vOmJhcg==', startRule);
  unknown('Proxy-Authorization: basic Zm9vOmJhcg==\x80', startRule);
  known('Range: bytes=-0', startRule);
  unknown('Range: bytes=-0\x80', startRule);
  known('Referer: ,', startRule);
  known('Referer: ', startRule); // Can't fail
  known('Referrer-Policy: no-referrer', startRule);
  known('Reporting-Endpoints: a=b', startRule);
  known('Retry-After: 0', startRule);
  unknown('Retry-After: 0\x80', startRule);
  known('Server: foo', startRule);
  known('Server-Timing: ,,,', startRule);
  unknown('Server: foo\x80', startRule);
  known('Set-Cookie: stateCode=CO; Domain=.cnn.com; Path=/; SameSite=None; Secure', startRule);
  known('Strict-Transport-Security: max-age=31536000; includeSubdomains; preload', startRule);
  known('TE: ,', startRule);
  known('Trailer: ,', startRule);
  known('Upgrade: ,', startRule);
  known('User-Agent: foo', startRule);
  unknown('User-Agent: foo\x80', startRule);
  known('Vary: ,', startRule);
  known('Via: ,', startRule);
  known('WWW-Authenticate: ,', startRule);
});

test('Header: unknown', () => {
  const startRule = 'Header';
  // All syntax-invalid, which should produce unknown:true unparsed header
  assert.deepEqual(parse('Accept: foo', {startRule, obsolete: true}), {
    kind: 'accept',
    name: 'Accept',
    value: 'foo',
    unknown: true,
  });
  unknown('Accept-CH: ;', startRule);
  unknown('Accept-CH: f;', startRule);
  unknown('Accept-CH: foo;', startRule);
  unknown('Accept-CH: foo,;', startRule);
  unknown('Accept-Charset: ;', startRule);
  unknown('Accept-Charset: foo ;', startRule);
  unknown('Accept-Encoding: ;', startRule);
  unknown('Accept-Language: ;', startRule);
  unknown('Accept-Ranges: ,', startRule);
  unknown('Access-Control-Allow-Credentials: ,', startRule);
  unknown('Access-Control-Allow-Headers: ;', startRule);
  unknown('Access-Control-Allow-Methods: ;', startRule);
  unknown('Access-Control-Allow-Origin: ;', startRule);
  unknown('Access-Control-Expose-Headers: ;', startRule);
  unknown('Access-Control-Max-Age: ;', startRule);
  unknown('Access-Control-Request-Headers: ;', startRule);
  unknown('Access-Control-Request-Method: ;', startRule);
  unknown('Age: a', startRule);
  unknown('Allow: ;', startRule);
  unknown('ALPN: ;', startRule);
  unknown('Alt-Svc: ;', startRule);
  unknown('Authentication-Info: ;', startRule);
  unknown('Authorization: ,', startRule);
  unknown('Cache-Control: ;', startRule);
  unknown('Connection: ;', startRule);
  unknown('Content-Encoding: ;', startRule);
  unknown('Content-Language: ;', startRule);
  unknown('Content-Length: ,', startRule);
  unknown('Content-Location: //\x80', startRule);
  unknown('Content-Range: ,', startRule);
  unknown('Content-Range: bytes,', startRule);
  unknown('Content-Range: bytes ,', startRule);
  unknown('Content-Security-Policy: \x80', startRule);
  unknown('Content-Security-Policy-Report-Only: \x80', startRule);
  unknown('Content-Type: ,', startRule);
  unknown('Cross-Origin-Embedder-Policy: \x80', startRule);
  unknown('Cross-Origin-Embedder-Policy-Report-Only: \x80', startRule);
  unknown('Cross-Origin-Opener-Policy: \x80', startRule);
  unknown('Cross-Origin-Opener-Policy-Report-Only: \x80', startRule);
  unknown('cross-origin-resource-policy: \x80', startRule);
  unknown('cross-origin-resource-policy: same-origin-ish', startRule);
  unknown('Date: ,', startRule);
  unknown('ETag: ,', startRule);
  unknown('Expect: ;', startRule);
  unknown('Expires: ;', startRule);
  unknown('From: ,', startRule);
  unknown('Host: {', startRule);
  unknown('If-Match: ;', startRule);
  unknown('If-Modified-Since: ,', startRule);
  unknown('If-None-Match: ;', startRule);
  unknown('If-None-Match: "foo', startRule);
  unknown('If-Range: ,', startRule);
  unknown('If-Unmodified-Since: ,', startRule);
  unknown('Last-Modified: ,', startRule);
  unknown('Link: ;', startRule);
  unknown('Location: {', startRule);
  unknown('Max-Forwards: ,', startRule);
  unknown('NEL: "', startRule);
  unknown('Permissions-Policy: ;', startRule);
  unknown('Proxy-Authenticate: ;', startRule);
  unknown('Proxy-Authentication-Info: ;', startRule);
  unknown('Proxy-Authorization: ,', startRule);
  unknown('Range: ,', startRule);
  unknown('Referer: {', startRule);
  unknown('Referrer-Policy: foo', startRule);
  unknown('Reporting-Endpoints: ;', startRule);
  unknown('Retry-After: ,', startRule);
  unknown('Server: ,', startRule);
  unknown('Server-Timing: ;', startRule);
  unknown('TE: ;', startRule);
  unknown('Set-Cookie: ;', startRule);
  unknown('Strict-Transport-Security: \x80', startRule);
  unknown('Trailer: ;', startRule);
  unknown('Upgrade: ;', startRule);
  unknown('User-Agent: ,', startRule);
  unknown('Vary: ;', startRule);
  unknown('Via: ;', startRule);
  unknown('WWW-Authenticate: ;', startRule);
});

test('Headers strict', () => {
  const googleHeaders = `\
location: https://www.google.com/\r
content-type: text/html; charset=UTF-8\r
content-security-policy-report-only: object-src 'none';base-uri 'self';script-src 'nonce-mDRix_DuLkaEeso5np47EA' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp\r
date: Tue, 12 Nov 2024 17:36:02 GMT\r
expires: Thu, 12 Dec 2024 17:36:02 GMT\r
cache-control: public, max-age=2592000\r
server: gws\r
content-length: 220\r
x-xss-protection: 0\r
x-frame-options: SAMEORIGIN\r
alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000\r
\r
`;
  const expected = [
    {
      kind: 'location',
      value: 'https://www.google.com/',
      uri: new URL('https://www.google.com/'),
      name: 'location',
    },
    {
      kind: 'content-type',
      value: 'text/html; charset=UTF-8',
      type: 'text',
      subtype: 'html',
      parameters: {charset: 'utf-8'},
      name: 'content-type',
    },
    {
      kind: 'content-security-policy-report-only',
      value: "object-src 'none';base-uri 'self';script-src 'nonce-mDRix_DuLkaEeso5np47EA' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp",
      directives: [
        {
          name: 'object-src',
          values: [{kind: 'keyword', value: "'none'"}],
        },
        {
          name: 'base-uri',
          values: [{kind: 'keyword', value: "'self'"}],
        },
        {
          name: 'script-src',
          values: [
            {kind: 'nonce', value: "'nonce-mDRix_DuLkaEeso5np47EA'"},
            {kind: 'keyword', value: "'strict-dynamic'"},
            {kind: 'keyword', value: "'report-sample'"},
            {kind: 'keyword', value: "'unsafe-eval'"},
            {kind: 'keyword', value: "'unsafe-inline'"},
            {kind: 'scheme', value: 'https:'},
            {kind: 'scheme', value: 'http:'},
          ],
        },
        {
          name: 'report-uri',
          values: [
            {
              kind: 'host',
              value: 'https://csp.withgoogle.com/csp/gws/other-hp',
            },
          ],
        },
      ],
      name: 'content-security-policy-report-only',
    },
    {
      kind: 'date',
      value: 'Tue, 12 Nov 2024 17:36:02 GMT',
      date: new Date('2024-11-12T17:36:02.000Z'),
      name: 'date',
    },
    {
      kind: 'expires',
      name: 'expires',
      value: 'Thu, 12 Dec 2024 17:36:02 GMT',
      date: new Date('Thu, 12 Dec 2024 17:36:02 GMT'),
    },
    {
      kind: 'cache-control',
      name: 'cache-control',
      value: 'public, max-age=2592000',
      controls: [
        ['public', null],
        ['max-age', 2592000],
      ],
    },
    {
      kind: 'server',
      value: 'gws',
      products: [{product: 'gws', version: null}],
      name: 'server',
    },
    {
      kind: 'content-length',
      value: '220',
      length: 220,
      name: 'content-length',
    },
    {
      kind: 'x-xss-protection',
      name: 'x-xss-protection',
      value: '0',
      unknown: true,
    },
    {
      kind: 'x-frame-options',
      name: 'x-frame-options',
      value: 'SAMEORIGIN',
      unknown: true,
    },
    {
      kind: 'alt-svc',
      value: 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000',
      services: [
        {
          protocol: 'h3',
          authority: ':443',
          parameters: {ma: '2592000'},
        },
        {
          protocol: 'h3-29',
          authority: ':443',
          parameters: {ma: '2592000'},
        },
      ],
      name: 'alt-svc',
    },
  ];
  assert.deepEqual(parse(googleHeaders), expected);
  const noCR = googleHeaders.replaceAll('\r', '');
  assert.throws(() => parse(noCR));
  assert.deepEqual(parse(noCR, {startRule: 'Headers_Loose'}), expected);
});

test('Headers edge cases', () => {
  assert.throws(() => parse('Foo: bar\r\nBaz: boo'));
});

test('Headers_Loose edge cases', () => {
  const startRule = 'Headers_Loose';
  fails('', startRule);
  fails('Foo: bar', startRule);
  fails('Foo: bar\r', startRule);
  fails('Foo: bar\nBar: boo\r', startRule);
});

test('Header edge cases', () => {
  const startRule = 'Header';
  fails('accept-charset', startRule);
  fails('accept-encoding', startRule);
  fails('Accept-Language', startRule);
  fails('Accept-Ranges', startRule);
  fails('Access-Control-Allow-Credentials', startRule);
  fails('Access-Control-Allow-Headers', startRule);
  fails('Access-Control-Allow-Methods', startRule);
  fails('Access-Control-Allow-Origin', startRule);
  fails('Access-Control-Expose-Headers', startRule);
  fails('Access-Control-Max-Age', startRule);
  fails('Access-Control-Request-Headers', startRule);
  fails('Access-Control-Request-Method', startRule);
  fails('Age', startRule);
  fails('Allow', startRule);
  fails('ALPN', startRule);
  fails('Alt-Svc', startRule);
  fails('Authentication-Info', startRule);
  fails('Authorization', startRule);
  fails('Cache-Control', startRule);
  fails('Connection', startRule);
  fails('Content-Encoding', startRule);
  fails('Content-Language', startRule);
  fails('Content-Length', startRule);
  fails('Content-Location', startRule);
  fails('Content-Range', startRule);
  fails('Content-Security-Policy', startRule);
  fails('Content-Security-Policy-Report-Only', startRule);
  fails('Content-Type', startRule);
  fails('Cross-Origin-Embedder-Policy', startRule);
  fails('Cross-Origin-Embedder-Policy-Report-Only', startRule);
  fails('Cross-Origin-Opener-Policy', startRule);
  fails('Cross-Origin-Opener-Policy-Report-Only', startRule);
  fails('Cross-Origin-Resource-Policy', startRule);
  fails('Date', startRule);
  fails('ETag', startRule);
  fails('Expect', startRule);
  fails('Expires', startRule);
  fails('From', startRule);
  fails('Host', startRule);
  fails('If-Match', startRule);
  fails('If-Modified-Since', startRule);
  fails('If-None-Match', startRule);
  fails('If-Range', startRule);
  fails('If-Unmodified-Since', startRule);
  fails('Last-Modified', startRule);
  fails('Link', startRule);
  fails('Location', startRule);
  fails('Max-Forwards', startRule);
  fails('NEL', startRule);
  fails('Permissions-Policy', startRule);
  fails('Proxy-Authenticate', startRule);
  fails('Proxy-Authentication-Info', startRule);
  fails('Proxy-Authorization', startRule);
  fails('Range', startRule);
  fails('Referer', startRule);
  fails('Referrer-Policy', startRule);
  fails('Reporting-Endpoints', startRule);
  fails('Retry-After', startRule);
  fails('Server', startRule);
  fails('Server-Timing', startRule);
  fails('Set-Cookie', startRule);
  fails('Strict-Transport-Security', startRule);
  fails('TE', startRule);
  fails('Trailer', startRule);
  fails('Upgrade', startRule);
  fails('User-Agent', startRule);
  fails('Vary', startRule);
  fails('Via', startRule);
  fails('WWW-Authenticate', startRule);
  fails('unknown:   ', startRule);
});

test('Accept', t => {
  known('*/*, test/*', t.name);

  fails('test', t.name);
  fails('test/', t.name);
  fails('*', t.name);
  fails('*/', t.name);
  fails('foo/bar;foo\x80', t.name);
  fails('foo/bar;foo=\x80', t.name);
});

test('Accept_Charset', t => {
  fails('*?', t.name);
  fails('*?-', t.name);
  fails('*;?', t.name);
  fails('*;-', t.name);
  fails('*;q', t.name);
  fails('*;q=', t.name);
  fails('*;q=2', t.name);
  fails('*;q=0.0001', t.name);
  fails('*;q=1a', t.name);
  fails('*;q=1.a', t.name);
  fails('*;q=1.0000', t.name);
});

test('Alt_Svc', t => {
  known('h3=":443"', t.name);
  fails('h3=":443"; ma', t.name);
  known('h3=":443";ma=1;mb=2', t.name);
  fails('h3=":443"; ma=1;mb=2;', t.name);
  fails('h3=":443"; ma=1;mb=2;mc', t.name);
  fails('h3\x80', t.name);
  fails('h3=\x80', t.name);
  fails('h3=":443"; ma=\x80', t.name);
});

test('Authorization', t => {
  known('foo', t.name);
  fails('\x80', t.name);
  fails('foo \x80', t.name);
});

test('Content_Language', t => {
  fails('sl-rozaj-roza\x80', t.name);
  fails('x\x80', t.name);
  fails('x-', t.name);
  fails('x-abcdefghi', t.name);
  fails('x-abc\x80', t.name);
  fails('x-abc-', t.name);
  fails('x-abc-abcdefghi', t.name);
  fails('abcdefghi', t.name);
  fails('foo-abcdefghi', t.name);
  fails('foo-1a', t.name);
  fails('foo-1-a', t.name);
  fails('foo-1-aa-a', t.name);
  fails('foo-1-aa-abcdefghi', t.name);
  known('foot', t.name);
  known('footb', t.name);
  known('en-yyy', t.name);
  known('en-yyy-zzz', t.name);
  known('en-xxx-yyy-zzz', t.name);
  known('en-xx', t.name);
  known('en-xxx-yy', t.name);
  known('en-xxx-yyy-zz', t.name);
  fails('en-xxz-yy1', t.name);

  for (const lang of [
    // Irregular
    'en-GB-oed',
    'i-ami',
    'i-bnn',
    'i-default',
    'i-enochian',
    'i-hak',
    'i-klingon',
    'i-lux',
    'i-mingo',
    'i-navajo',
    'i-pwn',
    'i-tao',
    'i-tay',
    'i-tsu',
    'sgn-BE-FR',
    'sgn-BE-NL',
    'sgn-CH-DE',
    // Regular
    'art-lojban',
    'cel-gaulish',
    'no-bok',
    'no-nyn',
    'zh-guoyu',
    'zh-hakka',
    'zh-min',
    'zh-min-nan',
    'zh-xiang',
  ]) {
    known(lang, t.name);
  }
});

test('fetch', () => {
  fails('true ', 'Access_Control_Allow_Credentials');

  known('X, Y', 'Access_Control_Allow_Headers');
  fails('X-foo, X-bar, \x00', 'Access_Control_Allow_Headers');

  known('GET, POST', 'Access_Control_Allow_Methods');
  fails('GET, POST, \x00', 'Access_Control_Allow_Methods');

  known('http://foo', 'Access_Control_Allow_Origin');
  fails('* ', 'Access_Control_Allow_Origin');
  fails('foo', 'Access_Control_Allow_Origin');
  fails('foo:', 'Access_Control_Allow_Origin');
  fails('foo://bar:\x00', 'Access_Control_Allow_Origin');

  known('X-foo, X-bar', 'Access_Control_Expose_Headers');
  fails('X-foo, X-bar, \x00', 'Access_Control_Expose_Headers');

  fails('\x00', 'Access_Control_Max_Age');
  fails('12\x00', 'Access_Control_Max_Age');

  known('X-foo, X-bar', 'Access_Control_Request_Headers');
  fails('X-foo, X-bar, \x00', 'Access_Control_Request_Headers');

  fails('\x00', 'Access_Control_Request_Method');
  fails('get\x00', 'Access_Control_Request_Method');
});

test('Content_Location', t => {
  known('http://foo:80/bar/baz/boo', t.name);
  known('foo', t.name);
  known('http://foo/bar?baz', t.name);
  known('http://$@foo/', t.name);
  known('foo?baz', t.name);
  known('/foo?baz', t.name);
  known('http:/foo?baz', t.name);
  known('file:/foo/bar/baz', t.name);
  known('file:', t.name);
  known('file:foo', t.name);
  known('file:foo/bar', t.name);
  known('file:foo/bar/baz-%ff:', t.name);
  known('foo/bar/baz', t.name);
  known('foo!', t.name);
  fails('http://foo@\x80', t.name);
  fails('http://foo/bar?/?\x80', t.name);
  fails('http://foo/bar?%f', t.name);
  fails('foo\x80', t.name);
  fails('f{', t.name);
});

test('Content_Range', t => {
  fails('bytes 1-2', t.name);
  fails('bytes 1a', t.name);
  fails('bytes 1-a', t.name);
  fails('bytes 1-2/a', t.name);
  fails('bytes *', t.name);
  fails('bytes */', t.name);
  fails('bytes */a', t.name);
});

test('Content_Security_Policy', t => {
  known('foo   ,   \t bar', t.name);
  known("webrtc 'block'", t.name);
  known("webrtc 'allow'", t.name);
  known("webrtc 'foo'", t.name);
  fails('webrtc\x00', t.name);
  known('sandbox', t.name);
  known('sandbox;', t.name);
  known('sandbox ', t.name);
  known('sandbox allow-downloads', t.name);
  known('sandbox allow-forms allow-modals', t.name);
  fails('sandbox allow-forms \x00', t.name);
  fails('sandbox "foo"');
  known("frame-ancestors 'none';", t.name);
  known("frame-ancestors 'self';", t.name);
  known('frame-ancestors foo: http://example.com;', t.name);
  known('frame-ancestors', t.name);
  known('frame-ancestors ', t.name);
  fails('frame-ancestors \x00', t.name);
  fails('frame-ancestors foo: ', t.name);
  known('report-uri   \t\fhttp://example.com https://example.com#bar;', t.name);
  known('report-uri http://foo@192.168.1.1/foo/baz/bo!o?bar=foo&baz=1 http://[::1]:443/ / /boo /boo/bar /boo/bar/baz/boop boo boo/bar boo/bar/baz f://! xmpp:example-node@example.com/some-resource/deep/there boop!%3b %3bblah @at !at;', t.name);
  known('report-uri mailto:foo@bar', t.name);
  known('report-uri', t.name);
  known('report-uri //???#?', t.name);
  known('report-uri /#', t.name);
  known('report-uri /#???', t.name);
  fails('report-uri /?\x00', t.name);
  fails('report-uri \x00', t.name);
  fails('report-uri //foo bar\x00', t.name);
  known('report-to foo', t.name);
  known('report-to', t.name);
  known('report-to ', t.name);
  known("base-uri 'none'", t.name);
  known('base-uri /', t.name);
  known('base-uri / ', t.name);
  fails('base-uri foo: / ', t.name);
  known('base-uri', t.name);
  known('child-src /', t.name);
  known('connect-src /', t.name);
  known('default-src /', t.name);
  known('font-src /', t.name);
  known('form-action /', t.name);
  known('form-src /', t.name);
  known("frame-src 'nonce-Zm9vOmJhcg=='", t.name);
  known("frame-src 'nonce-Zm9vOmJhcg==", t.name);
  known("frame-src 'sha256-Zm9vOmJhcg=='", t.name);
  known("frame-src 'sha384-Zm9vOmJhcg==", t.name);
  known("frame-src 'sha512", t.name);
  fails("frame-src 'sha256-\x00", t.name);
  fails("frame-src 'sha256-Z\x00", t.name);
  known('img-src *.example.com.', t.name);
  known('img-src *.example.com:400/foo/bar', t.name);
  fails('img-src *.example.\x00', t.name);
  fails('img-src *.example.com:400/\x00', t.name);
  fails('img-src *.example.com:400/foo\x00', t.name);
  fails('img-src *.example.com:400/foo/bar/\x00', t.name);
  fails('img-src *.example.com:400/foo/bar\x00', t.name);
  fails('img-src *.\x00', t.name);
  fails('img-src *.ex\x00', t.name);
  fails('img-src ex\x00', t.name);
  known("img-src 'wasm-unsafe-eval'", t.name);
  known("manifest-src 'unsafe-allow-redirects'", t.name);
  known("media-src 'report-sample'", t.name);
  known('object-src http://foo:*/', t.name);
  known('script-src-attr http://foo:444/', t.name);
  fails('script-src-attr http://foo:a/', t.name);
  known('script-src foo:;', t.name);
  known('script-src foo-.bar: foo;', t.name);
  known("style-src-attr 'unsafe-inline'", t.name);
  known("style-src-elem 'unsafe-eval'", t.name);
  known("style-src 'strict-dynamic'", t.name);
  known("worker-src 'unsafe-hashes'", t.name);
  known('upgrade-insecure-requests', t.name);
  known("require-trusted-types-for 'script'", t.name);
  known("require-trusted-types-for 'script' 'script'", t.name);
  fails("require-trusted-types-for 'script' 'script' ", t.name);
  fails("require-trusted-types-for 'script' ", t.name);
  known("require-trusted-types-for 'foo'", t.name);
  known('require-trusted-types-for', t.name);
  fails('require-trusted-types-for\x00', t.name);
  known('require-trusted-types-for ', t.name);
  known("trusted-types foo * 'none'", t.name);
  known('trusted-types', t.name);
  known('trusted-types ', t.name);
  fails('trusted-types \x00', t.name);
  fails("trusted-types 'allow-duplicates' \x00", t.name);
  known('foo ', t.name);
  known('foo, bar', t.name);
  fails(',', t.name);
  fails(';;', t.name);
  fails('foo, bar\x00');
});

test('Content_Security_Policy_Report_Only', t => {
  fails('foo, bar\x00', t.name);
});

test('Content_Type', t => {
  fails('foo', t.name);
  fails('foo/', t.name);
  fails('foo/\x80', t.name);
  fails('foo/bar   \x80', t.name);
  fails('foo/bar;\x80', t.name);
  fails('foo/bar;a=b;\x80', t.name);
});

test('Cross_Origin_Embedder_Policy', t => {
  fails('1', t.name);
  fails('1;foo', t.name);
  fails('foo\x00', t.name);
});

test('Cross_Origin_Embedder_Policy_Report_Only', t => {
  fails('1', t.name);
  fails('1;foo', t.name);
  fails('foo\x00', t.name);
});

test('Cross_Origin_Opener_Policy', t => {
  fails('1', t.name);
  fails('1;foo', t.name);
  fails('foo\x00', t.name);
});

test('Cross_Origin_Opener_Policy_Report_Only', t => {
  fails('1', t.name);
  fails('1;foo', t.name);
  fails('foo\x00', t.name);
});

test('Date', t => {
  let d = 'Sun, 06 Nov 1994 08:49:37 GMT';
  for (let i = 0; i < (d.length - 1); i++) {
    fails(d.slice(0, i), t.name);
  }
  d = 'Sunday, 06-Nov-94 08:49:37 GMT';
  for (let i = 0; i < (d.length - 1); i++) {
    fails(d.slice(0, i), t.name);
  }
  d = 'Sun Nov  6 08:49:37 1994';
  for (let i = 0; i < (d.length - 1); i++) {
    fails(d.slice(0, i), t.name);
  }
  known('Sunday, 06-Nov-94 08:49:37 GMT', t.name);
  known('Monday, 07-Nov-94 08:49:37 GMT', t.name);
  known('Tuesday, 08-Nov-94 08:49:37 GMT', t.name);
  known('Wednesday, 09-Nov-94 08:49:37 GMT', t.name);
  known('Thursday, 10-Nov-94 08:49:37 GMT', t.name);
  known('Friday, 11-Nov-94 08:49:37 GMT', t.name);
  known('Saturday, 12-Nov-94 08:49:37 GMT', t.name);

  known('Sun Nov 13 08:49:37 1994', t.name);
});

test('Expect', t => {
  fails('100-Continue=', t.name);
  fails('100-Continue="\x80', t.name);
  fails('100-Continue="\\"', t.name);
});

test('From', t => {
  known('Foo <boo@example>', t.name);
  known('<@example1.org,@example2.org:joe@example.org>', t.name);
  known('"boo"@example', t.name);
  known('"boo"."bar"@example', t.name);
  known('bar@[example]', t.name);
  known('bar@(comment)example', t.name);
  known('bar@(foo) bar. (boo) (blu)baz (boo). buzz', t.name);

  fails('', t.name);
  fails('\x80', t.name);
  fails('foo\x80', t.name);
  fails('foo@\x80', t.name);
  fails('Foo <foo@\x80', t.name);
  fails('Foo <foo@example\x80', t.name);
  fails('Foo <foo@example', t.name);
  fails('(foo) (bar)<foo@example', t.name);
  fails('Foo <"foo', t.name);
  fails('<@example1.org,@example2.org:joe@example.org', t.name);
  fails('<@:', t.name);
  fails('<\x80', t.name);
  fails('<@example1.org,@example2.org:joe@\x80', t.name);
  fails('"foo"."bar', t.name);
  fails('bar@[example\x80', t.name);
  fails('bar@[[', t.name);
});

test('Host', t => {
  known('1.2.3.4', t.name);
  known('255.240.199.84', t.name);
  known('256', t.name);
  known('266', t.name);
  known('24a', t.name);
  known('[::]', t.name);
  known('[::1]', t.name);
  known('[2001:0db8:85a3:0000:0000:8a2e:192.0.2.128]', t.name);
  known('[2001:0db8:85a3:0000:0000:8a2e:0370:7334]', t.name);
  known('[::0db8:85a3:0000:0000:8a2e:0370:7334]', t.name);
  known('[::85a3:0000:0000:8a2e:0370:7334]', t.name);
  known('[1::85a3:0000:0000:8a2e:0370:7334]', t.name);
  known('[::0000:0000:8a2e:0370:7334]', t.name);
  known('[1::0000:0000:8a2e:0370:7334]', t.name);
  known('[1:2::0000:0000:8a2e:0370:7334]', t.name);
  known('[::0000:8a2e:0370:7334]', t.name);
  known('[1::0000:8a2e:0370:7334]', t.name);
  known('[1:2::0000:8a2e:0370:7334]', t.name);
  known('[1:2:3::0000:8a2e:0370:7334]', t.name);
  known('[1::8a2e:0370:7334]', t.name);
  known('[1:2::8a2e:0370:7334]', t.name);
  known('[1:2:3::8a2e:0370:7334]', t.name);
  known('[1:2:3:4::8a2e:0370:7334]', t.name);
  known('[1::0370:7334]', t.name);
  known('[1:2::0370:7334]', t.name);
  known('[1:2:3::0370:7334]', t.name);
  known('[1:2:3:4::0370:7334]', t.name);
  known('[1:2:3:4:5::0370:7334]', t.name);
  known('[1::7334]', t.name);
  known('[1:2::7334]', t.name);
  known('[1:2:3::7334]', t.name);
  known('[1:2:3:4::7334]', t.name);
  known('[1:2:3:4:5::7334]', t.name);
  known('[1:2:3:4:5:6::7334]', t.name);
  known('[1:2:3:4:5:6::7334]', t.name);
  known('[2001::85a3:0000:0000:8a2e:0370:7334]', t.name);
  known('[::85a3:0000:0000:8a2e:0370:7334]', t.name);
  known('[2001:0db8::0000:0000:8a2e:0370:7334]', t.name);
  known('[2001::0000:0000:8a2e:0370:7334]', t.name);
  known('[::0000:0000:8a2e:0370:7334]', t.name);
  known('[2001:db8::1]', t.name);
  known('[2001:0db8::]', t.name);
  known('[2001:0db8:85a3::]', t.name);
  known('[2001:0db8:85a3:0000::]', t.name);
  known('[2001:0db8:85a3:0000:0000::]', t.name);
  known('[2001:0db8:85a3:0000:0000:8a2e::]', t.name);
  known('[2001:0db8:85a3:0000:0000:8a2e:0370::]', t.name);
  known('[va.::1]', t.name);
  known('%ff', t.name);

  fails('[::1', t.name);
  fails('\x80', t.name);
  fails('1.\x80', t.name);
  fails('1.2\x80', t.name);
  fails('1.2.\x80', t.name);
  fails('1.2.3\x80', t.name);
  fails('1.2.3.\x80', t.name);
  fails('[2001]', t.name);
  fails('[2001:0db8]', t.name);
  fails('[2001:0db8:85a]', t.name);
  fails('[2001:0db8:85a3]', t.name);
  fails('[2001:0db8:85a3:0000:0000:8a2e:0370:7334:2001]', t.name);
  fails('[2001:0db8:85a3:0000:0000:8a2e:0370:7334:2001:0db8]', t.name);
  fails('[20011]', t.name);
  fails('[aaaa:20011]', t.name);
  fails('[::\x80]', t.name);
  fails('[::1:\x80]', t.name);
  fails('[v]', t.name);
  fails('[z]', t.name);
  fails('[v\x80]', t.name);
  fails('[vaaa\x80]', t.name);
  fails('[vaaa.\x80]', t.name);
  fails('%zf', t.name);

  const d = '[2001:0db8:85a3:0000:0000:8a2e:0370:7334]';
  for (let i = 0; i < d.length; i++) {
    fails(`${d.slice(0, i)}\x80`, t.name);
  }
});

test('Link', t => {
  known('<https://aadcdn.msauth.net>; rel="preconnect"; crossorigin', t.name);
  fails('<:::', t.name);
  fails('<https://aa', t.name);
  fails('<https://aadcdn.msauth.net> ;/', t.name);
  fails('<https://aadcdn.msauth.net> rel=preconnect; /', t.name);
  fails('<https://aadcdn.msauth.net> ; rel=preconnect; /', t.name);
  fails('<https://aadcdn.msauth.net> ;rel=preconnect; crossorigin; /', t.name);
  fails('<https://aadcdn.msauth.net> ;rel="pre', t.name);
});

test('Location', t => {
  fails('foo\x80', t.name);
  fails('http://foo/#/\x80', t.name);
  fails('http://foo/#\x80', t.name);
  known('http://foo/#bar/', t.name);
  known('http://foo/?bar', t.name);
  known('/#bar', t.name);
  known('/?bar', t.name);
});

test('NEL', t => {
  fails('\x00', t.name);
});

test('Permissions_Policy', t => {
  fails('\x00', t.name);
  fails('a=b\x00', t.name);
  fails('a=b, \x00', t.name);
  fails('a=b, c\x00', t.name);
  fails('a=b, c=\x00', t.name);
  fails('a=b, c=d\x00', t.name);
  fails('a=b;\x00', t.name);
  fails('a=b;  \x00', t.name);
  fails('a=b; c; d\x00', t.name);
  fails('a=1234567890123456', t.name);
  fails('a=1.1234', t.name);
  fails('a=1.', t.name);
  fails('a="1', t.name);
  fails('foo=:Zm', t.name);
  fails('foo=:Zm9vOmJhcg=a:', t.name);
  known('foo=:Zm9vOmJhcg==:', t.name);
  known('geolocation=(self "https://example.com" "https://geo.example.com" "https://geo2.example.com" "https://new.geo2.example.com")', t.name);
  known('geolocation=(self "https://example.com" "https://*.example.com")', t.name);
  known('geolocation=(self "https://example.com" "https://example.com:444" "https://example.com:445" "https://example.com:446")', t.name);
  known('geolocation=(   *   1   -1 1.1 -1.1 ?0 ?1);foo', t.name);
  known('geolocation=*;foo=bar', t.name);
  known('foo=1', t.name);
  known('foo=a;b; c=d', t.name);
  fails('foo=a;a=?b', t.name);
  known('foo="a\\"b"', t.name);
  fails('foo="a\\("', t.name);
  fails('foo=?', t.name);
  fails('foo=?a', t.name);
  fails('foo=(?a)', t.name);
  fails('foo=(0 ?a)', t.name);
  fails('foo;A', t.name);
  fails('foo;a, bar;A', t.name);
});

test('Range', t => {
  fails('bytes\x80', t.name);
  fails('bytes=', t.name);
  fails('bytes=,', t.name);
});

test('Referrer_Policy', t => {
  known('no-referrer-when-downgrade', t.name);
  known('no-referrer', t.name);
  known('strict-origin-when-cross-origin', t.name);
  known('strict-origin', t.name);
  known('same-origin', t.name);
  known('origin-when-cross-origin', t.name);
  known('origin,,', t.name);
  known('unsafe-url,', t.name);
  known('unsafe-url, origin, same-origin', t.name);
  fails('', t.name);
  fails('foo', t.name);
  fails('unsafe-url\x80', t.name);
});

test('Reporting_Endpoints', t => {
  known('coop_report="https://www.facebook.com/browser_reporting/coop/?minimize=0"', t.name);
  fails('one=1', t.name);
  fails('one=two\x00', t.name);
});

test('Server', t => {
  fails('', t.name);
  fails('\x80', t.name);
  fails('foo \x80', t.name);
  fails('foo bar \x80', t.name);
  fails('foo/', t.name);
  fails('foo/\x80', t.name);
  fails('foo (\\\x00', t.name);
  known('foo  \t  bar (((more comment \\))))', t.name);
});

test('Server_Timing', t => {
  known('tid;desc="xcIlGVEQAJ0iusle8DcbYChbUeLtmQ";a=b,front;dur=0.171', t.name);
  fails('foo \x00', t.name);
  fails('foo ;\x00', t.name);
  fails('foo ;a\x00', t.name);
  fails('foo ;a=\x00', t.name);
  fails('foo ;a=b\x00', t.name);
  fails('foo ;a=b;\x00', t.name);
});

test('Set_Cookie', t => {
  known('foo="bar"', t.name);
  known('foo="bar";boo;', t.name);
  fails('foo=bar; \x00', t.name);
});

test('TE', t => {
  known('deflate;a="foo"', t.name);
  fails('deflate\x80', t.name);
  fails('deflate;\x80', t.name);
  fails('deflate;a\x80', t.name);
  fails('deflate;a=b;\x80', t.name);
  fails('deflate;a=b;c=d;\x80', t.name);
  fails('deflate;a="foo', t.name);
});

test('Upgrade', t => {
  fails('foo\x80', t.name);
  fails('foo/\x80', t.name);
});

test('User_Agent', t => {
  fails('', t.name);
  fails('\x80', t.name);
  fails('foo \x80', t.name);
  fails('foo bar \x80', t.name);
});

test('Vary', t => {
  fails('\x80', t.name);
  fails('foo, \x80', t.name);
  fails('foo, bar, \x80', t.name);
  fails('foo, *,,\x80', t.name);
});

test('Via', t => {
  fails('\x80', t.name);
  fails('1.1\x80', t.name);
  fails('1.1 \x80', t.name);
  fails('1.1 foo\x80', t.name);
  fails('1.1 foo \x80', t.name);
  fails('1.1 foo (\x80', t.name);

  fails('https/1.0 fred,\x80', t.name);
  fails('https/1.0 fred, 1.1\x80', t.name);
  fails('https/1.0 fred, 1.1 \x80', t.name);
  fails('https/1.0 fred, 1.1 foo\x80', t.name);
  fails('https/1.0 fred, 1.1 foo \x80', t.name);
  fails('https/1.0 fred, 1.1 foo (\x80', t.name);
});

test('WWW_Authenticate', t => {
  fails('basic ', t.name);
  fails('\x80 ', t.name);
  fails('basic\x80', t.name);
});

test('Unknown_Header', t => {
  fails('f: f\u1000', t.name);
});
