import assert from 'node:assert';
import {inspect} from 'node:util';
import {parse} from '../lib/index.js';
// eslint-disable-next-line n/no-unsupported-features/node-builtins
import test from 'node:test';

let count = 0;
function known(input, startRule, obsolete = true) {
  const source = `known_${count++}`;
  let obj = undefined;
  try {
    obj = parse(input, {startRule, grammarSource: source, obsolete});
  } catch (e) {
    e.message = e.format([{source, text: input}]);
    throw e;
  }
  assert(obj, input);
  assert.equal(typeof obj, 'object', input);
  assert.notEqual(obj.unknown, true, input);
}

function unknown(input, startRule, obsolete = true) {
  const source = `unknown_${count++}`;
  let obj = undefined;
  try {
    obj = parse(input, {startRule, grammarSource: source, obsolete});
  } catch (e) {
    e.message = e.format([{source, text: input}]);
    throw e;
  }
  assert(obj, input);
  assert.equal(typeof obj, 'object', input);
  assert.equal(obj.unknown, true, inspect(obj), input);
}

function fails(input, startRule, obsolete = true) {
  assert.throws(() => parse(input, {startRule, obsolete}), input);
}

test('Header: known', () => {
  const startRule = 'Header';
  // Minimal syntax-valid headers
  assert.deepEqual(parse('Accept: ,', {startRule, obsolete: true}), {
    kind: 'accept',
    name: 'Accept',
    ranges: [],
    value: ',',
  });
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
  known('Allow: ,', startRule);
  known('Alt-Svc: clear', startRule);
  unknown('Alt-Svc: clear\x80', startRule);
  known('Authentication-Info: ,', startRule);
  known('Authorization: basic Zm9vOmJhcg==', startRule);
  unknown('Authorization: basic Zm9vOmJhcg==\x80', startRule);
  known('Connection: ,', startRule);
  known('Content-Encoding: ,', startRule);
  known('Content-Language: ,', startRule);
  known('Content-Length: 0', startRule);
  unknown('Content-Length: 0\x80', startRule);
  known('Content-Location: ,', startRule);
  unknown('Content-Location: :', startRule);
  known('Content-Range: bytes */0', startRule);
  unknown('Content-Range: bytes */0\x80', startRule);
  known('Content-Type: foo/bar', startRule);
  fails('Content-Type: foo/bar\x80', startRule);
  known('Date: Sun, 06 Nov 1994 08:49:37 GMT', startRule);
  unknown('Date: Sun, 06 Nov 1994 08:49:37 GMT\x80', startRule);
  known('ETag: ""', startRule);
  unknown('ETag: ""\x80', startRule);
  known('Expect: ,', startRule);
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
  known('Location: /', startRule);
  known('Location: ', startRule); // Can't fail
  known('Max-Forwards: 0', startRule);
  unknown('Max-Forwards: 0\x80', startRule);
  known('Proxy-Authenticate: ,', startRule);
  known('Proxy-Authentication-Info: ,', startRule);
  known('Proxy-Authorization: basic Zm9vOmJhcg==', startRule);
  unknown('Proxy-Authorization: basic Zm9vOmJhcg==\x80', startRule);
  known('Range: bytes=-0', startRule);
  unknown('Range: bytes=-0\x80', startRule);
  known('Referer: ,', startRule);
  known('Referer: ', startRule); // Can't fail
  known('Retry-After: 0', startRule);
  unknown('Retry-After: 0\x80', startRule);
  known('Server: foo', startRule);
  unknown('Server: foo\x80', startRule);
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
  unknown('Accept-Charset: ;', startRule);
  unknown('Accept-Encoding: ;', startRule);
  unknown('Accept-Language: ;', startRule);
  unknown('Accept-Ranges: ,', startRule);
  unknown('Allow: ;', startRule);
  unknown('Alt-Svc: ;', startRule);
  unknown('Authentication-Info: ;', startRule);
  unknown('Authorization: ,', startRule);
  unknown('Connection: ;', startRule);
  unknown('Content-Encoding: ;', startRule);
  unknown('Content-Language: ;', startRule);
  unknown('Content-Length: ,', startRule);
  unknown('Content-Location: //\x80', startRule);
  unknown('Content-Range: ,', startRule);
  unknown('Content-Range: bytes,', startRule);
  unknown('Content-Range: bytes ,', startRule);
  unknown('Content-Type: ,', startRule);
  unknown('Date: ,', startRule);
  unknown('ETag: ,', startRule);
  unknown('Expect: ;', startRule);
  unknown('From: ,', startRule);
  unknown('Host: {', startRule);
  unknown('If-Match: ;', startRule);
  unknown('If-Modified-Since: ,', startRule);
  unknown('If-None-Match: ;', startRule);
  unknown('If-None-Match: "foo', startRule);
  unknown('If-Range: ,', startRule);
  unknown('If-Unmodified-Since: ,', startRule);
  unknown('Last-Modified: ,', startRule);
  unknown('Location: {', startRule);
  unknown('Max-Forwards: ,', startRule);
  unknown('Proxy-Authenticate: ;', startRule);
  unknown('Proxy-Authentication-Info: ;', startRule);
  unknown('Proxy-Authorization: ,', startRule);
  unknown('Range: ,', startRule);
  unknown('Referer: {', startRule);
  unknown('Retry-After: ,', startRule);
  unknown('Server: ,', startRule);
  unknown('TE: ;', startRule);
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
      name: 'content-security-policy-report-only',
      value: "object-src 'none';base-uri 'self';script-src 'nonce-mDRix_DuLkaEeso5np47EA' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp",
      unknown: true,
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
      unknown: true,
    },
    {
      kind: 'cache-control',
      name: 'cache-control',
      value: 'public, max-age=2592000',
      unknown: true,
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
  fails('Allow', startRule);
  fails('Alt-Svc', startRule);
  fails('Authentication-Info', startRule);
  fails('Authorization', startRule);
  fails('Connection', startRule);
  fails('Content-Encoding', startRule);
  fails('Content-Language', startRule);
  fails('Content-Length', startRule);
  fails('Content-Location', startRule);
  fails('Content-Range', startRule);
  fails('Content-Type', startRule);
  fails('Date', startRule);
  fails('ETag', startRule);
  fails('Expect', startRule);
  fails('From', startRule);
  fails('Host', startRule);
  fails('If-Match', startRule);
  fails('If-Modified-Since', startRule);
  fails('If-None-Match', startRule);
  fails('If-Range', startRule);
  fails('If-Unmodified-Since', startRule);
  fails('Last-Modified', startRule);
  fails('Location', startRule);
  fails('Max-Forwards', startRule);
  fails('Proxy-Authenticate', startRule);
  fails('Proxy-Authentication-Info', startRule);
  fails('Proxy-Authorization', startRule);
  fails('Range', startRule);
  fails('Referer', startRule);
  fails('Retry-After', startRule);
  fails('Server', startRule);
  fails('TE', startRule);
  fails('Trailer', startRule);
  fails('Upgrade', startRule);
  fails('User-Agent', startRule);
  fails('Vary', startRule);
  fails('Via', startRule);
  fails('WWW-Authenticate', startRule);
  fails('unknown:   ', startRule);
});

test('Accept', () => {
  const startRule = 'Accept';
  known('*/*, test/*', startRule);

  fails('test', startRule);
  fails('test/', startRule);
  fails('*', startRule);
  fails('*/', startRule);
  fails('foo/bar;foo\x80', startRule);
  fails('foo/bar;foo=\x80', startRule);
});

test('Accept_Charset', () => {
  const startRule = 'Accept_Charset';
  fails('*?', startRule);
  fails('*?-', startRule);
  fails('*;?', startRule);
  fails('*;-', startRule);
  fails('*;q', startRule);
  fails('*;q=', startRule);
  fails('*;q=2', startRule);
  fails('*;q=0.0001', startRule);
  fails('*;q=1a', startRule);
  fails('*;q=1.a', startRule);
  fails('*;q=1.0000', startRule);
});

test('Alt_Svc', () => {
  const startRule = 'Alt_Svc';
  known('h3=":443"', startRule);
  fails('h3=":443"; ma', startRule);
  known('h3=":443";ma=1;mb=2', startRule);
  fails('h3=":443"; ma=1;mb=2;', startRule);
  fails('h3=":443"; ma=1;mb=2;mc', startRule);
  fails('h3\x80', startRule);
  fails('h3=\x80', startRule);
  fails('h3=":443"; ma=\x80', startRule);
});

test('Authorization', () => {
  const startRule = 'Authorization';
  known('foo', startRule);
  fails('\x80', startRule);
  fails('foo \x80', startRule);
});

test('Content_Language', () => {
  const startRule = 'Content_Language';
  fails('sl-rozaj-roza\x80', startRule);
  fails('x\x80', startRule);
  fails('x-', startRule);
  fails('x-abcdefghi', startRule);
  fails('x-abc\x80', startRule);
  fails('x-abc-', startRule);
  fails('x-abc-abcdefghi', startRule);
  fails('abcdefghi', startRule);
  fails('foo-abcdefghi', startRule);
  fails('foo-1a', startRule);
  fails('foo-1-a', startRule);
  fails('foo-1-aa-a', startRule);
  fails('foo-1-aa-abcdefghi', startRule);
  known('foot', startRule);
  known('footb', startRule);
  known('en-yyy', startRule);
  known('en-yyy-zzz', startRule);
  known('en-xxx-yyy-zzz', startRule);
  known('en-xx', startRule);
  known('en-xxx-yy', startRule);
  known('en-xxx-yyy-zz', startRule);
  fails('en-xxz-yy1', startRule);

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
    known(lang, startRule);
  }
});

test('Content_Location', () => {
  const startRule = 'Content_Location';
  known('http://foo:80/bar/baz/boo', startRule);
  known('foo', startRule);
  known('http://foo/bar?baz', startRule);
  known('http://$@foo/', startRule);
  known('foo?baz', startRule);
  known('/foo?baz', startRule);
  known('http:/foo?baz', startRule);
  known('file:/foo/bar/baz', startRule);
  known('file:', startRule);
  known('file:foo', startRule);
  known('file:foo/bar', startRule);
  known('file:foo/bar/baz-%ff:', startRule);
  known('foo/bar/baz', startRule);
  known('foo!', startRule);
  fails('http://foo@\x80', startRule);
  fails('http://foo/bar?/?\x80', startRule);
  fails('http://foo/bar?%f', startRule);
  fails('foo\x80', startRule);
  fails('f{', startRule);
});

test('Content_Range', () => {
  const startRule = 'Content_Range';
  fails('bytes 1-2', startRule);
  fails('bytes 1a', startRule);
  fails('bytes 1-a', startRule);
  fails('bytes 1-2/a', startRule);
  fails('bytes *', startRule);
  fails('bytes */', startRule);
  fails('bytes */a', startRule);
});

test('Content_Type', () => {
  const startRule = 'Content_Type';
  fails('foo', startRule);
  fails('foo/', startRule);
  fails('foo/\x80', startRule);
  fails('foo/bar   \x80', startRule);
  fails('foo/bar;\x80', startRule);
  fails('foo/bar;a=b;\x80', startRule);
});

test('Date', () => {
  const startRule = 'Date';
  let d = 'Sun, 06 Nov 1994 08:49:37 GMT';
  for (let i = 0; i < (d.length - 1); i++) {
    fails(d.slice(0, i), startRule);
  }
  d = 'Sunday, 06-Nov-94 08:49:37 GMT';
  for (let i = 0; i < (d.length - 1); i++) {
    fails(d.slice(0, i), startRule);
  }
  d = 'Sun Nov  6 08:49:37 1994';
  for (let i = 0; i < (d.length - 1); i++) {
    fails(d.slice(0, i), startRule);
  }
  known('Sunday, 06-Nov-94 08:49:37 GMT', startRule);
  known('Monday, 07-Nov-94 08:49:37 GMT', startRule);
  known('Tuesday, 08-Nov-94 08:49:37 GMT', startRule);
  known('Wednesday, 09-Nov-94 08:49:37 GMT', startRule);
  known('Thursday, 10-Nov-94 08:49:37 GMT', startRule);
  known('Friday, 11-Nov-94 08:49:37 GMT', startRule);
  known('Saturday, 12-Nov-94 08:49:37 GMT', startRule);

  known('Sun Nov 13 08:49:37 1994', startRule);
});

test('Expect', () => {
  const startRule = 'Expect';
  fails('100-Continue=', startRule);
  fails('100-Continue="\x80', startRule);
  fails('100-Continue="\\"', startRule);
});

test('From', () => {
  const startRule = 'From';
  known('Foo <boo@example>', startRule);
  known('<@example1.org,@example2.org:joe@example.org>', startRule);
  known('"boo"@example', startRule);
  known('"boo"."bar"@example', startRule);
  known('bar@[example]', startRule);
  known('bar@(comment)example', startRule);
  known('bar@(foo) bar. (boo) (blu)baz (boo). buzz', startRule);

  fails('', startRule);
  fails('\x80', startRule);
  fails('foo\x80', startRule);
  fails('foo@\x80', startRule);
  fails('Foo <foo@\x80', startRule);
  fails('Foo <foo@example\x80', startRule);
  fails('Foo <foo@example', startRule);
  fails('(foo) (bar)<foo@example', startRule);
  fails('Foo <"foo', startRule);
  fails('<@example1.org,@example2.org:joe@example.org', startRule);
  fails('<@:', startRule);
  fails('<\x80', startRule);
  fails('<@example1.org,@example2.org:joe@\x80', startRule);
  fails('"foo"."bar', startRule);
  fails('bar@[example\x80', startRule);
  fails('bar@[[', startRule);
});

test('Host', () => {
  const startRule = 'Host';
  known('1.2.3.4', startRule);
  known('255.240.199.84', startRule);
  known('256', startRule);
  known('266', startRule);
  known('24a', startRule);
  known('[::]', startRule);
  known('[::1]', startRule);
  known('[2001:0db8:85a3:0000:0000:8a2e:192.0.2.128]', startRule);
  known('[2001:0db8:85a3:0000:0000:8a2e:0370:7334]', startRule);
  known('[::0db8:85a3:0000:0000:8a2e:0370:7334]', startRule);
  known('[::85a3:0000:0000:8a2e:0370:7334]', startRule);
  known('[1::85a3:0000:0000:8a2e:0370:7334]', startRule);
  known('[::0000:0000:8a2e:0370:7334]', startRule);
  known('[1::0000:0000:8a2e:0370:7334]', startRule);
  known('[1:2::0000:0000:8a2e:0370:7334]', startRule);
  known('[::0000:8a2e:0370:7334]', startRule);
  known('[1::0000:8a2e:0370:7334]', startRule);
  known('[1:2::0000:8a2e:0370:7334]', startRule);
  known('[1:2:3::0000:8a2e:0370:7334]', startRule);
  known('[1::8a2e:0370:7334]', startRule);
  known('[1:2::8a2e:0370:7334]', startRule);
  known('[1:2:3::8a2e:0370:7334]', startRule);
  known('[1:2:3:4::8a2e:0370:7334]', startRule);
  known('[1::0370:7334]', startRule);
  known('[1:2::0370:7334]', startRule);
  known('[1:2:3::0370:7334]', startRule);
  known('[1:2:3:4::0370:7334]', startRule);
  known('[1:2:3:4:5::0370:7334]', startRule);
  known('[1::7334]', startRule);
  known('[1:2::7334]', startRule);
  known('[1:2:3::7334]', startRule);
  known('[1:2:3:4::7334]', startRule);
  known('[1:2:3:4:5::7334]', startRule);
  known('[1:2:3:4:5:6::7334]', startRule);
  known('[1:2:3:4:5:6::7334]', startRule);
  known('[2001::85a3:0000:0000:8a2e:0370:7334]', startRule);
  known('[::85a3:0000:0000:8a2e:0370:7334]', startRule);
  known('[2001:0db8::0000:0000:8a2e:0370:7334]', startRule);
  known('[2001::0000:0000:8a2e:0370:7334]', startRule);
  known('[::0000:0000:8a2e:0370:7334]', startRule);
  known('[2001:db8::1]', startRule);
  known('[2001:0db8::]', startRule);
  known('[2001:0db8:85a3::]', startRule);
  known('[2001:0db8:85a3:0000::]', startRule);
  known('[2001:0db8:85a3:0000:0000::]', startRule);
  known('[2001:0db8:85a3:0000:0000:8a2e::]', startRule);
  known('[2001:0db8:85a3:0000:0000:8a2e:0370::]', startRule);
  known('[va.::1]', startRule);
  known('%ff', startRule);

  fails('[::1', startRule);
  fails('\x80', startRule);
  fails('1.\x80', startRule);
  fails('1.2\x80', startRule);
  fails('1.2.\x80', startRule);
  fails('1.2.3\x80', startRule);
  fails('1.2.3.\x80', startRule);
  fails('[2001]', startRule);
  fails('[2001:0db8]', startRule);
  fails('[2001:0db8:85a]', startRule);
  fails('[2001:0db8:85a3]', startRule);
  fails('[2001:0db8:85a3:0000:0000:8a2e:0370:7334:2001]', startRule);
  fails('[2001:0db8:85a3:0000:0000:8a2e:0370:7334:2001:0db8]', startRule);
  fails('[20011]', startRule);
  fails('[aaaa:20011]', startRule);
  fails('[::\x80]', startRule);
  fails('[::1:\x80]', startRule);
  fails('[v]', startRule);
  fails('[z]', startRule);
  fails('[v\x80]', startRule);
  fails('[vaaa\x80]', startRule);
  fails('[vaaa.\x80]', startRule);
  fails('%zf', startRule);

  const d = '[2001:0db8:85a3:0000:0000:8a2e:0370:7334]';
  for (let i = 0; i < d.length; i++) {
    fails(`${d.slice(0, i)}\x80`, startRule);
  }
});

test('Location', () => {
  const startRule = 'Location';
  fails('foo\x80', startRule);
  fails('http://foo/#/\x80', startRule);
  fails('http://foo/#\x80', startRule);
  known('http://foo/#bar/', startRule);
  known('http://foo/?bar', startRule);
  known('/#bar', startRule);
  known('/?bar', startRule);
});

test('Range', () => {
  const startRule = 'Range';
  fails('bytes\x80', startRule);
  fails('bytes=', startRule);
  fails('bytes=,', startRule);
});

test('Server', () => {
  const startRule = 'Server';
  fails('', startRule);
  fails('\x80', startRule);
  fails('foo \x80', startRule);
  fails('foo bar \x80', startRule);
  fails('foo/', startRule);
  fails('foo/\x80', startRule);
  fails('foo (\\\x00', startRule);
  known('foo  \t  bar (((more comment \\))))', startRule);
});

test('TE', () => {
  const startRule = 'TE';
  known('deflate;a="foo"', startRule);
  fails('deflate\x80', startRule);
  fails('deflate;\x80', startRule);
  fails('deflate;a\x80', startRule);
  fails('deflate;a=b;\x80', startRule);
  fails('deflate;a=b;c=d;\x80', startRule);
  fails('deflate;a="foo', startRule);
});

test('Upgrade', () => {
  const startRule = 'Upgrade';
  fails('foo\x80', startRule);
  fails('foo/\x80', startRule);
});

test('User_Agent', () => {
  const startRule = 'User_Agent';
  fails('', startRule);
  fails('\x80', startRule);
  fails('foo \x80', startRule);
  fails('foo bar \x80', startRule);
});

test('Vary', () => {
  const startRule = 'Vary';
  fails('\x80', startRule);
  fails('foo, \x80', startRule);
  fails('foo, bar, \x80', startRule);
  fails('foo, *,,\x80', startRule);
});

test('Via', () => {
  const startRule = 'Via';
  fails('\x80', startRule);
  fails('1.1\x80', startRule);
  fails('1.1 \x80', startRule);
  fails('1.1 foo\x80', startRule);
  fails('1.1 foo \x80', startRule);
  fails('1.1 foo (\x80', startRule);

  fails('https/1.0 fred,\x80', startRule);
  fails('https/1.0 fred, 1.1\x80', startRule);
  fails('https/1.0 fred, 1.1 \x80', startRule);
  fails('https/1.0 fred, 1.1 foo\x80', startRule);
  fails('https/1.0 fred, 1.1 foo \x80', startRule);
  fails('https/1.0 fred, 1.1 foo (\x80', startRule);
});

test('WWW_Authenticate', () => {
  const startRule = 'WWW_Authenticate';
  fails('basic ', startRule);
  fails('\x80 ', startRule);
  fails('basic\x80', startRule);
});

test('Unknown', () => {
  const startRule = 'Unknown_Header';
  fails('f: f\u1000', startRule);
});
