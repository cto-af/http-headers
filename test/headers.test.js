import assert from 'node:assert';
import {inspect} from 'node:util';
import {parse} from '../lib/index.js';
// eslint-disable-next-line n/no-unsupported-features/node-builtins
import test from 'node:test';

function known(obj) {
  assert(obj);
  assert.equal(typeof obj, 'object');
  assert.notEqual(obj.unknown, true);
}

function unknown(obj) {
  assert(obj);
  assert.equal(typeof obj, 'object');
  assert.equal(obj.unknown, true, inspect(obj));
}

test('Header: known', () => {
  const startRule = 'Header';
  // Minimal syntax-valid headers
  assert.deepEqual(parse('Accept: ,', {startRule}), {
    kind: 'accept',
    name: 'Accept',
    ranges: [],
    value: ',',
  });
  known(parse('Accept-Charset: ,', {startRule}));
  unknown(parse('Accept-Charset: ,\x80', {startRule}));
  known(parse('Accept-Encoding: ,', {startRule}));
  known(parse('Accept-Encoding: identity,', {startRule}));
  known(parse('Accept-Language: ,', {startRule}));
  known(parse('Accept-Language: *', {startRule}));
  unknown(parse('Accept-Language: abcdefghi', {startRule}));
  unknown(parse('Accept-Language: aaa-abcdefghi', {startRule}));
  unknown(parse('Accept-Language: aaa-', {startRule}));
  known(parse('Accept-Ranges: bytes', {startRule}));
  unknown(parse('Accept-Ranges: bytes\x80', {startRule}));
  known(parse('Allow: ,', {startRule}));
  known(parse('Alt-Svc: clear', {startRule}));
  unknown(parse('Alt-Svc: clear\x80', {startRule}));
  known(parse('Authentication-Info: ,', {startRule}));
  known(parse('Authorization: basic Zm9vOmJhcg==', {startRule}));
  unknown(parse('Authorization: basic Zm9vOmJhcg==\x80', {startRule}));
  known(parse('Connection: ,', {startRule}));
  known(parse('Content-Encoding: ,', {startRule}));
  known(parse('Content-Language: ,', {startRule}));
  known(parse('Content-Length: 0', {startRule}));
  unknown(parse('Content-Length: 0\x80', {startRule}));
  known(parse('Content-Location: ,', {startRule}));
  known(parse('Content-Location: ', {startRule})); // Can't fail
  known(parse('Content-Range: bytes */0', {startRule}));
  unknown(parse('Content-Range: bytes */0\x80', {startRule}));
  known(parse('Content-Type: foo/bar', {startRule}));
  unknown(parse('Content-Type: foo/bar\x80', {startRule}));
  known(parse('Date: Sun, 06 Nov 1994 08:49:37 GMT', {startRule}));
  unknown(parse('Date: Sun, 06 Nov 1994 08:49:37 GMT\x80', {startRule}));
  known(parse('ETag: ""', {startRule}));
  unknown(parse('ETag: ""\x80', {startRule}));
  known(parse('Expect: ,', {startRule}));
  known(parse('From: a@b', {startRule}));
  unknown(parse('From: a@b\x80', {startRule}));
  known(parse('Host: ,', {startRule}));
  known(parse('Host: ', {startRule})); // Can't fail
  known(parse('If-Match: ,', {startRule}));
  known(parse('If-Match: ', {startRule})); // Can't fail
  known(parse('If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT', {startRule}));
  unknown(parse('If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\x80', {startRule}));
  known(parse('If-None-Match: ,', {startRule}));
  known(parse('If-None-Match: ', {startRule})); // Can't fail
  known(parse('If-Range: ""', {startRule}));
  unknown(parse('If-Range: ""\x80', {startRule}));
  known(parse('If-Unmodified-Since: Sun, 06 Nov 1994 08:49:37 GMT', {startRule}));
  unknown(parse('If-Unmodified-Since: Sun, 06 Nov 1994 08:49:37 GMT\x80', {startRule}));
  known(parse('Last-Modified: Sun, 06 Nov 1994 08:49:37 GMT', {startRule}));
  unknown(parse('Last-Modified: Sun, 06 Nov 1994 08:49:37 GMT\x80', {startRule}));
  known(parse('Location: /', {startRule}));
  known(parse('Location: ', {startRule})); // Can't fail
  known(parse('Max-Forwards: 0', {startRule}));
  unknown(parse('Max-Forwards: 0\x80', {startRule}));
  known(parse('Proxy-Authenticate: ,', {startRule}));
  known(parse('Proxy-Authentication-Info: ,', {startRule}));
  known(parse('Proxy-Authorization: basic Zm9vOmJhcg==', {startRule}));
  unknown(parse('Proxy-Authorization: basic Zm9vOmJhcg==\x80', {startRule}));
  known(parse('Range: bytes=-0', {startRule}));
  unknown(parse('Range: bytes=-0\x80', {startRule}));
  known(parse('Referer: ,', {startRule}));
  known(parse('Referer: ', {startRule})); // Can't fail
  known(parse('Retry-After: 0', {startRule}));
  unknown(parse('Retry-After: 0\x80', {startRule}));
  known(parse('Server: foo', {startRule}));
  unknown(parse('Server: foo\x80', {startRule}));
  known(parse('TE: ,', {startRule}));
  known(parse('Trailer: ,', {startRule}));
  known(parse('Upgrade: ,', {startRule}));
  known(parse('User-Agent: foo', {startRule}));
  unknown(parse('User-Agent: foo\x80', {startRule}));
  known(parse('Vary: ,', {startRule}));
  known(parse('Via: ,', {startRule}));
  known(parse('WWW-Authenticate: ,', {startRule}));
});

test('Header: unknown', () => {
  const startRule = 'Header';
  // All syntax-invalid, which should produce unknown:true unparsed header
  assert.deepEqual(parse('Accept: foo', {startRule}), {
    kind: 'accept',
    name: 'Accept',
    value: 'foo',
    unknown: true,
  });
  unknown(parse('Accept-Charset: ;', {startRule}));
  unknown(parse('Accept-Encoding: ;', {startRule}));
  unknown(parse('Accept-Language: ;', {startRule}));
  unknown(parse('Accept-Ranges: ,', {startRule}));
  unknown(parse('Allow: ;', {startRule}));
  unknown(parse('Alt-Svc: ;', {startRule}));
  unknown(parse('Authentication-Info: ;', {startRule}));
  unknown(parse('Authorization: ,', {startRule}));
  unknown(parse('Connection: ;', {startRule}));
  unknown(parse('Content-Encoding: ;', {startRule}));
  unknown(parse('Content-Language: ;', {startRule}));
  unknown(parse('Content-Length: ,', {startRule}));
  unknown(parse('Content-Location: //\x80', {startRule}));
  unknown(parse('Content-Range: ,', {startRule}));
  unknown(parse('Content-Range: bytes,', {startRule}));
  unknown(parse('Content-Range: bytes ,', {startRule}));
  unknown(parse('Content-Type: ,', {startRule}));
  unknown(parse('Date: ,', {startRule}));
  unknown(parse('ETag: ,', {startRule}));
  unknown(parse('Expect: ;', {startRule}));
  unknown(parse('From: ,', {startRule}));
  unknown(parse('Host: {', {startRule}));
  unknown(parse('If-Match: ;', {startRule}));
  unknown(parse('If-Modified-Since: ,', {startRule}));
  unknown(parse('If-None-Match: ;', {startRule}));
  unknown(parse('If-None-Match: "foo', {startRule}));
  unknown(parse('If-Range: ,', {startRule}));
  unknown(parse('If-Unmodified-Since: ,', {startRule}));
  unknown(parse('Last-Modified: ,', {startRule}));
  unknown(parse('Location: {', {startRule}));
  unknown(parse('Max-Forwards: ,', {startRule}));
  unknown(parse('Proxy-Authenticate: ;', {startRule}));
  unknown(parse('Proxy-Authentication-Info: ;', {startRule}));
  unknown(parse('Proxy-Authorization: ,', {startRule}));
  unknown(parse('Range: ,', {startRule}));
  unknown(parse('Referer: {', {startRule}));
  unknown(parse('Retry-After: ,', {startRule}));
  unknown(parse('Server: ,', {startRule}));
  unknown(parse('TE: ;', {startRule}));
  unknown(parse('Trailer: ;', {startRule}));
  unknown(parse('Upgrade: ;', {startRule}));
  unknown(parse('User-Agent: ,', {startRule}));
  unknown(parse('Vary: ;', {startRule}));
  unknown(parse('Via: ;', {startRule}));
  unknown(parse('WWW-Authenticate: ;', {startRule}));
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
  assert.throws(() => parse('', {startRule}));
  assert.throws(() => parse('Foo: bar', {startRule}));
  assert.throws(() => parse('Foo: bar\r', {startRule}));
  assert.throws(() => parse('Foo: bar\nBar: boo\r', {startRule}));
});

test('Header edge cases', () => {
  const startRule = 'Header';
  assert.throws(() => parse('accept-charset', {startRule}));
  assert.throws(() => parse('accept-encoding', {startRule}));
  assert.throws(() => parse('Accept-Language', {startRule}));
  assert.throws(() => parse('Accept-Ranges', {startRule}));
  assert.throws(() => parse('Allow', {startRule}));
  assert.throws(() => parse('Alt-Svc', {startRule}));
  assert.throws(() => parse('Authentication-Info', {startRule}));
  assert.throws(() => parse('Authorization', {startRule}));
  assert.throws(() => parse('Connection', {startRule}));
  assert.throws(() => parse('Content-Encoding', {startRule}));
  assert.throws(() => parse('Content-Language', {startRule}));
  assert.throws(() => parse('Content-Length', {startRule}));
  assert.throws(() => parse('Content-Location', {startRule}));
  assert.throws(() => parse('Content-Range', {startRule}));
  assert.throws(() => parse('Content-Type', {startRule}));
  assert.throws(() => parse('Date', {startRule}));
  assert.throws(() => parse('ETag', {startRule}));
  assert.throws(() => parse('Expect', {startRule}));
  assert.throws(() => parse('From', {startRule}));
  assert.throws(() => parse('Host', {startRule}));
  assert.throws(() => parse('If-Match', {startRule}));
  assert.throws(() => parse('If-Modified-Since', {startRule}));
  assert.throws(() => parse('If-None-Match', {startRule}));
  assert.throws(() => parse('If-Range', {startRule}));
  assert.throws(() => parse('If-Unmodified-Since', {startRule}));
  assert.throws(() => parse('Last-Modified', {startRule}));
  assert.throws(() => parse('Location', {startRule}));
  assert.throws(() => parse('Max-Forwards', {startRule}));
  assert.throws(() => parse('Proxy-Authenticate', {startRule}));
  assert.throws(() => parse('Proxy-Authentication-Info', {startRule}));
  assert.throws(() => parse('Proxy-Authorization', {startRule}));
  assert.throws(() => parse('Range', {startRule}));
  assert.throws(() => parse('Referer', {startRule}));
  assert.throws(() => parse('Retry-After', {startRule}));
  assert.throws(() => parse('Server', {startRule}));
  assert.throws(() => parse('TE', {startRule}));
  assert.throws(() => parse('Trailer', {startRule}));
  assert.throws(() => parse('Upgrade', {startRule}));
  assert.throws(() => parse('User-Agent', {startRule}));
  assert.throws(() => parse('Vary', {startRule}));
  assert.throws(() => parse('Via', {startRule}));
  assert.throws(() => parse('WWW-Authenticate', {startRule}));
  assert.throws(() => parse('unknown:   ', {startRule}));
});

test('Accept', () => {
  const startRule = 'Accept';
  known(parse('*/*, test/*', {startRule}));

  assert.throws(() => parse('test', {startRule}));
  assert.throws(() => parse('test/', {startRule}));
  assert.throws(() => parse('*', {startRule}));
  assert.throws(() => parse('*/', {startRule}));
  assert.throws(() => parse('foo/bar;foo\x80', {startRule}));
  assert.throws(() => parse('foo/bar;foo=\x80', {startRule}));
});

test('Accept_Charset', () => {
  const startRule = 'Accept_Charset';
  assert.throws(() => parse('*?', {startRule}));
  assert.throws(() => parse('*?-', {startRule}));
  assert.throws(() => parse('*;?', {startRule}));
  assert.throws(() => parse('*;-', {startRule}));
  assert.throws(() => parse('*;q', {startRule}));
  assert.throws(() => parse('*;q=', {startRule}));
  assert.throws(() => parse('*;q=2', {startRule}));
  assert.throws(() => parse('*;q=0.0001', {startRule}));
  assert.throws(() => parse('*;q=1a', {startRule}));
  assert.throws(() => parse('*;q=1.a', {startRule}));
  assert.throws(() => parse('*;q=1.0000', {startRule}));
});

test('Alt_Svc', () => {
  const startRule = 'Alt_Svc';
  known(parse('h3=":443"', {startRule}));
  assert.throws(() => parse('h3=":443"; ma', {startRule}));
  known(parse('h3=":443";ma=1;mb=2', {startRule}));
  assert.throws(() => parse('h3=":443"; ma=1;mb=2;', {startRule}));
  assert.throws(() => parse('h3=":443"; ma=1;mb=2;mc', {startRule}));
  assert.throws(() => parse('h3\x80', {startRule}));
  assert.throws(() => parse('h3=\x80', {startRule}));
  assert.throws(() => parse('h3=":443"; ma=\x80', {startRule}));
});

test('Authorization', () => {
  const startRule = 'Authorization';
  known(parse('foo', {startRule}));
  assert.throws(() => parse('\x80', {startRule}));
  assert.throws(() => parse('foo \x80', {startRule}));
});

test('Content_Language', () => {
  const startRule = 'Content_Language';
  assert.throws(() => parse('sl-rozaj-roza\x80', {startRule}));
  assert.throws(() => parse('x\x80', {startRule}));
  assert.throws(() => parse('x-', {startRule}));
  assert.throws(() => parse('x-abcdefghi', {startRule}));
  assert.throws(() => parse('x-abc\x80', {startRule}));
  assert.throws(() => parse('x-abc-', {startRule}));
  assert.throws(() => parse('x-abc-abcdefghi', {startRule}));
  assert.throws(() => parse('abcdefghi', {startRule}));
  assert.throws(() => parse('foo-abcdefghi', {startRule}));
  assert.throws(() => parse('foo-1a', {startRule}));
  assert.throws(() => parse('foo-1-a', {startRule}));
  assert.throws(() => parse('foo-1-aa-a', {startRule}));
  assert.throws(() => parse('foo-1-aa-abcdefghi', {startRule}));
  known(parse('foot', {startRule}));
  known(parse('footb', {startRule}));
  known(parse('en-yyy', {startRule}));
  known(parse('en-yyy-zzz', {startRule}));
  known(parse('en-xxx-yyy-zzz', {startRule}));
  known(parse('en-xx', {startRule}));
  known(parse('en-xxx-yy', {startRule}));
  known(parse('en-xxx-yyy-zz', {startRule}));
  assert.throws(() => parse('en-xxz-yy1', {startRule}));

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
    known(parse(lang, {startRule}));
  }
});

test('Content_Location', () => {
  const startRule = 'Content_Location';
  known(parse('http://foo:80/bar/baz/boo', {startRule}));
  known(parse('foo', {startRule}));
  known(parse('http://foo/bar?baz', {startRule}));
  known(parse('http://$@foo/', {startRule}));
  known(parse('foo?baz', {startRule}));
  known(parse('/foo?baz', {startRule}));
  known(parse('http:/foo?baz', {startRule}));
  known(parse('file:/foo/bar/baz', {startRule}));
  known(parse('file:', {startRule}));
  known(parse('file:foo', {startRule}));
  known(parse('file:foo/bar', {startRule}));
  known(parse('file:foo/bar/baz-%ff:', {startRule}));
  known(parse('foo/bar/baz', {startRule}));
  known(parse('foo!', {startRule}));
  assert.throws(() => parse('http://foo@\x80', {startRule}));
  assert.throws(() => parse('http://foo/bar?/?\x80', {startRule}));
  assert.throws(() => parse('http://foo/bar?%f', {startRule}));
  assert.throws(() => parse('foo\x80', {startRule}));
  assert.throws(() => parse('f{', {startRule}));
});

test('Content_Range', () => {
  const startRule = 'Content_Range';
  assert.throws(() => parse('bytes 1-2', {startRule}));
  assert.throws(() => parse('bytes 1a', {startRule}));
  assert.throws(() => parse('bytes 1-a', {startRule}));
  assert.throws(() => parse('bytes 1-2/a', {startRule}));
  assert.throws(() => parse('bytes *', {startRule}));
  assert.throws(() => parse('bytes */', {startRule}));
  assert.throws(() => parse('bytes */a', {startRule}));
});

test('Content_Type', () => {
  const startRule = 'Content_Type';
  assert.throws(() => parse('foo', {startRule}));
  assert.throws(() => parse('foo/', {startRule}));
  assert.throws(() => parse('foo/\x80', {startRule}));
  assert.throws(() => parse('foo/bar   \x80', {startRule}));
  assert.throws(() => parse('foo/bar;\x80', {startRule}));
  assert.throws(() => parse('foo/bar;a=b;\x80', {startRule}));
});

test('Date', () => {
  const startRule = 'Date';
  let d = 'Sun, 06 Nov 1994 08:49:37 GMT';
  for (let i = 0; i < (d.length - 1); i++) {
    // eslint-disable-next-line no-loop-func
    assert.throws(() => parse(d.slice(0, i), {startRule}));
  }
  d = 'Sunday, 06-Nov-94 08:49:37 GMT';
  for (let i = 0; i < (d.length - 1); i++) {
    // eslint-disable-next-line no-loop-func
    assert.throws(() => parse(d.slice(0, i), {startRule}));
  }
  d = 'Sun Nov  6 08:49:37 1994';
  for (let i = 0; i < (d.length - 1); i++) {
    assert.throws(() => parse(d.slice(0, i), {startRule}));
  }
  known(parse('Sunday, 06-Nov-94 08:49:37 GMT', {startRule}));
  known(parse('Monday, 07-Nov-94 08:49:37 GMT', {startRule}));
  known(parse('Tuesday, 08-Nov-94 08:49:37 GMT', {startRule}));
  known(parse('Wednesday, 09-Nov-94 08:49:37 GMT', {startRule}));
  known(parse('Thursday, 10-Nov-94 08:49:37 GMT', {startRule}));
  known(parse('Friday, 11-Nov-94 08:49:37 GMT', {startRule}));
  known(parse('Saturday, 12-Nov-94 08:49:37 GMT', {startRule}));

  known(parse('Sun Nov 13 08:49:37 1994', {startRule}));
});

test('Expect', () => {
  const startRule = 'Expect';
  assert.throws(() => parse('100-Continue=', {startRule}));
  assert.throws(() => parse('100-Continue="\x80', {startRule}));
  assert.throws(() => parse('100-Continue="\\"', {startRule}));
});

test('From', () => {
  const startRule = 'From';
  known(parse('Foo <boo@example>', {startRule}));
  known(parse('<@example1.org,@example2.org:joe@example.org>', {startRule}));
  known(parse('"boo"@example', {startRule}));
  known(parse('"boo"."bar"@example', {startRule}));
  known(parse('bar@[example]', {startRule}));
  known(parse('bar@(comment)example', {startRule}));
  known(parse('bar@(foo) bar. (boo) (blu)baz (boo). buzz', {startRule}));

  assert.throws(() => parse('foo\x80', {startRule}));
  assert.throws(() => parse('foo@\x80', {startRule}));
  assert.throws(() => parse('Foo <foo@\x80', {startRule}));
  assert.throws(() => parse('Foo <foo@example\x80', {startRule}));
  assert.throws(() => parse('Foo <foo@example', {startRule}));
  assert.throws(() => parse('(foo) (bar)<foo@example', {startRule}));
  assert.throws(() => parse('Foo <"foo', {startRule}));
  assert.throws(() => parse('<@example1.org,@example2.org:joe@example.org', {startRule}));
  assert.throws(() => parse('<@:', {startRule}));
  assert.throws(() => parse('<\x80', {startRule}));
  assert.throws(() => parse('<@example1.org,@example2.org:joe@\x80', {startRule}));
  assert.throws(() => parse('"foo"."bar', {startRule}));
  assert.throws(() => parse('bar@[example\x80', {startRule}));
  assert.throws(() => parse('bar@[[', {startRule}));
});

test('Host', () => {
  const startRule = 'Host';
  known(parse('1.2.3.4', {startRule}));
  known(parse('255.240.199.84', {startRule}));
  known(parse('256', {startRule}));
  known(parse('266', {startRule}));
  known(parse('24a', {startRule}));
  known(parse('[::]', {startRule}));
  known(parse('[::1]', {startRule}));
  known(parse('[2001:0db8:85a3:0000:0000:8a2e:192.0.2.128]', {startRule}));
  known(parse('[2001:0db8:85a3:0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[::0db8:85a3:0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[::85a3:0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[1::85a3:0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[::0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[1::0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[1:2::0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[::0000:8a2e:0370:7334]', {startRule}));
  known(parse('[1::0000:8a2e:0370:7334]', {startRule}));
  known(parse('[1:2::0000:8a2e:0370:7334]', {startRule}));
  known(parse('[1:2:3::0000:8a2e:0370:7334]', {startRule}));
  known(parse('[1::8a2e:0370:7334]', {startRule}));
  known(parse('[1:2::8a2e:0370:7334]', {startRule}));
  known(parse('[1:2:3::8a2e:0370:7334]', {startRule}));
  known(parse('[1:2:3:4::8a2e:0370:7334]', {startRule}));
  known(parse('[1::0370:7334]', {startRule}));
  known(parse('[1:2::0370:7334]', {startRule}));
  known(parse('[1:2:3::0370:7334]', {startRule}));
  known(parse('[1:2:3:4::0370:7334]', {startRule}));
  known(parse('[1:2:3:4:5::0370:7334]', {startRule}));
  known(parse('[1::7334]', {startRule}));
  known(parse('[1:2::7334]', {startRule}));
  known(parse('[1:2:3::7334]', {startRule}));
  known(parse('[1:2:3:4::7334]', {startRule}));
  known(parse('[1:2:3:4:5::7334]', {startRule}));
  known(parse('[1:2:3:4:5:6::7334]', {startRule}));
  known(parse('[1:2:3:4:5:6::7334]', {startRule}));
  known(parse('[2001::85a3:0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[::85a3:0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[2001:0db8::0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[2001::0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[::0000:0000:8a2e:0370:7334]', {startRule}));
  known(parse('[2001:db8::1]', {startRule}));
  known(parse('[2001:0db8::]', {startRule}));
  known(parse('[2001:0db8:85a3::]', {startRule}));
  known(parse('[2001:0db8:85a3:0000::]', {startRule}));
  known(parse('[2001:0db8:85a3:0000:0000::]', {startRule}));
  known(parse('[2001:0db8:85a3:0000:0000:8a2e::]', {startRule}));
  known(parse('[2001:0db8:85a3:0000:0000:8a2e:0370::]', {startRule}));
  known(parse('[va.::1]', {startRule}));
  known(parse('%ff', {startRule}));

  assert.throws(() => parse('[::1', {startRule}));
  assert.throws(() => parse('\x80', {startRule}));
  assert.throws(() => parse('1.\x80', {startRule}));
  assert.throws(() => parse('1.2\x80', {startRule}));
  assert.throws(() => parse('1.2.\x80', {startRule}));
  assert.throws(() => parse('1.2.3\x80', {startRule}));
  assert.throws(() => parse('1.2.3.\x80', {startRule}));
  assert.throws(() => parse('[2001]', {startRule}));
  assert.throws(() => parse('[2001:0db8]', {startRule}));
  assert.throws(() => parse('[2001:0db8:85a]', {startRule}));
  assert.throws(() => parse('[2001:0db8:85a3]', {startRule}));
  assert.throws(() => parse('[2001:0db8:85a3:0000:0000:8a2e:0370:7334:2001]', {startRule}));
  assert.throws(() => parse('[2001:0db8:85a3:0000:0000:8a2e:0370:7334:2001:0db8]', {startRule}));
  assert.throws(() => parse('[20011]', {startRule}));
  assert.throws(() => parse('[aaaa:20011]', {startRule}));
  assert.throws(() => parse('[::\x80]', {startRule}));
  assert.throws(() => parse('[::1:\x80]', {startRule}));
  assert.throws(() => parse('[v]', {startRule}));
  assert.throws(() => parse('[z]', {startRule}));
  assert.throws(() => parse('[v\x80]', {startRule}));
  assert.throws(() => parse('[vaaa\x80]', {startRule}));
  assert.throws(() => parse('[vaaa.\x80]', {startRule}));
  assert.throws(() => parse('%zf', {startRule}));

  const d = '[2001:0db8:85a3:0000:0000:8a2e:0370:7334]';
  for (let i = 0; i < d.length; i++) {
    assert.throws(() => parse(`${d.slice(0, i)}\x80`, {startRule}));
  }
});

test('Location', () => {
  const startRule = 'Location';
  assert.throws(() => parse('foo\x80', {startRule}));
  assert.throws(() => parse('http://foo/#/\x80', {startRule}));
  assert.throws(() => parse('http://foo/#\x80', {startRule}));
  known(parse('http://foo/#bar/', {startRule}));
  known(parse('http://foo/?bar', {startRule}));
  known(parse('/#bar', {startRule}));
  known(parse('/?bar', {startRule}));
});

test('Range', () => {
  const startRule = 'Range';
  assert.throws(() => parse('bytes\x80', {startRule}));
  assert.throws(() => parse('bytes=', {startRule}));
  assert.throws(() => parse('bytes=,', {startRule}));
});

test('Server', () => {
  const startRule = 'Server';
  assert.throws(() => parse('', {startRule}));
  assert.throws(() => parse('\x80', {startRule}));
  assert.throws(() => parse('foo \x80', {startRule}));
  assert.throws(() => parse('foo bar \x80', {startRule}));
  assert.throws(() => parse('foo/', {startRule}));
  assert.throws(() => parse('foo/\x80', {startRule}));
  assert.throws(() => parse('foo (\\\x00', {startRule}));
  known(parse('foo  \t  bar (((more comment \\))))', {startRule}));
});

test('TE', () => {
  const startRule = 'TE';
  known(parse('deflate;a="foo"', {startRule}));
  assert.throws(() => parse('deflate\x80', {startRule}));
  assert.throws(() => parse('deflate;\x80', {startRule}));
  assert.throws(() => parse('deflate;a\x80', {startRule}));
  assert.throws(() => parse('deflate;a=b;\x80', {startRule}));
  assert.throws(() => parse('deflate;a=b;c=d;\x80', {startRule}));
  assert.throws(() => parse('deflate;a="foo', {startRule}));
});

test('Upgrade', () => {
  const startRule = 'Upgrade';
  assert.throws(() => parse('foo\x80', {startRule}));
  assert.throws(() => parse('foo/\x80', {startRule}));
});

test('User_Agent', () => {
  const startRule = 'User_Agent';
  assert.throws(() => parse('', {startRule}));
  assert.throws(() => parse('\x80', {startRule}));
  assert.throws(() => parse('foo \x80', {startRule}));
  assert.throws(() => parse('foo bar \x80', {startRule}));
});

test('Vary', () => {
  const startRule = 'Vary';
  assert.throws(() => parse('\x80', {startRule}));
  assert.throws(() => parse('foo, \x80', {startRule}));
  assert.throws(() => parse('foo, bar, \x80', {startRule}));
  assert.throws(() => parse('foo, *,,\x80', {startRule}));
});

test('Via', () => {
  const startRule = 'Via';
  assert.throws(() => parse('\x80', {startRule}));
  assert.throws(() => parse('1.1\x80', {startRule}));
  assert.throws(() => parse('1.1 \x80', {startRule}));
  assert.throws(() => parse('1.1 foo\x80', {startRule}));
  assert.throws(() => parse('1.1 foo \x80', {startRule}));
  assert.throws(() => parse('1.1 foo (\x80', {startRule}));

  assert.throws(() => parse('https/1.0 fred,\x80', {startRule}));
  assert.throws(() => parse('https/1.0 fred, 1.1\x80', {startRule}));
  assert.throws(() => parse('https/1.0 fred, 1.1 \x80', {startRule}));
  assert.throws(() => parse('https/1.0 fred, 1.1 foo\x80', {startRule}));
  assert.throws(() => parse('https/1.0 fred, 1.1 foo \x80', {startRule}));
  assert.throws(() => parse('https/1.0 fred, 1.1 foo (\x80', {startRule}));
});

test('WWW_Authenticate', () => {
  const startRule = 'WWW_Authenticate';
  assert.throws(() => parse('basic ', {startRule}));
  assert.throws(() => parse('\x80 ', {startRule}));
  assert.throws(() => parse('basic\x80', {startRule}));
});
