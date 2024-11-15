// eslint-disable-next-line n/no-unsupported-features/node-builtins
import test from 'node:test';
import {testPeggy} from '@peggyjs/coverage';

const PARSER = new URL('../lib/index.js', import.meta.url);

test('Headers', async() => {
  let startRule = '';
  await testPeggy(PARSER, [
    // #region Accept
    {
      startRule: (startRule = 'Accept'),
      validInput: 'text/html',
      validResult: {
        kind: 'accept',
        value: 'text/html',
        ranges: [
          {
            type: 'text',
            subtype: 'html',
            parameters: {},
            weight: 1,
          },
        ],
      },
      invalidInput: 'text/',
    },
    {
      validInput: ', ,,',
      validResult: {
        kind: 'accept',
        value: ', ,,',
        ranges: [],
      },
      startRule,
    },
    {
      validInput: 'text/html;encoding=utf8',
      validResult: {
        kind: 'accept',
        value: 'text/html;encoding=utf8',
        ranges: [
          {
            type: 'text',
            subtype: 'html',
            parameters: {
              encoding: 'utf8',
            },
            weight: 1,
          },
        ],
      },
      startRule,
    },
    {
      validInput: 'text/*;encoding=utf8;q=0.6',
      validResult: {
        kind: 'accept',
        value: 'text/*;encoding=utf8;q=0.6',
        ranges: [
          {
            type: 'text',
            subtype: '*',
            parameters: {
              encoding: 'utf8',
            },
            weight: 0.6,
          },
        ],
      },
      startRule,
    },

    // #region Accept_Charset
    {
      startRule: (startRule = 'Accept_Charset'),
      validInput: 'iso-8859-5, unicode-1-1;q=0.8, *',
      validResult: {
        kind: 'accept-charset',
        value: 'iso-8859-5, unicode-1-1;q=0.8, *',
        charsets: [
          {charset: 'iso-8859-5', weight: 1},
          {charset: 'unicode-1-1', weight: 0.8},
          {charset: '*', weight: 1},
        ],
      },
      invalid: '* ',
    },
    {
      startRule,
      validInput: '*',
      validResult: {
        kind: 'accept-charset',
        value: '*',
        charsets: [
          {charset: '*', weight: 1},
        ],
      },
    },

    // #region Accept_Encoding
    {
      startRule: (startRule = 'Accept_Encoding'),
      validInput: 'compress, gzip',
      validResult: {
        kind: 'accept-encoding',
        value: 'compress, gzip',
        encodings: [
          {coding: 'compress', weight: 1},
          {coding: 'gzip', weight: 1},
        ],
      },
    },
    {
      validInput: 'compress;q=0.5,, gzip;q=1.0,',
      validResult: {
        kind: 'accept-encoding',
        value: 'compress;q=0.5,, gzip;q=1.0,',
        encodings: [
          {coding: 'compress', weight: 0.5},
          {coding: 'gzip', weight: 1},
        ],
      },
      startRule,
    },
    {
      validInput: 'gzip;q=1.0, identity; q=0.5, *;q=0',
      validResult: {
        kind: 'accept-encoding',
        value: 'gzip;q=1.0, identity; q=0.5, *;q=0',
        encodings: [
          {coding: 'gzip', weight: 1},
          {coding: 'identity', weight: 0.5},
          {coding: '*', weight: 0},
        ],
      },
      startRule,
    },

    // #region Accept_Language
    {
      startRule: (startRule = 'Accept_Language'),
      validInput: 'da, en-gb;q=0.8, en;q=0.7, es',
      validResult: {
        kind: 'accept-language',
        value: 'da, en-gb;q=0.8, en;q=0.7, es',
        languages: [
          {range: ['da'], weight: 1},
          {range: ['en', 'gb'], weight: 0.8},
          {range: ['en'], weight: 0.7},
          {range: ['es'], weight: 1},
        ],
      },
    },
    {
      startRule,
      validInput: '*',
      validResult: {
        kind: 'accept-language',
        languages: [{range: ['*'], weight: 1}],
        value: '*',
      },
    },

    // #region Accept_Ranges
    {
      startRule: (startRule = 'Accept_Ranges'),
      validInput: 'bytes,, ,',
      validResult: {
        kind: 'accept-ranges',
        value: 'bytes,, ,',
        ranges: ['bytes'],
      },
    },

    // #region Allow
    {
      startRule: (startRule = 'Allow'),
      validInput: 'GET, PUT,,',
      validResult: {
        kind: 'allow',
        value: 'GET, PUT,,',
        methods: ['GET', 'PUT'],
      },
    },

    // #region Alt_Svc
    {
      startRule: (startRule = 'Alt_Svc'),
      validInput: 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000',
      validResult: {
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
      },
    },
    {
      startRule,
      validInput: 'h3=":443"; ma=2592000,,',
      validResult: {
        kind: 'alt-svc',
        value: 'h3=":443"; ma=2592000,,',
        services: [
          {
            protocol: 'h3',
            authority: ':443',
            parameters: {ma: '2592000'},
          },
        ],
      },
    },

    // #region Authentication_Info
    {
      startRule: (startRule = 'Authentication_Info'),
      validInput: 'foo=bar,boo="bla\\""',
      validResult: {
        kind: 'authentication-info',
        value: 'foo=bar,boo="bla\\""',
        params: [
          {name: 'foo', value: 'bar'},
          {name: 'boo', value: 'bla"'},
        ],
      },
    },

    // #region Authorization
    {
      startRule: (startRule = 'Authorization'),
      validInput: 'basic Zm9vOmJhcg==',
      validResult: {
        kind: 'authorization',
        value: 'basic Zm9vOmJhcg==',
        scheme: 'basic',
        token68: 'Zm9vOmJhcg==',
      },
    },
    {
      validInput: 'basic foo=bar',
      validResult: {
        kind: 'authorization',
        value: 'basic foo=bar',
        scheme: 'basic',
        params: [{name: 'foo', value: 'bar'}],
      },
      startRule,
    },

    // #region Connection
    {
      startRule: (startRule = 'Connection'),
      validInput: 'upgrade,,,',
      validResult: {
        kind: 'connection',
        value: 'upgrade,,,',
        opts: ['upgrade'],
      },
    },

    // #region Content_Encoding
    {
      startRule: (startRule = 'Content_Encoding'),
      validInput: 'gzip,,',
      validResult: {
        kind: 'content-encoding',
        value: 'gzip,,',
        encodings: ['gzip'],
      },
    },

    // #region Content_Language
    {
      // Simple language subtag
      startRule: (startRule = 'Content_Language'),
      validInput: 'de, fr, ja, i-enochian',
      validResult: {
        kind: 'content-language',
        value: 'de, fr, ja, i-enochian',
        tags: [
          {
            language: 'de',
            script: null,
            region: null,
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'fr',
            script: null,
            region: null,
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'ja',
            script: null,
            region: null,
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'i-enochian',
            script: null,
            region: null,
            variant: [],
            extension: [],
            privateuse: null,
          },
        ],
      },
    },
    {
      // Language subtag plus Script subtag
      validInput: 'zh-Hant, zh-Hans, sr-Cyrl, sr-Latn',
      validResult: {
        kind: 'content-language',
        value: 'zh-Hant, zh-Hans, sr-Cyrl, sr-Latn',
        tags: [
          {
            language: 'zh',
            script: 'Hant',
            region: null,
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'zh',
            script: 'Hans',
            region: null,
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'sr',
            script: 'Cyrl',
            region: null,
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'sr',
            script: 'Latn',
            region: null,
            variant: [],
            extension: [],
            privateuse: null,
          },
        ],
      },
      startRule,
    },
    {
      // Extended language subtags and their primary language subtag
      // counterparts
      validInput: 'zh-cmn-Hans-CN, cmn-Hans-CN, zh-yue-HK, yue-HK',
      validResult: {
        kind: 'content-language',
        value: 'zh-cmn-Hans-CN, cmn-Hans-CN, zh-yue-HK, yue-HK',
        tags: [
          {
            language: 'zh-cmn',
            script: 'Hans',
            region: 'CN',
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'cmn',
            script: 'Hans',
            region: 'CN',
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'zh-yue',
            script: null,
            region: 'HK',
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'yue',
            script: null,
            region: 'HK',
            variant: [],
            extension: [],
            privateuse: null,
          },
        ],
      },
      startRule,
    },
    {
      // Language-Script-Region
      validInput: 'zh-Hans-CN, sr-Latn-RS',
      validResult: {
        kind: 'content-language',
        value: 'zh-Hans-CN, sr-Latn-RS',
        tags: [
          {
            language: 'zh',
            script: 'Hans',
            region: 'CN',
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'sr',
            script: 'Latn',
            region: 'RS',
            variant: [],
            extension: [],
            privateuse: null,
          },
        ],
      },
      startRule,
    },
    {
      // Language-Variant
      validInput: 'sl-rozaj, sl-rozaj-biske, sl-nedis',
      validResult: {
        kind: 'content-language',
        value: 'sl-rozaj, sl-rozaj-biske, sl-nedis',
        tags: [
          {
            language: 'sl',
            script: null,
            region: null,
            variant: ['rozaj'],
            extension: [],
            privateuse: null,
          },
          {
            language: 'sl',
            script: null,
            region: null,
            variant: ['rozaj', 'biske'],
            extension: [],
            privateuse: null,
          },
          {
            language: 'sl',
            script: null,
            region: null,
            variant: ['nedis'],
            extension: [],
            privateuse: null,
          },
        ],
      },
      startRule,
    },
    {
      // Language-Region-Variant
      validInput: 'de-CH-1901, sl-IT-nedis',
      validResult: {
        kind: 'content-language',
        value: 'de-CH-1901, sl-IT-nedis',
        tags: [
          {
            language: 'de',
            script: null,
            region: 'CH',
            variant: ['1901'],
            extension: [],
            privateuse: null,
          },
          {
            language: 'sl',
            script: null,
            region: 'IT',
            variant: ['nedis'],
            extension: [],
            privateuse: null,
          },
        ],
      },
      startRule,
    },
    {
      // Language-Script-Region-Variant
      validInput: 'hy-Latn-IT-arevela,,',
      validResult: {
        kind: 'content-language',
        value: 'hy-Latn-IT-arevela,,',
        tags: [
          {
            language: 'hy',
            script: 'Latn',
            region: 'IT',
            variant: ['arevela'],
            extension: [],
            privateuse: null,
          },
        ],
      },
      startRule,
    },
    {
      // Language-Region
      validInput: 'de-DE, en-US, es-419',
      validResult: {
        kind: 'content-language',
        value: 'de-DE, en-US, es-419',
        tags: [
          {
            language: 'de',
            script: null,
            region: 'DE',
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'en',
            script: null,
            region: 'US',
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'es',
            script: null,
            region: '419',
            variant: [],
            extension: [],
            privateuse: null,
          },
        ],
      },
      startRule,
    },
    {
      // Private use subtags
      validInput: 'de-CH-x-phonebk, az-Arab-x-AZE-derbend',
      validResult: {
        kind: 'content-language',
        value: 'de-CH-x-phonebk, az-Arab-x-AZE-derbend',
        tags: [
          {
            language: 'de',
            script: null,
            region: 'CH',
            variant: [],
            extension: [],
            privateuse: 'x-phonebk',
          },
          {
            language: 'az',
            script: 'Arab',
            region: null,
            variant: [],
            extension: [],
            privateuse: 'x-AZE-derbend',
          },
        ],
      },
      startRule,
    },
    {
      // Private use registry values
      validInput: 'x-whatever, qaa-Qaaa-QM-x-southern, de-Qaaa, sr-Latn-QM, sr-Qaaa-RS',
      validResult: {
        kind: 'content-language',
        value: 'x-whatever, qaa-Qaaa-QM-x-southern, de-Qaaa, sr-Latn-QM, sr-Qaaa-RS',
        tags: [
          {
            language: null,
            script: null,
            region: null,
            variant: [],
            extension: [],
            privateuse: 'x-whatever',
          },
          {
            language: 'qaa',
            script: 'Qaaa',
            region: 'QM',
            variant: [],
            extension: [],
            privateuse: 'x-southern',
          },
          {
            language: 'de',
            script: 'Qaaa',
            region: null,
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'sr',
            script: 'Latn',
            region: 'QM',
            variant: [],
            extension: [],
            privateuse: null,
          },
          {
            language: 'sr',
            script: 'Qaaa',
            region: 'RS',
            variant: [],
            extension: [],
            privateuse: null,
          },
        ],
      },
      startRule,
    },
    {
      // Tags that use extensions
      validInput: 'en-US-u-islamcal, zh-CN-a-myext-x-private, en-a-myext-b-another',
      validResult: {
        kind: 'content-language',
        value: 'en-US-u-islamcal, zh-CN-a-myext-x-private, en-a-myext-b-another',
        tags: [
          {
            language: 'en',
            script: null,
            region: 'US',
            variant: [],
            extension: ['u-islamcal'],
            privateuse: null,
          },
          {
            language: 'zh',
            script: null,
            region: 'CN',
            variant: [],
            extension: ['a-myext'],
            privateuse: 'x-private',
          },
          {
            language: 'en',
            script: null,
            region: null,
            variant: [],
            extension: ['a-myext', 'b-another'],
            privateuse: null,
          },
        ],
      },
      startRule,
    },
    {
      invalidInput: 'de-419-DE',
      startRule,
    },
    {
      invalidInput: 'a-DE',
      startRule,
    },
    // Can't find this one with a parser, and I can't be bothered to implement
    // the semantics layer.
    // {
    //   invalidInput: 'ar-a-aaa-b-bbb-a-ccc',
    //   startRule,
    // },

    // #region Content_Length
    {
      startRule: (startRule = 'Content_Length'),
      validInput: '0',
      validResult: {
        kind: 'content-length',
        value: '0',
        length: 0,
      },
    },
    {
      validInput: '01',
      validResult: {
        kind: 'content-length',
        value: '01',
        length: 1,
      },
      startRule,
    },
    {
      validInput: '10',
      validResult: {
        kind: 'content-length',
        value: '10',
        length: 10,
      },
      startRule,
    },

    // #region Content_Location
    {
      startRule: (startRule = 'Content_Location'),
      validInput: 'https://httpwg.org/specs/rfc9110.html',
      validResult: {
        kind: 'content-location',
        value: 'https://httpwg.org/specs/rfc9110.html',
        uri: 'https://httpwg.org/specs/rfc9110.html',
        absolute: true,
      },
    },
    {
      validInput: '/specs/rfc9110.html',
      validResult: {
        kind: 'content-location',
        value: '/specs/rfc9110.html',
        uri: '/specs/rfc9110.html',
        absolute: false,
      },
      startRule,
    },

    // #region Content_Range
    {
      startRule: (startRule = 'Content_Range'),
      validInput: 'bytes 42-1233/1234',
      validResult: {
        kind: 'content-range',
        value: 'bytes 42-1233/1234',
        units: 'bytes',
        first: 42,
        last: 1233,
        complete: 1234,
      },
    },
    {
      validInput: 'bytes 42-1233/*',
      validResult: {
        kind: 'content-range',
        value: 'bytes 42-1233/*',
        units: 'bytes',
        first: 42,
        last: 1233,
        complete: NaN,
      },
      startRule,
    },
    {
      validInput: 'bytes */1234',
      validResult: {
        kind: 'content-range',
        value: 'bytes */1234',
        units: 'bytes',
        complete: 1234,
        unsatisfied: true,
      },
      startRule,
    },

    // #region Content_Type
    {
      startRule: (startRule = 'Content_Type'),
      validInput: 'text/html; charset=ISO-8859-4',
      validResult: {
        kind: 'content-type',
        value: 'text/html; charset=ISO-8859-4',
        type: 'text',
        subtype: 'html',
        parameters: {charset: 'iso-8859-4'},
      },
    },
    {
      validInput: 'text/html;charset=utf-8',
      validResult: {
        kind: 'content-type',
        value: 'text/html;charset=utf-8',
        type: 'text',
        subtype: 'html',
        parameters: {charset: 'utf-8'},
      },
      startRule,
    },
    {
      validInput: 'Text/HTML;Charset="utf-8"',
      validResult: {
        kind: 'content-type',
        value: 'Text/HTML;Charset="utf-8"',
        type: 'text',
        subtype: 'html',
        parameters: {charset: 'utf-8'},
      },
      startRule,
    },
    {
      validInput: 'text/html; charset="utf-8"',
      validResult: {
        kind: 'content-type',
        value: 'text/html; charset="utf-8"',
        type: 'text',
        subtype: 'html',
        parameters: {charset: 'utf-8'},
      },
      startRule,
    },
    {
      validInput: 'text/html;charset=UTF-8',
      validResult: {
        kind: 'content-type',
        value: 'text/html;charset=UTF-8',
        type: 'text',
        subtype: 'html',
        parameters: {charset: 'utf-8'},
      },
      startRule,
    },

    // #region Date
    {
      // IMF-fixdate
      startRule: (startRule = 'Date'),
      validInput: 'Sun, 06 Nov 1994 08:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Sun, 06 Nov 1994 08:49:37 GMT',
        date: new Date('1994-11-06T08:49:37.000Z'),
      },
    },
    {
      // Obsolete RFC 850
      startRule,
      validInput: 'Sunday, 06-Nov-94 08:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Sunday, 06-Nov-94 08:49:37 GMT',
        date: new Date('1994-11-06T08:49:37.000Z'),
      },
    },
    {
      // Obsolete asctime() format
      startRule,
      validInput: 'Sun Nov  6 08:49:37 1994',
      validResult: {
        kind: 'date',
        value: 'Sun Nov  6 08:49:37 1994',
        date: new Date('1994-11-06T08:49:37.000Z'),
      },
    },
    {
      startRule,
      validInput: 'Fri, 06 May 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Fri, 06 May 1994 07:49:37 GMT',
        date: new Date('Fri, 06 May 1994 07:49:37 GMT'),
      },
    },
    {
      startRule,
      validInput: 'Mon, 06 Jun 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Mon, 06 Jun 1994 07:49:37 GMT',
        date: new Date('Mon, 06 Jun 1994 07:49:37 GMT'),
      },
    },
    {
      startRule,
      validInput: 'Wed, 06 Jul 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Wed, 06 Jul 1994 07:49:37 GMT',
        date: new Date('Wed, 06 Jul 1994 07:49:37 GMT'),
      },
    },
    {
      startRule,
      validInput: 'Sat, 06 Aug 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Sat, 06 Aug 1994 07:49:37 GMT',
        date: new Date('Sat, 06 Aug 1994 07:49:37 GMT'),
      },
    },
    {
      startRule,
      validInput: 'Tue, 06 Sep 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Tue, 06 Sep 1994 07:49:37 GMT',
        date: new Date('Tue, 06 Sep 1994 07:49:37 GMT'),
      },
    },
    {
      startRule,
      validInput: 'Thu, 06 Oct 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Thu, 06 Oct 1994 07:49:37 GMT',
        date: new Date('Thu, 06 Oct 1994 07:49:37 GMT'),
      },
    },
    {
      startRule,
      validInput: 'Tue, 06 Dec 1994 08:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Tue, 06 Dec 1994 08:49:37 GMT',
        date: new Date('Tue, 06 Dec 1994 08:49:37 GMT'),
      },
    },

    // #region ETag
    {
      startRule: (startRule = 'ETag'),
      validInput: '"foo"',
      validResult: {
        kind: 'etag',
        value: '"foo"',
        etag: '"foo"',
      },
    },
    {
      startRule,
      validInput: 'W/"foo\x80"',
      validResult: {
        kind: 'etag',
        value: 'W/"foo\x80"',
        etag: 'W/"foo\x80"',
      },
    },
    {
      startRule,
      validInput: '""',
      validResult: {
        kind: 'etag',
        value: '""',
        etag: '""',
      },
    },

    // #region Expect
    {
      startRule: (startRule = 'Expect'),
      validInput: '100-Continue',
      validResult: {
        kind: 'expect',
        value: '100-Continue',
        expectations: [
          {token: '100-continue'},
        ],
      },
    },
    {
      startRule,
      validInput: '100-Continue=boo',
      validResult: {
        kind: 'expect',
        value: '100-Continue=boo',
        expectations: [
          {token: '100-continue', value: 'boo', parameters: {}},
        ],
      },
    },
    {
      startRule,
      validInput: '100-Continue=boo;bar=baz',
      validResult: {
        kind: 'expect',
        value: '100-Continue=boo;bar=baz',
        expectations: [
          {token: '100-continue', value: 'boo', parameters: {bar: 'baz'}},
        ],
      },
    },

    // #region From
    {
      startRule: (startRule = 'From'),
      validInput: 'spider-admin@example.org',
      validResult: {
        kind: 'from',
        value: 'spider-admin@example.org',
        address: 'spider-admin@example.org',
      },
    },
    {
      startRule,
      validInput: 'SPIDER ADMIN <spider-admin@example.org>',
      validResult: {
        kind: 'from',
        value: 'SPIDER ADMIN <spider-admin@example.org>',
        address: 'spider-admin@example.org',
      },
    },
    {
      startRule,
      validInput: 'very.common@example.com',
      validResult: {
        kind: 'from',
        value: 'very.common@example.com',
        address: 'very.common@example.com',
      },
    },
    {
      startRule,
      validInput: 'long.email-address-with-hyphens@and.subdomains.example.com',
      validResult: {
        kind: 'from',
        value: 'long.email-address-with-hyphens@and.subdomains.example.com',
        address: 'long.email-address-with-hyphens@and.subdomains.example.com',
      },
    },
    {
      startRule,
      validInput: 'user.name+tag+sorting@example.com',
      validResult: {
        kind: 'from',
        value: 'user.name+tag+sorting@example.com',
        address: 'user.name+tag+sorting@example.com',
      },
    },
    {
      startRule,
      validInput: 'name/surname@example.com',
      validResult: {
        kind: 'from',
        value: 'name/surname@example.com',
        address: 'name/surname@example.com',
      },
    },
    {
      startRule,
      validInput: '" "@example.org',
      validResult: {
        kind: 'from',
        value: '" "@example.org',
        address: '" "@example.org',
      },
    },
    {
      startRule,
      validInput: '"john..doe"@example.org',
      validResult: {
        kind: 'from',
        value: '"john..doe"@example.org',
        address: '"john..doe"@example.org',
      },
    },
    {
      startRule,
      validInput: 'mailhost!username@example.org',
      validResult: {
        kind: 'from',
        value: 'mailhost!username@example.org',
        address: 'mailhost!username@example.org',
      },
    },
    {
      startRule,
      validInput: '"very.(),:;<>[]\\".VERY.\\"very@\\\\ \\"very\\".unusual"@strange.example.com',
      validResult: {
        kind: 'from',
        value: '"very.(),:;<>[]\\".VERY.\\"very@\\\\ \\"very\\".unusual"@strange.example.com',
        address: '"very.(),:;<>[]\\".VERY.\\"very@\\\\ \\"very\\".unusual"@strange.example.com',
      },
    },
    {
      startRule,
      validInput: 'user%example.com@example.org',
      validResult: {
        kind: 'from',
        value: 'user%example.com@example.org',
        address: 'user%example.com@example.org',
      },
    },
    {
      startRule,
      validInput: 'user-@example.org',
      validResult: {
        kind: 'from',
        value: 'user-@example.org',
        address: 'user-@example.org',
      },
    },
    {
      startRule,
      validInput: 'postmaster@[123.123.123.123]',
      validResult: {
        kind: 'from',
        value: 'postmaster@[123.123.123.123]',
        address: 'postmaster@[123.123.123.123]',
      },
    },
    {
      startRule,
      validInput: 'postmaster@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
      validResult: {
        kind: 'from',
        value: 'postmaster@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
        address: 'postmaster@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
      },
    },
    {
      startRule,
      validInput: '_test@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
      validResult: {
        kind: 'from',
        value: '_test@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
        address: '_test@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
      },
    },

    // #region Host
    {
      startRule: (startRule = 'Host'),
      validInput: 'foo.bar',
      validResult: {
        kind: 'host',
        value: 'foo.bar',
        host: 'foo.bar',
        port: null,
      },
    },
    {
      startRule,
      validInput: 'foo%41.bar:80',
      validResult: {
        kind: 'host',
        value: 'foo%41.bar:80',
        host: 'fooA.bar',
        port: 80,
      },
    },
    // #region If_Match
    {
      startRule: (startRule = 'If_Match'),
      validInput: '*',
      validResult: {
        kind: 'if-match',
        value: '*',
        etags: ['*'],
      },
    },
    {
      startRule,
      validInput: '"xyzzy", "r2d2xxxx", W/"c3piozzzz",',
      validResult: {
        kind: 'if-match',
        value: '"xyzzy", "r2d2xxxx", W/"c3piozzzz",',
        etags: ['"xyzzy"', '"r2d2xxxx"', 'W/"c3piozzzz"'],
      },
    },

    // #region If_Modified_Since
    {
      startRule: (startRule = 'If_Modified_Since'),
      validInput: 'Thu, 06 Jan 1994 08:49:37 GMT',
      validResult: {
        kind: 'if-modified-since',
        value: 'Thu, 06 Jan 1994 08:49:37 GMT',
        date: new Date('Thu, 06 Jan 1994 08:49:37 GMT'),
      },
    },

    // #region If_None_Match
    {
      startRule: (startRule = 'If_None_Match'),
      validInput: '*',
      validResult: {
        kind: 'if-none-match',
        value: '*',
        etags: ['*'],
      },
    },
    {
      startRule,
      validInput: '"xyzzy", "r2d2xxxx", W/"c3piozzzz",',
      validResult: {
        kind: 'if-none-match',
        value: '"xyzzy", "r2d2xxxx", W/"c3piozzzz",',
        etags: ['"xyzzy"', '"r2d2xxxx"', 'W/"c3piozzzz"'],
      },
    },

    // #region If_Range
    {
      startRule: (startRule = 'If_Range'),
      validInput: 'W/"c3piozzzz"',
      validResult: {
        kind: 'if-range',
        value: 'W/"c3piozzzz"',
        etag: 'W/"c3piozzzz"',
      },
    },
    {
      startRule,
      validInput: 'Sun, 06 Feb 1994 08:49:37 GMT',
      validResult: {
        kind: 'if-range',
        value: 'Sun, 06 Feb 1994 08:49:37 GMT',
        date: new Date('Sun, 06 Feb 1994 08:49:37 GMT'),
      },
    },

    // #region If_Unmodified_Since
    {
      startRule: (startRule = 'If_Unmodified_Since'),
      validInput: 'Sun, 06 Mar 1994 08:49:37 GMT',
      validResult: {
        kind: 'if-unmodified-since',
        value: 'Sun, 06 Mar 1994 08:49:37 GMT',
        date: new Date('Sun, 06 Mar 1994 08:49:37 GMT'),
      },
    },

    // #region Last_Modified
    {
      startRule: (startRule = 'Last_Modified'),
      validInput: 'Wed, 06 Apr 1994 07:49:37 GMT',
      validResult: {
        kind: 'last-modified',
        value: 'Wed, 06 Apr 1994 07:49:37 GMT',
        date: new Date('Wed, 06 Apr 1994 07:49:37 GMT'),
      },
    },

    // #region Location
    {
      startRule: (startRule = 'Location'),
      validInput: '/People.html#tim',
      validResult: {
        kind: 'location',
        value: '/People.html#tim',
        uri: '/People.html#tim',
      },
    },
    {
      startRule,
      validInput: 'http://www.example.net/index.html',
      validResult: {
        kind: 'location',
        value: 'http://www.example.net/index.html',
        uri: new URL('http://www.example.net/index.html'),
      },
    },

    // #region Max_Forwards
    {
      startRule: (startRule = 'Max_Forwards'),
      validInput: '10',
      validResult: {
        kind: 'max-forwards',
        value: '10',
        max: 10,
      },
    },

    // #region Proxy_Authenticate
    {
      startRule: (startRule = 'Proxy_Authenticate'),
      validInput: 'Basic realm="simple", Newauth realm="apps", type=1, title="Login to \\"apps\\"", basic fasdasda',
      validResult: {
        kind: 'proxy-authenticate',
        value: 'Basic realm="simple", Newauth realm="apps", type=1, title="Login to \\"apps\\"", basic fasdasda',
        challenges: [
          {scheme: 'Basic', params: [{name: 'realm', value: 'simple'}]},
          {
            scheme: 'Newauth',
            params: [
              {name: 'realm', value: 'apps'},
              {name: 'type', value: '1'},
              {name: 'title', value: 'Login to "apps"'},
            ],
          },
          {scheme: 'basic', token68: 'fasdasda'},
        ],
      },
    },

    // #region Proxy_Authentication_Info
    {
      startRule: (startRule = 'Proxy_Authentication_Info'),
      validInput: 'foo=bar,boo="bla\\""',
      validResult: {
        kind: 'proxy-authentication-info',
        value: 'foo=bar,boo="bla\\""',
        params: [
          {name: 'foo', value: 'bar'},
          {name: 'boo', value: 'bla"'},
        ],
      },
    },

    // #region Proxy_Authorization
    {
      startRule: (startRule = 'Proxy_Authorization'),
      validInput: 'basic Zm9vOmJhcg==',
      validResult: {
        kind: 'proxy-authorization',
        value: 'basic Zm9vOmJhcg==',
        scheme: 'basic',
        token68: 'Zm9vOmJhcg==',
      },
    },
    {
      validInput: 'basic foo=bar',
      validResult: {
        kind: 'proxy-authorization',
        value: 'basic foo=bar',
        scheme: 'basic',
        params: [{name: 'foo', value: 'bar'}],
      },
      startRule,
    },

    // #region Range
    {
      startRule: (startRule = 'Range'),
      validInput: 'bytes=1-,1-10,-20,foo,foo-12,-12foo,12-foo,,',
      validResult: {
        kind: 'range',
        value: 'bytes=1-,1-10,-20,foo,foo-12,-12foo,12-foo,,',
        units: 'bytes',
        ranges: [
          {first: 1, last: null},
          {first: 1, last: 10},
          {first: null, last: 20},
          {other: 'foo'},
          {other: 'foo-12'},
          {other: '-12foo'},
          {other: '12-foo'},
        ],
      },
    },
    {
      startRule,
      invalidInput: 'bytes=10-1',
    },
    {
      startRule,
      invalidInput: 'bytes=10\x80',
    },
    {
      startRule,
      invalidInput: 'bytes=-\x80',
    },

    // #region Referer
    {
      startRule: (startRule = 'Referer'),
      validInput: 'https://httpwg.org/specs/rfc9110.html',
      validResult: {
        kind: 'referer',
        value: 'https://httpwg.org/specs/rfc9110.html',
        uri: 'https://httpwg.org/specs/rfc9110.html',
        absolute: true,
      },
    },
    {
      validInput: '/specs/rfc9110.html',
      validResult: {
        kind: 'referer',
        value: '/specs/rfc9110.html',
        uri: '/specs/rfc9110.html',
        absolute: false,
      },
      startRule,
    },

    // #region Retry_After
    {
      startRule: (startRule = 'Retry_After'),
      validInput: '30',
      validResult: {
        kind: 'retry-after',
        value: '30',
        seconds: 30,
      },
    },
    {
      startRule,
      validInput: 'Fri, 06 May 1994 07:49:37 GMT',
      validResult: {
        kind: 'retry-after',
        value: 'Fri, 06 May 1994 07:49:37 GMT',
        date: new Date('Fri, 06 May 1994 07:49:37 GMT'),
      },
    },

    // #region Server
    {
      startRule: (startRule = 'Server'),
      validInput: 'Foo/1.0 (bar\\) boo) Moo/2.2.2.122332',
      validResult: {
        kind: 'server',
        value: 'Foo/1.0 (bar\\) boo) Moo/2.2.2.122332',
        products: [
          {product: 'Foo', version: '1.0'},
          {comment: 'bar) boo'},
          {product: 'Moo', version: '2.2.2.122332'},
        ],
      },
    },

    // #region TE
    {
      startRule: (startRule = 'TE'),
      validInput: 'trailers, deflate;q=0.5',
      validResult: {
        kind: 'te',
        value: 'trailers, deflate;q=0.5',
        trailers: true,
        codings: [{encoding: 'deflate', parameters: {}, weight: 0.5}],
      },
    },
    {
      startRule,
      validInput: 'compress',
      validResult: {
        kind: 'te',
        value: 'compress',
        trailers: false,
        codings: [{encoding: 'compress', parameters: {}, weight: 1}],
      },
    },

    // #region Trailer
    {
      startRule: (startRule = 'Trailer'),
      validInput: 'Expires, Via',
      validResult: {
        kind: 'trailer',
        value: 'Expires, Via',
        fields: ['expires', 'via'],
      },
    },

    // #region Upgrade
    {
      startRule: (startRule = 'Upgrade'),
      validInput: 'example/1, foo/2',
      validResult: {
        kind: 'upgrade',
        value: 'example/1, foo/2',
        protocols: [
          {name: 'example', version: '1'},
          {name: 'foo', version: '2'},
        ],
      },
    },

    // #region User_Agent
    {
      startRule: (startRule = 'User_Agent'),
      validInput: 'Mozilla/5.0 (platform; rv:gecko-version) Gecko/gecko-trail Firefox/firefox-version',
      validResult: {
        kind: 'user-agent',
        value: 'Mozilla/5.0 (platform; rv:gecko-version) Gecko/gecko-trail Firefox/firefox-version',
        products: [
          {product: 'Mozilla', version: '5.0'},
          {comment: 'platform; rv:gecko-version'},
          {product: 'Gecko', version: 'gecko-trail'},
          {product: 'Firefox', version: 'firefox-version'},
        ],
      },
    },
    {
      startRule,
      validInput: 'Opera/9.80 (Macintosh; Intel Mac OS X; U; en) Presto/2.2.15 Version/10.00',
      validResult: {
        kind: 'user-agent',
        value: 'Opera/9.80 (Macintosh; Intel Mac OS X; U; en) Presto/2.2.15 Version/10.00',
        products: [
          {product: 'Opera', version: '9.80'},
          {comment: 'Macintosh; Intel Mac OS X; U; en'},
          {product: 'Presto', version: '2.2.15'},
          {product: 'Version', version: '10.00'},
        ],
      },
    },

    // #region Vary
    {
      startRule: (startRule = 'Vary'),
      validInput: '*, accept, User-Agent',
      validResult: {
        kind: 'vary',
        value: '*, accept, User-Agent',
        fields: ['*', 'accept', 'user-agent'],
      },
    },

    // #region Via
    {
      startRule: (startRule = 'Via'),
      validInput: 'https/1.0 fred (not ethel), 1.1 p.example.net:900 (such example)',
      validResult: {
        kind: 'via',
        value: 'https/1.0 fred (not ethel), 1.1 p.example.net:900 (such example)',
        path: [
          {
            protocol: 'https',
            version: '1.0',
            name: 'fred',
            port: null,
            comment: 'not ethel',
          },
          {
            protocol: null,
            version: '1.1',
            name: 'p.example.net',
            port: 900,
            comment: 'such example',
          },
        ],
      },
    },

    // #region WWW_Authenticate
    {
      startRule: (startRule = 'WWW_Authenticate'),
      validInput: 'Basic realm="simple", Newauth realm="apps", type=1, title="Login to \\"apps\\""',
      validResult: {
        kind: 'www-authenticate',
        value: 'Basic realm="simple", Newauth realm="apps", type=1, title="Login to \\"apps\\""',
        challenges: [
          {scheme: 'Basic', params: [{name: 'realm', value: 'simple'}]},
          {
            scheme: 'Newauth',
            params: [
              {name: 'realm', value: 'apps'},
              {name: 'type', value: '1'},
              {name: 'title', value: 'Login to "apps"'},
            ],
          },
        ],
      },
    },

    // #region Unknown_Header
    {
      startRule: (startRule = 'Unknown_Header'),
      validInput: 'Unk: known',
      validResult: {
        kind: 'unk',
        name: 'Unk',
        value: 'known',
        unknown: true,
      },
    },
    {
      // Bad Accept, fall through to Unknown.
      validInput: 'Accept: @@',
      validResult: {
        kind: 'accept',
        name: 'Accept',
        value: '@@',
        unknown: true,
      },
      startRule,
    },
    {
      startRule,
      validInput: 'Unk: f\tb',
      validResult: {
        kind: 'unk',
        name: 'Unk',
        value: 'f\tb',
        unknown: true,
      },
    },

    // #region Unreachable
    {
      validInput: '\t',
      validResult: '\t',
      invalidInput: ' ',
      options: {
        peg$startRuleFunction: 'peg$parseHTAB',
      },
    },
  ]);
});
