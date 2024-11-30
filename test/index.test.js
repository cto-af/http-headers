// eslint-disable-next-line n/no-unsupported-features/node-builtins
import test from 'node:test';
import {testPeggy} from '@peggyjs/coverage';

const PARSER = new URL('../lib/index.js', import.meta.url);

const options = {
  obsolete: true,
};
const invalid = '\r\n';

test('Headers testPeggy', async() => {
  let startRule = '';
  const results = await testPeggy(PARSER, [
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
      options,
      invalid,
    },
    {
      validInput: ', ,,',
      validResult: {
        kind: 'accept',
        value: ', ,,',
        ranges: [],
      },
      startRule,
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      invalidInput: '* ',
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
    },
    {
      startRule,
      validInput: '*',
      validResult: {
        kind: 'accept-language',
        languages: [{range: ['*'], weight: 1}],
        value: '*',
      },
      options,
      invalid,
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
      options,
      invalid,
    },

    // #region Age
    {
      startRule: (startRule = 'Age'),
      invalidInput: '20\x80',
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
      options,
      invalid,
    },

    // #region ALPN
    {
      startRule: (startRule = 'ALPN'),
      invalidInput: 'foo, \x80',
    },
    {
      startRule,
      invalidInput: '',
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
    },

    // #region Cache_Control
    {
      startRule: (startRule = 'Cache_Control'),
      validInput: 'max-age=300, s-maxage=300, public,, no-cache="Date,Via", private="Date,Via", foo, bar=baz, BOO="BOAR"',
      validResult: {
        kind: 'cache-control',
        value: 'max-age=300, s-maxage=300, public,, no-cache="Date,Via", private="Date,Via", foo, bar=baz, BOO="BOAR"',
        controls: [
          ['max-age', 300],
          ['s-maxage', 300],
          ['public', null],
          ['no-cache', ['date', 'via']],
          ['private', ['date', 'via']],
          ['foo', null],
          ['bar', 'baz'],
          ['boo', 'BOAR'],
        ],
      },
      options,
      invalid,
    },
    {
      startRule: (startRule = 'Cache_Control'),
      validInput: 'max-age, max-age=abc, no-cache',
      validResult: {
        kind: 'cache-control',
        value: 'max-age, max-age=abc, no-cache',
        controls: [
          ['max-age', null],
          ['max-age', 'abc'],
          ['no-cache', []],
        ],
      },
      options,
      invalid,
    },
    {
      startRule,
      invalidInput: 'no-cache="',
    },
    {
      startRule,
      invalidInput: 'private\x80',
    },
    {
      startRule,
      invalidInput: 'private=\x80',
    },

    {
      startRule,
      invalidInput: 'private="',
    },
    {
      startRule,
      invalidInput: 'private="foo,\x80',
    },
    {
      startRule,
      invalidInput: 's-maxage\x80',
    },
    {
      startRule,
      invalidInput: 's-maxage=\x80',
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
    },
    {
      invalidInput: 'de-419-DE',
      startRule,
      options,
      invalid,
    },
    {
      invalidInput: 'a-DE',
      startRule,
      options,
      invalid,
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
      options,
      invalid,
    },
    {
      validInput: '01',
      validResult: {
        kind: 'content-length',
        value: '01',
        length: 1,
      },
      startRule,
      options,
      invalid,
    },
    {
      validInput: '10',
      validResult: {
        kind: 'content-length',
        value: '10',
        length: 10,
      },
      startRule,
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
    },
    {
      startRule,
      invalidInput: '',
      options: {
        obsolete: false,
        failContentLocation: true,
      },
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
    },

    // #region Content_Security_Policy
    {
      startRule: (startRule = 'Content_Security_Policy'),
      // From bing.com
      validInput: 'script-src https: \'strict-dynamic\' \'report-sample\' \'wasm-unsafe-eval\' \'nonce-4YYA6/wuMp3dRsmB0reDgiSUDofJrQu/FKWOPTvFspQ=\'; base-uri \'self\';',
      validResult: {
        kind: 'content-security-policy',
        value: "script-src https: 'strict-dynamic' 'report-sample' 'wasm-unsafe-eval' 'nonce-4YYA6/wuMp3dRsmB0reDgiSUDofJrQu/FKWOPTvFspQ='; base-uri 'self';",
        directives: [
          {
            name: 'script-src',
            values: [
              {kind: 'scheme', value: 'https:'},
              {kind: 'keyword', value: "'strict-dynamic'"},
              {kind: 'keyword', value: "'report-sample'"},
              {kind: 'keyword', value: "'wasm-unsafe-eval'"},
              {
                kind: 'nonce',
                value: "'nonce-4YYA6/wuMp3dRsmB0reDgiSUDofJrQu/FKWOPTvFspQ='",
              },
            ],
          },
          {name: 'base-uri', values: [{kind: 'keyword', value: "'self'"}]},
        ],
      },
      invalid,
    },
    {
      startRule,
      invalidInput: 'foo, bar\x00',
      options: {
        peg$silentFails: -1,
      },
    },
    {
      invalidInput: '//',
      options: {
        peg$startRuleFunction: 'peg$parsehier_part_csp',
        peg$failAfter: {
          peg$parseauthority_csp: 0,
        },
      },
    },
    {
      invalidInput: '//foo',
      options: {
        peg$startRuleFunction: 'peg$parserelative_part_csp',
        peg$failAfter: {
          peg$parseauthority_csp: 0,
        },
      },
    },
    {
      invalidInput: 'report-uri // foo',
      options: {
        peg$startRuleFunction: 'peg$parsereport_uri_directive',
        peg$failAfter: {
          peg$parseURI_reference_csp: 0,
        },
      },
    },
    {
      invalidInput: 'report-uri // foo',
      options: {
        peg$startRuleFunction: 'peg$parsereport_uri_directive',
        peg$failAfter: {
          peg$parseURI_reference_csp: 1,
        },
      },
    },
    {
      invalidInput: '',
      options: {
        peg$startRuleFunction: 'peg$parseauthority_csp',
        peg$failAfter: {
          peg$parseuri_host_csp: 0,
        },
      },
    },
    {
      invalidInput: "'nonce-foo\x00",
      options: {
        peg$startRuleFunction: 'peg$parsenonce_source',
        peg$failAfter: {
          peg$parsebase64_value: 0,
        },
      },
    },
    {
      invalidInput: "'sha256-foo\x00",
      options: {
        peg$startRuleFunction: 'peg$parsehash_source',
        peg$failAfter: {
          peg$parsebase64_value: 0,
        },
      },
    },
    {
      invalidInput: 'foo:\x00',
      options: {
        peg$startRuleFunction: 'peg$parsescheme_source',
        peg$silentFails: -1,
      },
    },
    {
      validInput: '',
      validResult: null,
      options: {
        peg$startRuleFunction: 'peg$parsehier_part_csp',
      },
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'Fri, 06 May 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Fri, 06 May 1994 07:49:37 GMT',
        date: new Date('Fri, 06 May 1994 07:49:37 GMT'),
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'Mon, 06 Jun 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Mon, 06 Jun 1994 07:49:37 GMT',
        date: new Date('Mon, 06 Jun 1994 07:49:37 GMT'),
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'Wed, 06 Jul 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Wed, 06 Jul 1994 07:49:37 GMT',
        date: new Date('Wed, 06 Jul 1994 07:49:37 GMT'),
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'Sat, 06 Aug 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Sat, 06 Aug 1994 07:49:37 GMT',
        date: new Date('Sat, 06 Aug 1994 07:49:37 GMT'),
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'Tue, 06 Sep 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Tue, 06 Sep 1994 07:49:37 GMT',
        date: new Date('Tue, 06 Sep 1994 07:49:37 GMT'),
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'Thu, 06 Oct 1994 07:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Thu, 06 Oct 1994 07:49:37 GMT',
        date: new Date('Thu, 06 Oct 1994 07:49:37 GMT'),
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'Tue, 06 Dec 1994 08:49:37 GMT',
      validResult: {
        kind: 'date',
        value: 'Tue, 06 Dec 1994 08:49:37 GMT',
        date: new Date('Tue, 06 Dec 1994 08:49:37 GMT'),
      },
      options,
      invalid,
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
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'W/"foo\x80"',
      validResult: {
        kind: 'etag',
        value: 'W/"foo\x80"',
        etag: 'W/"foo\x80"',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: '""',
      validResult: {
        kind: 'etag',
        value: '""',
        etag: '""',
      },
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
    },

    // #region Expires
    {
      startRule: (startRule = 'Expires'),
      invalidInput: 'Sun, 06 Nov 1994 08:49:37 GMT\x80',
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
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'SPIDER ADMIN <spider-admin@example.org>',
      validResult: {
        kind: 'from',
        value: 'SPIDER ADMIN <spider-admin@example.org>',
        address: 'spider-admin@example.org',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'very.common@example.com',
      validResult: {
        kind: 'from',
        value: 'very.common@example.com',
        address: 'very.common@example.com',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'long.email-address-with-hyphens@and.subdomains.example.com',
      validResult: {
        kind: 'from',
        value: 'long.email-address-with-hyphens@and.subdomains.example.com',
        address: 'long.email-address-with-hyphens@and.subdomains.example.com',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'user.name+tag+sorting@example.com',
      validResult: {
        kind: 'from',
        value: 'user.name+tag+sorting@example.com',
        address: 'user.name+tag+sorting@example.com',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'name/surname@example.com',
      validResult: {
        kind: 'from',
        value: 'name/surname@example.com',
        address: 'name/surname@example.com',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: '" "@example.org',
      validResult: {
        kind: 'from',
        value: '" "@example.org',
        address: '" "@example.org',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: '"john..doe"@example.org',
      validResult: {
        kind: 'from',
        value: '"john..doe"@example.org',
        address: '"john..doe"@example.org',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'mailhost!username@example.org',
      validResult: {
        kind: 'from',
        value: 'mailhost!username@example.org',
        address: 'mailhost!username@example.org',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: '"very.(),:;<>[]\\".VERY.\\"very@\\\\ \\"very\\".unusual"@strange.example.com',
      validResult: {
        kind: 'from',
        value: '"very.(),:;<>[]\\".VERY.\\"very@\\\\ \\"very\\".unusual"@strange.example.com',
        address: '"very.(),:;<>[]\\".VERY.\\"very@\\\\ \\"very\\".unusual"@strange.example.com',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'user%example.com@example.org',
      validResult: {
        kind: 'from',
        value: 'user%example.com@example.org',
        address: 'user%example.com@example.org',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'user-@example.org',
      validResult: {
        kind: 'from',
        value: 'user-@example.org',
        address: 'user-@example.org',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'postmaster@[123.123.123.123]',
      validResult: {
        kind: 'from',
        value: 'postmaster@[123.123.123.123]',
        address: 'postmaster@[123.123.123.123]',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'postmaster@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
      validResult: {
        kind: 'from',
        value: 'postmaster@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
        address: 'postmaster@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: '_test@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
      validResult: {
        kind: 'from',
        value: '_test@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
        address: '_test@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
      },
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
    },
    {
      startRule,
      invalidInput: '',
      options: {
        peg$failAfter: {
          peg$parseuri_host: 0,
        },
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
      options,
      invalid,
    },
    {
      startRule,
      validInput: '"xyzzy", "r2d2xxxx", W/"c3piozzzz",',
      validResult: {
        kind: 'if-match',
        value: '"xyzzy", "r2d2xxxx", W/"c3piozzzz",',
        etags: ['"xyzzy"', '"r2d2xxxx"', 'W/"c3piozzzz"'],
      },
      options,
      invalid,
    },
    {
      startRule,
      invalidInput: '',
      options: {
        ...options,
        peg$failAfter: {
          peg$parseetags_list: 0,
        },
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
      options,
      invalid,
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
      options,
      invalid,
    },
    {
      startRule,
      validInput: '"xyzzy", "r2d2xxxx", W/"c3piozzzz",',
      validResult: {
        kind: 'if-none-match',
        value: '"xyzzy", "r2d2xxxx", W/"c3piozzzz",',
        etags: ['"xyzzy"', '"r2d2xxxx"', 'W/"c3piozzzz"'],
      },
      options,
      invalid,
    },
    {
      startRule,
      invalidInput: '',
      options: {
        ...options,
        peg$failAfter: {
          peg$parseetags_list: 0,
        },
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
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'Sun, 06 Feb 1994 08:49:37 GMT',
      validResult: {
        kind: 'if-range',
        value: 'Sun, 06 Feb 1994 08:49:37 GMT',
        date: new Date('Sun, 06 Feb 1994 08:49:37 GMT'),
      },
      options,
      invalid,
    },
    {
      startRule,
      invalidInput: 'Sun, 06 Feb 1994 08:49:37 GMT\x80',
      options,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'http://www.example.net/index.html',
      validResult: {
        kind: 'location',
        value: 'http://www.example.net/index.html',
        uri: new URL('http://www.example.net/index.html'),
      },
      options,
      invalid,
    },
    {
      startRule,
      invalidInput: '',
      options: {
        peg$failAfter: {
          peg$parseURI_reference: 0,
        },
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
      options,
      invalid,
    },

    // #region Permissions_Policy
    {
      startRule: (startRule = 'Permissions_Policy'),
      validInput: 'fullscreen=(), geolocation=()',
      validResult: {
        kind: 'permissions-policy',
        value: 'fullscreen=(), geolocation=()',
        directives: [
          ['fullscreen', {items: []}],
          ['geolocation', {items: []}],
        ],
      },
      invalid,
    },
    {
      startRule,
      validInput: 'geolocation=(self "https://example.com")',
      validResult: {
        kind: 'permissions-policy',
        value: 'geolocation=(self "https://example.com")',
        directives: [
          [
            'geolocation',
            {
              items: [{item: 'self'}, {item: 'https://example.com'}],
            },
          ],
        ],
      },
      invalid,
    },
    {
      invalidInput: 'foo;b',
      options: {
        peg$startRuleFunction: 'peg$parsesf_dict_member',
        peg$failAfter: {
          peg$parsesf_parameters: 0,
        },
      },
    },
    {
      invalidInput: ';foo;b',
      options: {
        peg$startRuleFunction: 'peg$parsesf_parameters',
        peg$failAfter: {
          peg$parsesf_parameter: 1,
        },
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'bytes=10-1',
      validResult: {
        kind: 'range',
        value: 'bytes=10-1',
        ranges: [{other: '10-1'}],
        units: 'bytes',
      },
      options,
      invalid,
    },
    {
      startRule,
      invalidInput: 'bytes=10\x80',
      options,
    },
    {
      startRule,
      invalidInput: 'bytes=-\x80',
      options,
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
      options,
      invalid,
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
      options,
      invalid,
    },
    {
      startRule,
      invalidInput: '',
      options: {
        failReferer: true,
      },
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
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'Fri, 06 May 1994 07:49:37 GMT',
      validResult: {
        kind: 'retry-after',
        value: 'Fri, 06 May 1994 07:49:37 GMT',
        date: new Date('Fri, 06 May 1994 07:49:37 GMT'),
      },
      options,
      invalid,
    },
    {
      startRule,
      invalidInput: 'Fri, 06 May 1994 07:49:37 GMT\x80',
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
      options,
      invalid,
    },

    // # Region Set_Cookie
    {
      startRule: (startRule = 'Set_Cookie'),
      validInput: 'lang=en-US;Expires=Wed, 09 Jun 2021 10:18:14 GMT; max-age=20; HttpOnly',
      validResult: {
        kind: 'set-cookie',
        value: 'lang=en-US;Expires=Wed, 09 Jun 2021 10:18:14 GMT; max-age=20; HttpOnly',
        cookieName: 'lang',
        cookieValue: 'en-US',
        attributes: [
          ['expires', new Date('Wed, 09 Jun 2021 10:18:14 GMT')],
          ['max-age', 20],
          ['httponly', null],
        ],
      },
      options,
      invalid,
    },
    {
      startRule,
      validInput: 'foo=bar',
      validResult: {
        kind: 'set-cookie',
        value: 'foo=bar',
        cookieName: 'foo',
        cookieValue: 'bar',
        attributes: [],
      },
      invalid,
    },
    {
      startRule,
      invalidInput: 'foo',
    },
    {
      startRule,
      invalidInput: 'foo=\x00',
    },
    {
      startRule,
      invalidInput: 'foo="\x00',
    },
    {
      startRule,
      invalidInput: 'foo="bar',
    },
    {
      startRule,
      invalidInput: 'foo="a\x00',
    },
    {
      startRule,
      invalidInput: 'foo=bar3',
      options: {
        peg$failAfter: {
          peg$parsecookie_value: 0,
        },
      },
    },
    {
      startRule,
      invalidInput: 'foo=bar; Expires=\x00',
    },
    {
      startRule,
      invalidInput: 'foo=bar; max-age=a\x00',
    },
    {
      startRule,
      invalidInput: 'foo=bar; domain=\x00',
    },
    {
      startRule,
      invalidInput: 'foo=bar; path=\x00',
    },
    {
      startRule,
      invalidInput: 'foo=bar; HttpOnlo\x00',
    },

    // #region Strict_Transport_Security
    {
      startRule: (startRule = 'Strict_Transport_Security'),
      invalidInput: '\x80',
    },
    {
      startRule,
      invalidInput: 'foo; \x80',
    },
    {
      startRule,
      validInput: 'max-age',
      validResult: {
        kind: 'strict-transport-security',
        value: 'max-age',
        directives: [
          ['max-age', null],
        ],
      },
      invalid,
    },
    {
      startRule,
      validInput: 'max-age=a',
      validResult: {
        kind: 'strict-transport-security',
        value: 'max-age=a',
        directives: [
          ['max-age', 'a'],
        ],
      },
      invalid,
    },
    {
      startRule,
      invalidInput: 'foo=',
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      options,
      invalid,
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
      startRule: 'Header',
      options,
      invalid,
    },
    {
      invalidInput: 'Content-Location: ',
      startRule: 'Header',
      options: {
        obsolete: false,
        peg$failAfter: {
          peg$parseContent_Location: 0,
        },
      },
      invalid,
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
      options,
      invalid,
    },

    // #region Unreachable
    {
      validInput: '\t',
      validResult: '\t',
      invalidInput: ' ',
      options: {
        peg$startRuleFunction: 'peg$parseHTAB',
        obsolete: true,
      },
      invalid,
    },

    // #region Random stuff
    {
      invalidInput: '//',
      options: {
        peg$startRuleFunction: 'peg$parsehier_part',
        peg$failAfter: {
          peg$parseauthority: 0,
        },
      },
    },
    {
      invalidInput: '//',
      options: {
        peg$startRuleFunction: 'peg$parserelative_part',
        peg$failAfter: {
          peg$parseauthority: 0,
        },
      },
    },
    {
      invalidInput: '',
      options: {
        peg$startRuleFunction: 'peg$parseobs_date',
        peg$failAfter: {
          peg$parseOBS: 0,
        },
      },
    },
    {
      invalidInput: '',
      options: {
        peg$startRuleFunction: 'peg$parseaddr_spec',
        peg$failAfter: {
          peg$parselocal_part: 0,
        },
      },
    },
    {
      invalidInput: '',
      options: {
        peg$startRuleFunction: 'peg$parseauthority',
        peg$failAfter: {
          peg$parseuri_host: 0,
        },
      },
    },
    {
      invalidInput: '-aaa-aaaa',
      options: {
        peg$startRuleFunction: 'peg$parselangextss',
      },
    },
    {
      validInput: 'foo foo foo',
      validResult: [
        'foo',
        'foo',
        'foo',
      ],
      options: {
        peg$startRuleFunction: 'peg$parsephrase',
      },
    },
    {
      invalidInput: '',
      options: {
        peg$startRuleFunction: 'peg$parseobs_angle_addr',
      },
    },
    {
      invalidInput: '',
      options: {
        peg$startRuleFunction: 'peg$parseobs_local_part',
        peg$failAfter: {
          peg$parseOBS: 0,
        },
      },
    },
    {
      invalidInput: 'foo',
      options: {
        obsolete: false,
        peg$startRuleFunction: 'peg$parseobs_domain',
      },
    },
    {
      invalidInput: 'foo.foo.foo.',
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_domain',
      },
    },
    {
      validInput: 'foo clap clap . foo "boo" baz',
      validResult: [
        undefined,
        'foo',
        [
          'clap',
          'clap',
          '.',
          'foo',
          'boo',
          'baz',
        ],
      ],
      //
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_phrase',
      },
    },
    {
      validInput: '   \r\n   \r\n   ',
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_FWS',
      },
    },
    {
      invalidInput: '   \r\n   \r\n',
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_FWS',
      },
    },
    {
      validInput: ',,,@foo',
      validResult: [['foo']],
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_domain_list',
      },
    },
    {
      invalidInput: ',,,@foo,',
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_domain_list',
      },
    },
    {
      invalidInput: ',,,@foo,@',
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_domain_list',
      },
    },
    {
      invalidInput: '',
      options: {
        peg$startRuleFunction: 'peg$parseobs_domain_list',
      },
    },
    {
      invalidInput: '\\\x80',
      options: {
        peg$startRuleFunction: 'peg$parseemail_quoted_pair',
      },
    },
    {
      validInput: '\x7f',
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_dtext',
      },
    },
    {
      invalidInput: '',
      options: {
        obsolete: false,
        peg$startRuleFunction: 'peg$parseobs_dtext',
      },
    },
    {
      invalidInput: '',
      options: {
        obsolete: false,
        peg$startRuleFunction: 'peg$parseobs_qtext',
      },
    },
    {
      validInput: '\x7f',
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_qtext',
      },
    },
    {
      invalidInput: '\\',
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_qp',
      },
    },
    {
      validInput: '\\\x00',
      validResult: '\x00',
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_qp',
      },
    },
    {
      invalidInput: '',
      options: {
        obsolete: false,
        peg$startRuleFunction: 'peg$parseobs_ctext',
      },
    },
    {
      validInput: '\x7f',
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_ctext',
      },
    },
    {
      invalidInput: '\x80',
      options: {
        peg$startRuleFunction: 'peg$parsetchar',
      },
    },
    {
      invalidInput: '\x80',
      options: {
        peg$silentFails: -1,
        peg$startRuleFunction: 'peg$parsetoken68',
      },
    },
    {
      invalidInput: 'a\x80',
      options: {
        peg$silentFails: -1,
        peg$startRuleFunction: 'peg$parsetoken68',
      },
    },
    {
      invalidInput: 'a=\x80',
      options: {
        peg$silentFails: -1,
        peg$startRuleFunction: 'peg$parsetoken68',
      },
    },
    {
      invalidInput: '"a"',
      options: {
        peg$silentFails: -1,
        peg$startRuleFunction: 'peg$parselocal_part',
      },
    },
    {
      invalidInput: '1-10  \x80',
      options: {
        peg$silentFails: -1,
        peg$startRuleFunction: 'peg$parseint_range',
      },
    },
    {
      invalidInput: '-10  \x80',
      options: {
        peg$silentFails: -1,
        peg$startRuleFunction: 'peg$parsesuffix_range',
      },
    },
    {
      invalidInput: '( \x80',
      options: {
        peg$startRuleFunction: 'peg$parseemail_comment',
      },
    },
    {
      invalidInput: '@foo',
      options: {
        obsolete: true,
        peg$startRuleFunction: 'peg$parseobs_route',
      },
    },
    {
      invalidInput: 'foo.',
      options: {
        peg$startRuleFunction: 'peg$parsedot_atom_text',
      },
    },
    {
      invalidInput: '\r\x80',
      options: {
        peg$startRuleFunction: 'peg$parseCRLF',
      },
    },
    {
      validInput: '',
      validResult: undefined,
      options: {
        peg$silentFails: -1,
        peg$startRuleFunction: 'peg$parseEOL',
      },
      invalid: '',
    },
    {
      invalidInput: 'f;',
      options: {
        peg$silentFails: -1,
        peg$startRuleFunction: 'peg$parsesf_token',
      },
    },
    {
      validInput: 'a',
      invalidInput: 'A',
      options: {
        peg$startRuleFunction: 'peg$parselcalpha',
      },
    },
    {
      invalidInput: '<http',
      options: {
        peg$startRuleFunction: 'peg$parselink_value',
        peg$failAfter: {
          peg$parseURI_reference: 0,
        },
      },
    },
    {
      invalidInput: 'http://*',
      options: {
        peg$startRuleFunction: 'peg$parseserialized_origin',
        peg$failAfter: {
          peg$parseuri_host: 0,
        },
      },
    },
  ]);
  delete results.grammarPath;
  delete results.modifiedPath;
  // eslint-disable-next-line no-console
  console.log(results);
});
