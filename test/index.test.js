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
      validInput: 'iso-8859-5, unicode-1-1;q=0.8',
      validResult: {
        kind: 'accept_charset',
        value: 'iso-8859-5, unicode-1-1;q=0.8',
        charsets: [
          {charset: 'iso-8859-5', weight: 1},
          {charset: 'unicode-1-1', weight: 0.8},
        ],
      },
    },

    // #region Accept_Encoding
    {
      startRule: (startRule = 'Accept_Encoding'),
      validInput: 'compress, gzip',
      validResult: {
        kind: 'accept_encoding',
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
        kind: 'accept_encoding',
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
        kind: 'accept_encoding',
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
      validInput: 'da, en-gb;q=0.8, en;q=0.7',
      validResult: {
        kind: 'accept_language',
        value: 'da, en-gb;q=0.8, en;q=0.7',
        languages: [
          {range: ['da'], weight: 1},
          {range: ['en', 'gb'], weight: 0.8},
          {range: ['en'], weight: 0.7},
        ],
      },
    },

    // #region Accept_Ranges
    {
      startRule: (startRule = 'Accept_Ranges'),
      validInput: 'bytes,, ,',
      validResult: {
        kind: 'accept_ranges',
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

    // #region Authentication_Info
    {
      startRule: (startRule = 'Authentication_Info'),
      validInput: 'foo=bar,boo="bla\\""',
      validResult: {
        kind: 'authentication_info',
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
        kind: 'content_encoding',
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
        kind: 'content_language',
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
        kind: 'content_language',
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
        kind: 'content_language',
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
        kind: 'content_language',
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
        kind: 'content_language',
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
        kind: 'content_language',
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
        kind: 'content_language',
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
        kind: 'content_language',
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
        kind: 'content_language',
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
        kind: 'content_language',
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
        kind: 'content_language',
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
        kind: 'content_length',
        value: '0',
        length: 0,
      },
    },
    {
      validInput: '01',
      validResult: {
        kind: 'content_length',
        value: '01',
        length: 1,
      },
      startRule,
    },
    {
      validInput: '10',
      validResult: {
        kind: 'content_length',
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
        kind: 'content_location',
        value: 'https://httpwg.org/specs/rfc9110.html',
        uri: 'https://httpwg.org/specs/rfc9110.html',
        absolute: true,
      },
    },
    {
      validInput: '/specs/rfc9110.html',
      validResult: {
        kind: 'content_location',
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
        kind: 'content_range',
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
        kind: 'content_range',
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
        kind: 'content_range',
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
        kind: 'content_type',
        value: 'text/html; charset=ISO-8859-4',
        type: 'text',
        subtype: 'html',
        parameters: {charset: 'iso-8859-4'},
      },
    },
    {
      validInput: 'text/html;charset=utf-8',
      validResult: {
        kind: 'content_type',
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
        kind: 'content_type',
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
        kind: 'content_type',
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
        kind: 'content_type',
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
  ]);
});
