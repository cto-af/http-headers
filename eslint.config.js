import es6 from '@cto.af/eslint-config/es6.js';
import jsdoc from '@cto.af/eslint-config/jsdoc.js';
import markdown from '@cto.af/eslint-config/markdown.js';
import mod from '@cto.af/eslint-config/module.js';
import ts from '@cto.af/eslint-config/ts.js';

export default [
  {
    ignores: [
      'lib/**',
      'docs/**',
      'src/index.js',
    ],
  },
  ...es6,
  ...mod,
  ...jsdoc,
  ...markdown,
  ...ts,
];
