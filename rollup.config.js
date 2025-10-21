import resolve from '@rollup/plugin-node-resolve';
import babel from '@rollup/plugin-babel';
import terser from '@rollup/plugin-terser';

export default [
  // UMD build for browsers
  {
    input: 'src/ghostsecurity.js',
    output: {
      file: 'dist/ghostsecurity.js',
      format: 'umd',
      name: 'GhostSecurity',
      sourcemap: true,
      exports:'named'
    },
    plugins: [
      resolve(),
      babel({
        babelHelpers: 'bundled',
        presets: ['@babel/preset-env']
      })
    ]
  },
  // Minified UMD build
  {
    input: 'src/ghostsecurity.js',
    output: {
      file: 'dist/ghostsecurity.min.js',
      format: 'umd',
      name: 'GhostSecurity',
      sourcemap: true
    },
    plugins: [
      resolve(),
      babel({
        babelHelpers: 'bundled',
        presets: ['@babel/preset-env']
      }),
      terser()
    ]
  },
  // ES module build
  {
    input: 'src/ghostsecurity.js',
    output: {
      file: 'dist/ghostsecurity.esm.js',
      format: 'es',
      sourcemap: true
    },
    plugins: [
      resolve()
    ]
  },
  // CommonJS build for Node.js
  {
    input: 'src/ghostsecurity.js',
    output: {
      file: 'dist/ghostsecurity.cjs.js',
      format: 'cjs',
      sourcemap: true
    },
    plugins: [
      resolve(),
      babel({
        babelHelpers: 'bundled',
        presets: ['@babel/preset-env']
      })
    ]
  }
];
