import * as esbuild from 'esbuild';

const common = { bundle: true, format: 'esm', minify: true, target: 'es2022', legalComments: 'inline' };

await esbuild.build({ ...common, entryPoints: ['vendor-entry.js'], outfile: 'dist/shvr-vendor.js' });
await esbuild.build({ ...common, entryPoints: ['scan-entry.js'], outfile: 'dist/shvr-scan.js' });
console.log('dist/shvr-vendor.js, dist/shvr-scan.js');
