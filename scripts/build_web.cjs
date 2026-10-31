#!/usr/bin/env node
// 用法：node scripts/build_web.cjs <输出目录>
// 由 CMake 的 ryba_web_page target 调用；输出目录必须显式传，不猜默认值。
// 入口是 web/src/app.ts（浏览器入口：DOM 胶水 + 副作用），打包成 IIFE 全局 RybaWeb。
// web/src/main.ts 只是给单测 import 的纯 barrel，不是打包入口。
// 不开 minify：单测（tests/unit/test_web_page.c）依赖产物里保留 refreshLive 等顶层符号。
const path = require('path')

const out = process.argv[2]
if (!out) {
  console.error('usage: build_web.cjs <out-dir>')
  process.exit(1)
}

let esbuild
try {
  // 全局安装的 esbuild 靠 NODE_PATH（CMake 已注入 $(npm root -g)）解析
  esbuild = require('esbuild')
} catch {
  console.error('esbuild not found: npm install -g esbuild (or set NODE_PATH=$(npm root -g))')
  process.exit(1)
}

esbuild.buildSync({
  entryPoints: [path.join(__dirname, '..', 'web', 'src', 'app.ts')],
  outfile: path.join(out, 'ryba-web.js'),
  bundle: true,
  format: 'iife',
  globalName: 'RybaWeb',
  target: ['es2020'],
  minify: false,
  sourcemap: false,
  logLevel: 'info',
})
