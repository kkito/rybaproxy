#!/usr/bin/env node
const fs = require('fs')
const path = require('path')

const webDir = path.join(__dirname, '..', 'web')
const dist = path.join(webDir, 'dist')
const out = path.join(__dirname, '..', 'src', 'web', 'web_page_gen.h')

function escapeC(s) {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '')
}

const htmlTpl = fs.readFileSync(path.join(webDir, 'index.html'), 'utf8')
const css = fs.readFileSync(path.join(webDir, 'style.css'), 'utf8')
const files = fs.readdirSync(dist)
const js = files.find(f => f.endsWith('.js'))
if (!js) { console.error('no js bundle'); process.exit(1) }
const jsContent = fs.readFileSync(path.join(dist, js), 'utf8')

let html = htmlTpl
  .replace('<link rel="stylesheet" href="./style.css">', `<style>\n${css}\n</style>`)
  .replace('<script src="./ryba-web.js"></script>', `<script>\n${jsContent}\n</script>`)

const content = `#ifndef RYBA_WEB_PAGE_GEN_H
#define RYBA_WEB_PAGE_GEN_H

static const char WEB_PAGE_HTML_GEN[] = "${escapeC(html)}";

#endif
`
fs.mkdirSync(path.dirname(out), { recursive: true })
fs.writeFileSync(out, content)
console.log('generated', out)
