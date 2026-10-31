
- 默认本机安装了node环境
- 全局工具链（不用安装在当前项目里，不写 web/package.json、不提交 web/node_modules）：
  ```sh
  npm install -g vitest happy-dom esbuild typescript
  ```
  - 全局工具链由 CMake 自动注入 `NODE_PATH`（`npm root -g`），无需在项目里安装依赖
  - `vitest`：单元测试 runner（`NODE_PATH=$(npm root -g) vitest run`）
  - `happy-dom`：vitest 的 DOM 环境（`vitest.config.mjs` 里 `environment: 'happy-dom'`，跑 WebComponent 测试用）
  - `esbuild`：TS 打包（`scripts/build_web.cjs` 把 `web/src/app.ts` 打成 `build/web-dist/ryba-web.js`，IIFE 全局 `RybaWeb`），再由 `scripts/gen_web_page.js` 拼成 `build/generated/web_page_gen.h` 内嵌进二进制
    - 入口是 `web/src/app.ts`：它持有 DOM 胶水与副作用（绑定事件、`loadAll()`、`setInterval`），是**浏览器入口**
    - `web/src/main.ts` 只是给单测 import 的纯 barrel（re-export，不碰 DOM、不发请求）；不要把 `app.ts` import 进 `main.ts`，否则任何 `import '../src/main.js'` 的单测都会跑起整页初始化（零网络规则）
    - 不开 minify：`tests/unit/test_web_page.c` 断言产物里保留 `refreshLive` / `setInterval(` 等顶层符号
  - `typescript`：类型检查（`tsc --noEmit -p web/tsconfig.json`，可选，不参与打包）
  当前验证版本：`vitest@5.0.5 / happy-dom@21.0.4 / esbuild@0.28.2 / typescript@7.0.2`
- 页面通过webcomponent 实现
- 通过vitest 和 happydom 做完整的页面组件单元测试
- 前后端分离， 通过fetch api 来调用接口
- 和当前项目组装起来 (用这种方案构建一个简单，轻量，可测试的前端方案)