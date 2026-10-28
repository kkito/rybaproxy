
- 默认本机安装了node环境
- 全局工具链（不用安装在当前项目里，不写 web/package.json、不提交 web/node_modules）：
  ```sh
  npm install -g vitest happy-dom esbuild typescript
  ```
  - `vitest`：单元测试 runner（`NODE_PATH=$(npm root -g) vitest run`）
  - `happy-dom`：vitest 的 DOM 环境（`vitest.config.mjs` 里 `environment: 'happy-dom'`，跑 WebComponent 测试用）
  - `esbuild`：TS 打包（`scripts/build_web.cjs` 把 `web/src/main.ts` 打成 `web/dist/ryba-web.js`，IIFE 全局 `RybaWeb`）
  - `typescript`：类型检查（`tsc --noEmit -p web/tsconfig.json`，可选，不参与打包）
  当前验证版本：`vitest@5.0.5 / happy-dom@21.0.4 / esbuild@0.28.2 / typescript@7.0.2`
- 页面通过webcomponent 实现
- 通过vitest 和 happydom 做完整的页面组件单元测试
- 前后端分离， 通过fetch api 来调用接口
- 和当前项目组装起来 (用这种方案构建一个简单，轻量，可测试的前端方案)