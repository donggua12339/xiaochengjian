module.exports = {
  // 后端 TypeScript
  'backend/src/**/*.ts': [
    'eslint --fix',
    'prettier --write',
  ],

  // 前端 Vue + TypeScript
  'admin-web/src/**/*.{ts,vue}': [
    'eslint --fix',
    'prettier --write',
  ],

  // Android SDK C 代码
  'sdk-android/defender-sdk/src/main/cpp/*.{c,h}': [
    'clang-format -i --style=file',
  ],

  // Kotlin(injector + sdk-android)
  '**/*.kt': [
    'ktlint -F',
  ],

  // JSON / YAML / Markdown
  '*.{json,yml,yaml,md}': [
    'prettier --write',
  ],
};
