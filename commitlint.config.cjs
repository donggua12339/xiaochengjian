module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      ['feat', 'fix', 'docs', 'chore', 'refactor', 'test', 'perf', 'ci', 'build', 'revert'],
    ],
    'scope-enum': [
      2,
      'always',
      ['backend', 'admin', 'sdk', 'injector', 'injector-android', 'deploy', 'docs', 'ci', 'root'],
    ],
    'subject-max-length': [2, 'always', 72],
  },
};
