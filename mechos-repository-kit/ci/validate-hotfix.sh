#!/usr/bin/env bash
set -euo pipefail

# Replace or extend these generic checks with the canonical MechOS image build,
# upgrade, signature, and rollback tests. Keeping this file executable makes the
# PR guard fail closed when the real validation entrypoint is missing.
git diff --check "${GITHUB_BASE_REF:-HEAD^}" HEAD
if command -v shellcheck >/dev/null 2>&1; then
  mapfile -t scripts < <(git ls-files '*.sh')
  ((${#scripts[@]} == 0)) || shellcheck "${scripts[@]}"
fi
echo "Generic hotfix checks passed. Configure the full MechOS image gates before release."
