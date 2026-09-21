#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
if [[ -z "${VERSION}" || "${VERSION}" != v* ]]; then
  echo "usage: $0 vX.Y.Z"
  exit 1
fi

docker build -f deploy/Dockerfile -t "zerohackorg/vguard:${VERSION}" .
docker tag "zerohackorg/vguard:${VERSION}" zerohackorg/vguard:latest

git tag -a "${VERSION}" -m "release ${VERSION}"
git push origin main --tags
echo "Release ${VERSION} tagged. Push to PyPI via the Release workflow on push of tag ${VERSION}."