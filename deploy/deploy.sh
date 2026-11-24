#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
git pull --ff-only
docker --context default compose build
docker --context default save idlenap:0.2.0 | docker --context kiri load
docker --context kiri compose up -d --no-build
docker --context kiri compose ps
