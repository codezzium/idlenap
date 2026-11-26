#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
git pull --ff-only
docker --context kiri compose build
docker --context kiri compose up -d --no-build
docker --context kiri compose ps
