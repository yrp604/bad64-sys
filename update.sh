#!/bin/sh

git fetch arch-arm64 dev
git subtree pull --prefix arch-arm64 arch-arm64 dev --squash
