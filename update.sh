#!/bin/sh

git fetch arch-arm64 master
git subtree pull --prefix arch-arm64 arch-arm64 master --squash
