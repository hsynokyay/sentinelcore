#!/bin/sh
export PATH="/opt/homebrew/Cellar/node/25.6.0/bin:$PATH"
exec node node_modules/.bin/next dev "$@"
