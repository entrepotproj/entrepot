package server

import "runtime/debug"

func debugStack() []byte { return debug.Stack() }
