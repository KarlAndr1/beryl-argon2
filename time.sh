#!/usr/bin/env sh

time beryl <<SCRIPT
	let argon2 = require "argon2"
	argon2 :encode "foobar" "123456789"
SCRIPT
