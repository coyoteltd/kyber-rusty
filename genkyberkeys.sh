#!/bin/bash
# IMPORTANT:
# This script assumes libkyber_rusty.so is already built and placed somewhere
# that OpenResty/LuaJIT can find it via package.cpath.
#
# Common locations depending on install method:
#
# Built from source (default):
#   /usr/local/openresty/lualib/
#   /usr/local/openresty/site/lualib/
#   /usr/local/openresty/nginx/lua/
#
# System package install (apt/yum):
#   /usr/lib/lua/5.1/
#   /usr/local/lib/lua/5.1/
#
# Docker (official OpenResty images often use):
#   /usr/local/openresty/lualib/
#   /usr/local/openresty/site/lualib/
#
# Custom deployments:
#   Anywhere in package.cpath (check with: print(package.cpath))
#
# If Lua cannot find the module, you may need to:
#   - move the .so file into one of the above directories, OR
#   - extend package.cpath inside kyber.lua

/usr/local/openresty/bin/resty -e "

local kyber = require('kyber')

local pk, sk, err = kyber.keygen()
if not pk then print('ERROR: ' .. tostring(err)) return end

print('mlkem_public_key=' .. ngx.encode_base64(pk))
print('mlkem_secret_key=' .. ngx.encode_base64(sk))
"
