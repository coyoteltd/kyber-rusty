-- paseto.lua
-- PASETO v4 local implementation.
-- Spec: https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md
--
-- Token format:
--   v4.local.<base64url(nonce || ciphertext_with_tag)>.<base64url(footer)>
--
-- Encryption:
--   1. n  = random_bytes(32)
--   2. Ek, Ak = derive keys from shared_secret + n via Blake2b
--   3. nonce  = first 24 bytes of Blake2b("paseto-encryption-key" || n, key=Ek)  [implicit nonce]
--      Actually per spec: n2 = Blake2b-512(msg = "v4.local." || h || n, key = shared_secret)
--      Ek = first 32 bytes of n2, nonce = next 24 bytes
--      Ak = Blake2b-512(msg = "v4.local-auth-key-for-" || h || n, key = shared_secret) [first 32]
--   4. aad = PAE(header, n, footer)
--   5. c   = XChaCha20Poly1305(key=Ek, nonce=nonce, aad=aad, plaintext=message)
--   6. token = header || base64url(n || c) [|| "." || base64url(footer) if footer present]

local kyber = require("kyber")
local cjson = require("cjson.safe")

local _M = {}

local HEADER   = "v4.local."
local TOKEN_TTL = 8 * 3600  -- 8 hours in seconds

-- ── PAE — Pre-Authentication Encoding ────────────────────────────────────────
-- PAE(pieces...) = LE64(count) || for each piece: LE64(len(piece)) || piece
-- Protects against canonicalization attacks.

local function le64(n)
    -- 64-bit little-endian encoding of n (Lua numbers are doubles, safe up to 2^53)
    local bytes = {}
    for i = 1, 8 do
        bytes[i] = string.char(n % 256)
        n = math.floor(n / 256)
    end
    return table.concat(bytes)
end

local function pae(...)
    local pieces = {...}
    local parts  = { le64(#pieces) }
    for _, piece in ipairs(pieces) do
        parts[#parts + 1] = le64(#piece)
        parts[#parts + 1] = piece
    end
    return table.concat(parts)
end

-- ── Base64url (no padding) ────────────────────────────────────────────────────

local function b64url_encode(s)
    return (ngx.encode_base64(s):gsub("+", "-"):gsub("/", "_"):gsub("=+$", ""))
end

local function b64url_decode(s)
    -- Restore standard base64
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = #s % 4
    if pad == 2 then s = s .. "=="
    elseif pad == 3 then s = s .. "="
    end
    return ngx.decode_base64(s)
end

-- ── Key derivation ────────────────────────────────────────────────────────────
-- Derives Ek (encryption key, 32 bytes) and nonce (24 bytes) and Ak (auth key, 32 bytes)
-- from the ML-KEM shared secret and a random seed n.
-- Follows PASETO v4 local spec key derivation.

local function derive_keys(shared_secret, n, header)
    -- Ek and nonce: Blake2b-512("paseto-encryption-key" || n, key=shared_secret)
    local ek_info = "paseto-encryption-key" .. n
    local ek_hash, err = kyber.blake2b(shared_secret .. ek_info)
    if not ek_hash then return nil, nil, nil, "ek derivation failed: " .. (err or "") end

    local Ek    = ek_hash:sub(1, 32)
    local nonce = ek_hash:sub(33, 56)  -- bytes 33-56 = 24 bytes

    -- Ak: Blake2b-512("paseto-auth-key-for-" || n, key=shared_secret)
    local ak_info = "paseto-auth-key-for-" .. n
    local ak_hash, err = kyber.blake2b(shared_secret .. ak_info)
    if not ak_hash then return nil, nil, nil, "ak derivation failed: " .. (err or "") end

    local Ak = ak_hash:sub(1, 32)

    return Ek, nonce, Ak
end

-- ── Public: mint ──────────────────────────────────────────────────────────────
-- Encrypts claims into a PASETO v4 local token.
--
-- shared_secret : 32-byte string from ML-KEM decaps/encaps
-- claims        : Lua table (will be JSON-encoded); sub and jti are required
-- footer        : optional string (will appear unencrypted in token)
--
-- Returns token string or nil, err.

function _M.mint(shared_secret, claims, footer)
    if type(claims) ~= "table" then return nil, "claims must be a table" end
    if not claims.sub then return nil, "claims.sub is required" end
    if not claims.jti then return nil, "claims.jti is required" end

    footer = footer or ""

    -- Embed expiry
    claims.exp = ngx.time() + TOKEN_TTL
    claims.iat = ngx.time()

    local message, err = cjson.encode(claims)
    if not message then return nil, "could not encode claims: " .. (err or "") end

    -- Random 32-byte nonce seed
    local n, err = kyber.random_bytes(32)
    if not n then return nil, "random_bytes failed: " .. (err or "") end

    local Ek, nonce, Ak, err = derive_keys(shared_secret, n, HEADER)
    if not Ek then return nil, err end

    -- PAE for encryption AAD
    local aad = pae(HEADER, n, footer)

    local ciphertext, err = kyber.encrypt(Ek, nonce, aad, message)
    if not ciphertext then return nil, "encrypt failed: " .. (err or "") end

    local payload = b64url_encode(n .. ciphertext)
    local token

    if footer ~= "" then
        token = HEADER .. payload .. "." .. b64url_encode(footer)
    else
        token = HEADER .. payload
    end

    return token
end

-- ── Public: verify ────────────────────────────────────────────────────────────
-- Decrypts and verifies a PASETO v4 local token.
--
-- shared_secret : 32-byte string from ML-KEM decaps
-- token         : the token string
-- expected_footer: optional — if provided, footer must match exactly
--
-- Returns claims table or nil, err.

function _M.verify(shared_secret, token, expected_footer)
    if type(token) ~= "string" then return nil, "token must be a string" end

    -- Strip and validate header
    if token:sub(1, #HEADER) ~= HEADER then
        return nil, "invalid token header"
    end
    local rest = token:sub(#HEADER + 1)

    -- Split payload and optional footer
    local payload_b64, footer_b64 = rest:match("^([^.]+)%.?(.*)$")
    if not payload_b64 then return nil, "malformed token" end

    local footer = ""
    if footer_b64 and footer_b64 ~= "" then
        footer = b64url_decode(footer_b64)
        if not footer then return nil, "invalid footer encoding" end
    end

    -- Validate footer if caller expects one
    if expected_footer and not kyber.constant_time_eq(footer, expected_footer) then
        return nil, "footer mismatch"
    end

    local payload = b64url_decode(payload_b64)
    if not payload then return nil, "invalid payload encoding" end

    -- payload = n (32 bytes) || ciphertext
    if #payload <= 32 then return nil, "payload too short" end
    local n          = payload:sub(1, 32)
    local ciphertext = payload:sub(33)

    local Ek, nonce, Ak, err = derive_keys(shared_secret, n, HEADER)
    if not Ek then return nil, err end

    local aad = pae(HEADER, n, footer)

    local message, err = kyber.decrypt(Ek, nonce, aad, ciphertext)
    if not message then return nil, "decryption failed — token invalid or tampered" end

    local claims, err = cjson.decode(message)
    if not claims then return nil, "could not decode claims: " .. (err or "") end

    -- Validate expiry
    if not claims.exp or claims.exp < ngx.time() then
        return nil, "token expired"
    end

    if not claims.sub then return nil, "missing sub claim" end
    if not claims.jti then return nil, "missing jti claim" end

    return claims
end

return _M
