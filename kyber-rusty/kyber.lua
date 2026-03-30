local ffi = require("ffi")

ffi.cdef[[
    size_t mlkem768_public_key_bytes();
    size_t mlkem768_secret_key_bytes();
    size_t mlkem768_ciphertext_bytes();
    size_t mlkem768_shared_secret_bytes();
    size_t xchacha20poly1305_key_bytes();
    size_t xchacha20poly1305_nonce_bytes();
    size_t xchacha20poly1305_tag_bytes();
    size_t blake2b_512_bytes();

    int32_t mlkem768_keygen(
        uint8_t *public_key_out,  size_t public_key_out_len,
        uint8_t *secret_key_out,  size_t secret_key_out_len
    );
    int32_t mlkem768_encaps(
        const uint8_t *public_key,        size_t public_key_len,
        uint8_t       *ciphertext_out,    size_t ciphertext_out_len,
        uint8_t       *shared_secret_out, size_t shared_secret_out_len
    );
    int32_t mlkem768_decaps(
        const uint8_t *secret_key,        size_t secret_key_len,
        const uint8_t *ciphertext,        size_t ciphertext_len,
        uint8_t       *shared_secret_out, size_t shared_secret_out_len
    );

    int32_t blake2b_512_hash(
        const uint8_t *input,  size_t input_len,
        uint8_t       *output, size_t output_len
    );

    int32_t xchacha20poly1305_encrypt(
        const uint8_t *key,            size_t key_len,
        const uint8_t *nonce,          size_t nonce_len,
        const uint8_t *aad,            size_t aad_len,
        const uint8_t *plaintext,      size_t plaintext_len,
        uint8_t       *ciphertext_out, size_t ciphertext_out_len
    );
    int32_t xchacha20poly1305_decrypt(
        const uint8_t *key,           size_t key_len,
        const uint8_t *nonce,         size_t nonce_len,
        const uint8_t *aad,           size_t aad_len,
        const uint8_t *ciphertext,    size_t ciphertext_len,
        uint8_t       *plaintext_out, size_t plaintext_out_len
    );

    int32_t random_bytes(uint8_t *out, size_t out_len);
    int32_t constant_time_eq(
        const uint8_t *a, size_t a_len,
        const uint8_t *b, size_t b_len
    );
]]

local function file_exists(path)
    local f = io.open(path, "rb")
    if f then
        f:close()
        return true
    end
    return false
end

local function dirname(path)
    if not path or path == "" then
        return "."
    end
    return (path:match("^(.*)[/\\][^/\\]*$")) or "."
end

local function current_file_dir()
    local info = debug and debug.getinfo and debug.getinfo(1, "S")
    if not info or not info.source then
        return "."
    end

    local source = info.source
    if source:sub(1, 1) == "@" then
        return dirname(source:sub(2))
    end

    return "."
end

local function unique_paths(paths)
    local out = {}
    local seen = {}

    for _, p in ipairs(paths) do
        if p and p ~= "" and not seen[p] then
            seen[p] = true
            out[#out + 1] = p
        end
    end

    return out
end

local function candidate_library_paths()
    local here = current_file_dir()
    local env_path = os.getenv("KYBER_RUSTY_LIB")
    local package_cpath = package.cpath or ""

    local names = {
        env_path,
        "kyber_rusty",
        "libkyber_rusty.so",
        here .. "/libkyber_rusty.so",
        here .. "/lib/kyber_rusty.so",
        here .. "/lib/libkyber_rusty.so",
        "/usr/local/lib/libkyber_rusty.so",
        "/usr/lib/libkyber_rusty.so",
    }

    for template in package_cpath:gmatch("[^;]+") do
        local candidate = template:gsub("%?", "libkyber_rusty")
        names[#names + 1] = candidate
    end

    return unique_paths(names)
end

local function load_library()
    local attempts = {}

    for _, candidate in ipairs(candidate_library_paths()) do
        local ok, lib = pcall(ffi.load, candidate)
        if ok then
            return lib, candidate
        end

        attempts[#attempts + 1] = tostring(candidate)
    end

    error(
        "Unable to load libkyber_rusty.so. " ..
        "Set KYBER_RUSTY_LIB to the full path of the shared library, " ..
        "place the library next to this Lua file, or install it in a standard library path. " ..
        "Attempted: " .. table.concat(attempts, ", ")
    )
end

local C, LIB_PATH = load_library()

local SIZES = {
    mlkem768_pk   = tonumber(C.mlkem768_public_key_bytes()),
    mlkem768_sk   = tonumber(C.mlkem768_secret_key_bytes()),
    mlkem768_ct   = tonumber(C.mlkem768_ciphertext_bytes()),
    mlkem768_ss   = tonumber(C.mlkem768_shared_secret_bytes()),
    xchacha_key   = tonumber(C.xchacha20poly1305_key_bytes()),
    xchacha_nonce = tonumber(C.xchacha20poly1305_nonce_bytes()),
    xchacha_tag   = tonumber(C.xchacha20poly1305_tag_bytes()),
    blake2b       = tonumber(C.blake2b_512_bytes()),
}

local _M = {
    SIZES = SIZES,
    LIB_PATH = LIB_PATH,
}

local ERR = {
    [-1] = "null pointer",
    [-2] = "invalid input length",
    [-3] = "crypto error",
    [-4] = "invalid output length",
    [-5] = "panic in native code",
}

local function rust_err(code)
    return ERR[code] or ("unknown error: " .. tostring(code))
end

local function with_buf(size, fn)
    local buf = ffi.new("uint8_t[?]", size)
    local rc = fn(buf, size)
    if rc ~= 0 then
        return nil, rust_err(rc)
    end
    return ffi.string(buf, size)
end

function _M.keygen()
    local pk_buf = ffi.new("uint8_t[?]", SIZES.mlkem768_pk)
    local sk_buf = ffi.new("uint8_t[?]", SIZES.mlkem768_sk)

    local rc = C.mlkem768_keygen(
        pk_buf, SIZES.mlkem768_pk,
        sk_buf, SIZES.mlkem768_sk
    )

    if rc ~= 0 then
        return nil, nil, rust_err(rc)
    end

    return ffi.string(pk_buf, SIZES.mlkem768_pk),
           ffi.string(sk_buf, SIZES.mlkem768_sk)
end

function _M.encaps(public_key)
    if type(public_key) ~= "string" then
        return nil, nil, "public_key must be a string"
    end

    if #public_key ~= SIZES.mlkem768_pk then
        return nil, nil, "public key must be " .. SIZES.mlkem768_pk .. " bytes"
    end

    local ct_buf = ffi.new("uint8_t[?]", SIZES.mlkem768_ct)
    local ss_buf = ffi.new("uint8_t[?]", SIZES.mlkem768_ss)

    local rc = C.mlkem768_encaps(
        public_key, #public_key,
        ct_buf, SIZES.mlkem768_ct,
        ss_buf, SIZES.mlkem768_ss
    )

    if rc ~= 0 then
        return nil, nil, rust_err(rc)
    end

    return ffi.string(ct_buf, SIZES.mlkem768_ct),
           ffi.string(ss_buf, SIZES.mlkem768_ss)
end

function _M.decaps(secret_key, ciphertext)
    if type(secret_key) ~= "string" then
        return nil, "secret_key must be a string"
    end

    if type(ciphertext) ~= "string" then
        return nil, "ciphertext must be a string"
    end

    if #secret_key ~= SIZES.mlkem768_sk then
        return nil, "secret key must be " .. SIZES.mlkem768_sk .. " bytes"
    end

    if #ciphertext ~= SIZES.mlkem768_ct then
        return nil, "ciphertext must be " .. SIZES.mlkem768_ct .. " bytes"
    end

    return with_buf(SIZES.mlkem768_ss, function(buf, sz)
        return C.mlkem768_decaps(
            secret_key, #secret_key,
            ciphertext, #ciphertext,
            buf, sz
        )
    end)
end

function _M.blake2b(input)
    if type(input) ~= "string" then
        return nil, "input must be a string"
    end

    return with_buf(SIZES.blake2b, function(buf, sz)
        return C.blake2b_512_hash(input, #input, buf, sz)
    end)
end

function _M.encrypt(key, nonce, aad, plaintext)
    if type(key) ~= "string" then
        return nil, "key must be a string"
    end

    if type(nonce) ~= "string" then
        return nil, "nonce must be a string"
    end

    if type(aad) ~= "string" then
        return nil, "aad must be a string"
    end

    if type(plaintext) ~= "string" then
        return nil, "plaintext must be a string"
    end

    if #key ~= SIZES.xchacha_key then
        return nil, "key must be " .. SIZES.xchacha_key .. " bytes"
    end

    if #nonce ~= SIZES.xchacha_nonce then
        return nil, "nonce must be " .. SIZES.xchacha_nonce .. " bytes"
    end

    local ct_len = #plaintext + SIZES.xchacha_tag

    return with_buf(ct_len, function(buf, sz)
        return C.xchacha20poly1305_encrypt(
            key, #key,
            nonce, #nonce,
            aad, #aad,
            plaintext, #plaintext,
            buf, sz
        )
    end)
end

function _M.decrypt(key, nonce, aad, ciphertext)
    if type(key) ~= "string" then
        return nil, "key must be a string"
    end

    if type(nonce) ~= "string" then
        return nil, "nonce must be a string"
    end

    if type(aad) ~= "string" then
        return nil, "aad must be a string"
    end

    if type(ciphertext) ~= "string" then
        return nil, "ciphertext must be a string"
    end

    if #key ~= SIZES.xchacha_key then
        return nil, "key must be " .. SIZES.xchacha_key .. " bytes"
    end

    if #nonce ~= SIZES.xchacha_nonce then
        return nil, "nonce must be " .. SIZES.xchacha_nonce .. " bytes"
    end

    if #ciphertext <= SIZES.xchacha_tag then
        return nil, "ciphertext too short"
    end

    local pt_len = #ciphertext - SIZES.xchacha_tag

    return with_buf(pt_len, function(buf, sz)
        return C.xchacha20poly1305_decrypt(
            key, #key,
            nonce, #nonce,
            aad, #aad,
            ciphertext, #ciphertext,
            buf, sz
        )
    end)
end

function _M.random_bytes(n)
    if type(n) ~= "number" or n < 0 or n ~= math.floor(n) then
        return nil, "n must be a non-negative integer"
    end

    return with_buf(n, function(buf, sz)
        return C.random_bytes(buf, sz)
    end)
end

function _M.constant_time_eq(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then
        return false
    end

    return C.constant_time_eq(a, #a, b, #b) == 1
end

return _M
