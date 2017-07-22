-- ￥ curl -F "file=@evil_script.jpg;type=image/jpeg"  localhost:8888
-- You saied 'image/jpeg', but we found 'text/plain'
local mime_sniff = require "lib.mime_sniff"
local upload = require "resty.upload"

local chunk_size = 1445 -- 512 is enough for the most cases

local form, err = upload:new(chunk_size)
if not form then
    ngx.log(ngx.ERR, "failed to new upload: ", err)
    ngx.exit(500)
end

form:set_timeout(1000)

local submit_content_type
local actual_content_type
while true do
    local typ, res, err = form:read()
    if not typ then
        ngx.say("failed to read: ", err)
        return
    end

    if typ == "header" and res[1] == "Content-Type" then
        submit_content_type = res[2]
    elseif typ == "body" then
        --if not mime_sniff.match_content_type("image/jpeg") then
        --if not mime_sniff.match_content_type({"image/gif", "image/jpeg"}) then
        actual_content_type = mime_sniff.detect_content_type(res)
        break
    elseif typ == "eof" then
        break
    end
end
ngx.say("You saied '", submit_content_type, "', but we found '", actual_content_type, "'")
