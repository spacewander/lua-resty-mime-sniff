## Name

lua-resty-mime-sniff - Sniff the real MIME type of given data.

## Status

[![Travis](https://travis-ci.org/spacewander/lua-resty-mime-sniff.svg?branch=master)](https://travis-ci.org/spacewander/lua-resty-mime-sniff)
[![Coverage Status](https://coveralls.io/repos/github/spacewander/lua-resty-mime-sniff/badge.svg?branch=master)](https://coveralls.io/github/spacewander/lua-resty-mime-sniff?branch=master)

## Synopsis

```lua
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
```

## Methods

detect_content_type
---
`syntax: content_type = mime_sniff.detect_content_type(data)`

`detect_content_type` could be used to detect real Content-Type of the given data.
It considers at most the first 1445 bytes of data,
though first 512 bytes are enough for the majority of cases.
This function always returns a valid MIME type:
if it cannot determine a more specific one, it returns "application/octet-stream".


match_content_type
---
`syntax: match_content_type = mime_sniff.match_content_type(data, types, ...)`

`match_content_type` checks if the given data's Content-Type matches any of the given types.
The types is an array-like table or strings, and the length of data should be long enough.
(1445 bytes at most and 512 bytes is enough)
Note that the order of types is important. The first type matches first.
This function will return matched type or nil,
or throw an error if none of the given types is supported yet.
For the list of supported mime types, please refer to the wiki:
https://github.com/spacewander/lua-resty-mime-sniff/wiki/MIME-type-support-status

## Installation

You could install via `opm --cwd get spacewander/lua-resty-mime-sniff`.(Recommended)
Or you could vendor the `lib/` in your project.

## Contributing

Any contribution are welcome! However, before writing your pull request, please read through [the Guide](CONTRIBUTING.md).