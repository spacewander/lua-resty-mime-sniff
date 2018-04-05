require "table.new"
local error = error
local ipairs = ipairs
local type = type
local bit = require "bit"
local bit_band  = bit.band
local bit_lshift = bit.lshift
local re_find = ngx.re.find
local string_byte = string.byte
local string_sub = string.sub
local table_new = table.new
local table_insert = table.insert

local MAX_SNIFF_LEN = 1445

local _M = { version = "0.1.0" }

local function html_match(self, data, first_non_ws)
    local sig = self.sig
    data = string_sub(data, first_non_ws)

    local sig_len = #sig
    if #data <= sig_len then
        return ""
    end
    for i = 1, sig_len do
        local b = string_byte(sig, i)
        local db = string_byte(data, i)
        -- byte('A') == 65, byte('Z') == 90
        if 65 <= b and b <= 90 then
            db = bit_band(db, 0xDF)
        end
        if b ~= db then
            return ""
        end
    end

    -- Next byte must be tag-terminating byte(space or right angle bracket).
    local db = string_byte(data, sig_len+1)
    -- byte(' ') == 32, byte('>') == 62
    if db ~= 32 and db ~= 62 then
        return ""
    end
    return self.ct
end

local function HtmlSignature(sig)
    return {match = html_match, sig = sig, ct = "text/html"}
end

local function masked_match(self, data, first_non_ws)
    -- https://mimesniff.spec.whatwg.org/#pattern-matching-algorithm
    if self.skip_ws then
        data = string_sub(data, first_non_ws)
    end
    local mask = self.mask
    local mask_len = #mask
    local pat = self.pat
    if #data < mask_len then
        return ""
    end
    for i = 1, mask_len do
        local db = bit_band(string_byte(data, i), string_byte(mask, i))
        if db ~= string_byte(pat, i) then
            return ""
        end
    end
    return self.ct
end

local function MaskedSignature(opts)
    if #opts.pat ~= #opts.mask then
        error("Incorrect mask given. Mask length should be equal to pattern length")
    end
    return {
        match = masked_match,
        mask = opts.mask,
        pat = opts.pat,
        skip_ws = opts.skip_ws,
        ct = opts.ct
    }
end

local function exact_match(self, data, _)
    local sig = self.sig
    if string_sub(data, 1, #sig) == sig then
        return self.ct
    end
    return ""
end

local function ExactSignature(sig, ct)
    return { match = exact_match, sig = sig, ct = ct}
end

local function regex_match(self, data, first_non_ws)
    if self.skip_ws then
        data = string_sub(data, first_non_ws)
    end
    local offset = self.offset
    if #data <= offset then
        return ""
    end

    if re_find(data:sub(offset+1), self.regex, "jo") then
        return self.ct
    end
    return ""
end

local function RegexSignature(opts)
    return {
        match = regex_match,
        offset = opts.offset or 0,
        regex = opts.regex,
        skip_ws = opts.skip_ws,
        ct = opts.ct
    }
end

-- Pass len to avoid creating substring
local function big_endian_bytes_to_num(bytes, len)
    local n = 0
    for i = 1, len do
        n = bit_lshift(n, 8) + string_byte(bytes, i)
    end
    return n
end

local function mp4_match(self, data, _)
    -- https://mimesniff.spec.whatwg.org/#signature-for-mp4
    local data_len = #data
    if data_len < 12 then
        return ""
    end
    local box_size = big_endian_bytes_to_num(data, 4)
    if box_size % 4 ~= 0 or box_size > data_len then
        return ""
    end
    if string_sub(data, 5, 8) ~= "ftyp" then
        return ""
    end
    for st = 9, box_size, 4 do
        -- 13 is minor version number
        if st ~= 13 and string_sub(data, st, st+2) == "mp4" then
            return self.ct
        end
    end
    return ""
end

local function Mp4Signature()
    return { match = mp4_match, ct = "video/mp4" }
end

local function text_match(self, data, first_non_ws)
    data = string_sub(data, first_non_ws)
    for i = 1, #data do
        local b = string_byte(data, i)
        if b <= 0x08 or
           b == 0x0B or
           (0x0E <= b and b <= 0x1A) or
           (0x1C <= b and b <= 0x1F) then
            return ""
        end
    end
    return self.ct
end

local function TextSignature()
    return { match = text_match, ct = "text/plain" }
end

local function octet_stream_match(self)
    return self.ct
end

local function OctetStreamSignature()
    return { match = octet_stream_match, ct = "application/octet-stream" }
end

local sniff_signatures = {
    HtmlSignature("<!DOCTYPE HTML"),
    HtmlSignature("<HTML"),
    HtmlSignature("<HEAD"),
    HtmlSignature("<SCRIPT"),
    HtmlSignature("<IFRAME"),
    HtmlSignature("<H1"),
    HtmlSignature("<DIV"),
    HtmlSignature("<FONT"),
    HtmlSignature("<TABLE"),
    HtmlSignature("<A"),
    HtmlSignature("<STYLE"),
    HtmlSignature("<TITLE"),
    HtmlSignature("<B"),
    HtmlSignature("<BODY"),
    HtmlSignature("<BR"),
    HtmlSignature("<P"),
    HtmlSignature("<!--"),

    RegexSignature{
        regex = [[(?:<\?xml\s+.*\?>\s*)?(?:<!DOCTYPE\s+svg|<svg) ]],
        skip_ws = true,
        ct = "image/svg+xml",
    },
    MaskedSignature{
        mask = "\xFF\xFF\xFF\xFF\xFF",
        pat = "<?xml", skip_ws = true,
        ct = "text/xml"},

    ExactSignature("%PDF-", "application/pdf"),
    ExactSignature("%!PS-Adobe-", "application/postscript"),

    -- UTF BOMs.
    MaskedSignature{
        mask = "\xFF\xFF\x00\x00",
        pat = "\xFE\xFF\x00\x00",
        ct = "text/plain"},
    MaskedSignature{
        mask = "\xFF\xFF\x00\x00",
        pat = "\xFF\xFE\x00\x00",
        ct = "text/plain"},
    MaskedSignature{
        mask =  "\xFF\xFF\xFF\x00",
        pat = "\xEF\xBB\xBF\x00",
        ct = "text/plain"},

    ExactSignature("GIF87a", "image/gif"),
    ExactSignature("GIF89a", "image/gif"),
    ExactSignature("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", "image/png"),
    ExactSignature("\xFF\xD8\xFF", "image/jpeg"),
    ExactSignature("BM", "image/bmp"),
    -- https://en.wikipedia.org/wiki/TIFF#Byte_order
    ExactSignature("MM\x00*", "image/tiff"),
    ExactSignature("II*\x00", "image/tiff"),
    MaskedSignature{
        mask = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
        pat =  "RIFF\x00\x00\x00\x00WEBPVP",
        ct =   "image/webp",
    },
    ExactSignature("\x00\x00\x01\x00", "image/vnd.microsoft.icon"),
    MaskedSignature{
        mask = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat =  "RIFF\x00\x00\x00\x00WAVE",
        ct =   "audio/wave",
    },
    MaskedSignature{
        mask = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat =  "FORM\x00\x00\x00\x00AIFF",
        ct =   "audio/aiff",
    },
    MaskedSignature{
        mask = "\xFF\xFF\xFF\xFF",
        pat =  ".snd",
        ct =   "audio/basic",
    },
    MaskedSignature{
        mask = "OggS\x00",
        pat =  "\x4F\x67\x67\x53\x00",
        ct =   "application/ogg",
    },
    MaskedSignature{
        mask = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        pat =  "MThd\x00\x00\x00\x06",
        ct =   "audio/midi",
    },
    -- TODO support mp3 without ID3, need a sample
    MaskedSignature{
        mask = "\xFF\xFF\xFF",
        pat =  "ID3",
        ct =   "audio/mpeg",
    },
    MaskedSignature{
        mask = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
        pat =  "RIFF\x00\x00\x00\x00AVI ",
        ct =   "video/x-msvideo", -- aka. video/avi
    },
    ExactSignature("\x1A\x45\xDF\xA3", "video/webm"),
    ExactSignature("\x52\x61\x72\x20\x1A\x07\x00", "application/x-rar-compressed"),
    ExactSignature("\x52\x61\x72\x21\x1A\x07\x00", "application/x-rar-compressed"),
    ExactSignature("\x50\x4B\x03\x04", "application/zip"),
    ExactSignature("\x1F\x8B\x08", "application/x-gzip"),
    ExactSignature("BZh", "application/x-bzip2"),
    ExactSignature("BZ0", "application/x-bzip"),
    ExactSignature("7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),

    -- Old GNU format use "ustar  \0", though the standard is "ustar\000"
    RegexSignature{ offset = 257, regex = [[^ustar(?:  \x00|\x0000)]], ct = "application/x-tar" },
    Mp4Signature(),

    TextSignature(), -- should be second last
    OctetStreamSignature(), -- should be last
}

local ct_sig_map = table_new(0, #sniff_signatures)
for _, signature in ipairs(sniff_signatures) do
    if ct_sig_map[signature.ct] then
        table_insert(ct_sig_map[signature.ct], signature)
    else
        ct_sig_map[signature.ct] = {signature}
    end
end
ct_sig_map['video/avi'] = ct_sig_map['video/x-msvideo']

local function truncate_sniff_data(data)
    if #data > MAX_SNIFF_LEN then
        return string_sub(data, 1, MAX_SNIFF_LEN)
    end
    return data
end

local function find_first_non_ws(data)
    local first_non_ws = re_find(data, [[\S]], "jo")
    if not first_non_ws then
        return #data + 1
    end
    return first_non_ws
end

-- detect_content_type could be used to detect real Content-Type of the given data.
-- It considers at most the first 1445 bytes of data,
-- though first 512 bytes are enough for the majority of cases.
-- This function always returns a valid MIME type:
-- if it cannot determine a more specific one, it returns "application/octet-stream".
function _M.detect_content_type(data)
    data = truncate_sniff_data(data)
    local first_non_ws = find_first_non_ws(data)
    for i = 1, #sniff_signatures do
        local ct = sniff_signatures[i]:match(data, first_non_ws)
        if ct ~= "" then
            return ct
        end
    end
end


-- match_content_type checks if the given data's Content-Type matches any of the given types.
-- The types is an array-like table or strings, and the length of data should be long enough.
-- (1445 bytes at most and 512 bytes is enough)
-- Note that the order of types is important. The first type matches first.
-- This function will return matched type or nil,
-- or throw an error if none of the given types is supported yet.
-- For the list of supported mime types, please refer to the wiki:
-- https://github.com/spacewander/lua-resty-mime-sniff/wiki/MIME-type-support-status
function _M.match_content_type(data, types, ...)
    if type(types) == "string" then
        types = {types, ...}
    end

    local first_non_ws = find_first_non_ws(data)
    local type_supported = false
    local need_match_plain_text = false
    local need_match_octet_stream = false

    for i = 1, #types do
        local given_type = types[i]
        if given_type == "application/octet-stream" then
            need_match_octet_stream = true
            goto continue
        elseif given_type == "text/plain" then
            need_match_plain_text = true
            goto continue
        end
        local signatures = ct_sig_map[given_type]
        if not signatures then
            goto continue
        end
        type_supported = true
        for j = 1, #signatures do
            local signature = signatures[j]
            if signature:match(data, first_non_ws) ~= "" then
                return given_type
            end
        end

        ::continue::
    end

    if need_match_plain_text then
        type_supported = true
        local signatures = ct_sig_map["text/plain"]
        for i = 1, #signatures do
            local signature = signatures[i]
            if signature:match(data, first_non_ws) ~= "" then
                return "text/plain"
            end
        end
    end
    if need_match_octet_stream then
        return "application/octet-stream"
    end

    if not type_supported then
        local wiki = "https://github.com/spacewander/lua-resty-mime-sniff/wiki/MIME-type-support-status"
        error("None of given mime types is supported. Please check the "..
              wiki.." for current supported types.")
    end

    return nil
end

return _M
