local mime_sniff = require "mime_sniff"

local function read_file(filename, opt)
    local f = io.open("test/" .. filename)
    return f:read(opt)
end

local old_gnu_format_tar = read_file("old_gnu_format.tar", 300)
local standard_tar = read_file("standard.tar", 300)
local case_groups = {
    ["text/html"] = {
        "<html>",
        "<HTML ",
        "<HtMl><bOdY>blah blah blah</body></html>",
        "\r\n<html>...",
        "   <!DOCTYPE HTML>...",
        "\t<!-- ",
        ("\r\n"):rep(512) .. "<script >" .. ("\r\n"):rep(512),
    },
    ["text/plain"] = {
        "",
        "#! /bin/bash",
        "Plain Text",
        "<html",
        "<html\t",
        "Àpa@",
        "\n<?php",
    },
    ["video/mp4"] = {
        "\x00\x00\x00\x18ftyp\x01\x02\x032\x00\x00\x00\x00mp42isom<\x06t\xbfmdat",
        "\x00\x00\x00\x14ftypmp42\x00\x00\x00\x00mp42isom<\x06t\xbfmdat",
    },
    ["text/xml"] = {
        "\n<?xml !",
    },
    ["application/pdf"] = {
        "\x25\x50\x44\x46\x2d\x31\x2e\x37\x0a\x33\x20\x30\x20\x6f\x62\x6a",
    },
    ["application/x-rar-compressed"] = {
        "\x52\x61\x72\x21\x1a\x07\x00\xcf\x90\x73\x00\x00\x0d",
    },
    ["application/zip"] = {
        "\x50\x4b\x03\x04\x14\x00\x00\x00\x08\x00\xb8\x91\x49\x49\x7d\x3d",
    },
    ["application/x-bzip2"] = {
        "\x42\x5a\x68\x31\x17\x72\x45\x38\x50\x90",
    },
    ["application/x-7z-compressed"] = {
        "\x37\x7a\xbc\xaf\x27\x1c\x00\x04\xb2\xd6\x90\x05\x0d\x03",
    },
    ["application/x-tar"] = {
        old_gnu_format_tar,
        standard_tar,
    },
    ["image/svg+xml"] = {
        [[  <!DOCTYPE svg ]],
        "<svg ",
    },
    ["image/jpeg"] = {
        "\xff\xd8\xff\xe1\x57\xae\x45\x78\x69\x66\x00\x00\x4d\x4d\x00\x2a",
    },
    ["image/gif"] = {
        "GIF87a",
        "GIF89a..",
    },
    ["image/png"] = {
        "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49",
    },
    ["image/tiff"] = {
        "\x4d\x4d\x00\x2a\x00\x00\x08\xce\x80\x00",
        "\x49\x49\x2a\x00\x08\x00\x00\x00\x14\x00",
    },
    ["audio/midi"] = {
        "MThd\x00\x00\x00\x06\x00\x01",
    },
    ["audio/mpeg"] = {
        "ID3\x03\x00\x00\x00\x00\x0f",
    },
    ["audio/wave"] = {
        "RIFFb\xb8\x00\x00WAVEfmt \x12\x00\x00\x00\x06",
        "RIFF,\x00\x00\x00WAVEfmt \x12\x00\x00\x00\x06",
    },
    ["audio/aiff"] = {
        "FORM\x00\x00\x00\x00AIFFCOMM\x00\x00\x00\x12\x00\x01\x00\x00\x57\x55\x00\x10\x40\x0d\xf3\x34",
    },
    ["application/ogg"] = {
        "OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x7e\x46\x00\x00\x00\x00\x00\x00\x1f\xf6\xb4"..
        "\xfc\x01\x1e\x01\x76\x6f\x72",
    },
    ["video/x-msvideo"] = {
        "RIFF,O\n\x00AVI LISTÀ",
        "RIFF,\n\x00\x00AVI LISTÀ",
    },
    ["application/octet-stream"] = {
        "\1\2\3",
        -- mp4: box size is not the multiple of 4
        "\x00\x00\x00\x16ftypmp42\x00\x00\x00\x00mp42isom<\x06t\xbfmdat",
        -- mp4: box size too large
        "\x00\x00\x10\x14ftypmp42\x00\x00\x00\x00mp42isom<\x06t\xbfmdat",
        -- mp4: not magic type name
        "\x00\x00\x00\x14ftyomp42\x00\x00\x00\x00mp42isom<\x06t\xbfmdat",
        -- mp4: not magic type name(mp4)
        "\x00\x00\x00\x18ftyp1234mp42isom<\x06t\xbfmdatblah",
    },
}

it('Detect Content-Type', function()
    for expect_ct, cases in pairs(case_groups) do
        for _, case in ipairs(cases) do
            assert.are.same(expect_ct, mime_sniff.detect_content_type(case),
                "While detecting with " .. case)
        end
    end

    -- Addition check for image/svg+xml and text/xml
    local svg = [[
        <?xml version="1.0" standalone="no"?>
        <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 20010904//EN"]]
    assert.are.same("image/svg+xml", mime_sniff.detect_content_type(svg))
end)

describe('Match Content-Type', function()
    local possible_cts = {}
    for ct, _ in pairs(case_groups) do
        table.insert(possible_cts, ct)
    end
    local upper = #possible_cts

    it('content-type found', function()
        for expect_ct, cases in pairs(case_groups) do
            for _, case in ipairs(cases) do
                local rand_ct = {}
                for _ = 1, 3 do
                    local ct = possible_cts[math.random(upper)]
                    table.insert(rand_ct, ct)
                end
                table.insert(rand_ct, expect_ct)
                assert.are.same(expect_ct, mime_sniff.match_content_type(case, rand_ct),
                    "While detecting with " .. case .. " with " .. table.concat(rand_ct, " "))
            end
        end
    end)

    it('alias video/x-msvideo to video/avi for match_content_type', function()
        local avi = "RIFF,O\n\x00AVI LISTÀ"
        assert.are.same("video/avi", mime_sniff.match_content_type(avi, "video/avi"))
        assert.are.same("video/x-msvideo", mime_sniff.match_content_type(avi, "video/x-msvideo"))
    end)

    it('content-type not found', function()
        for expect_ct, cases in pairs(case_groups) do
            for _, case in ipairs(cases) do
                local rand_ct = {}
                for _ = 1, 4 do
                    local ct = possible_cts[math.random(upper)]
                    if ct ~= "application/octet-stream" and ct ~= "text/plain" and ct ~= expect_ct then
                        table.insert(rand_ct, ct)
                    end
                end
                assert.Nil(mime_sniff.match_content_type(case, rand_ct),
                    "While detecting with " .. case .. " with " .. table.concat(rand_ct, " "))
            end
        end
    end)

    it('content-type not supported', function()
        assert.has_error(function() mime_sniff.match_content_type("", "x-not-support") end)
    end)

    it('also accept string types argument', function()
        local data = "\xff\xd8\xff\xe1\x57\xae\x45\x78\x69\x66\x00"
        assert.are.same("image/jpeg", mime_sniff.match_content_type(data, "image/jpeg"))
        assert.are.same("image/jpeg", mime_sniff.match_content_type(
            data, "image/gif", "image/jpeg", "image/png"))
    end)
end)
