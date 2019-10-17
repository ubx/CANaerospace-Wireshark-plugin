--
-- canas-protocol.lua: CANaerospace Wireshark Lua plugin
--
-- Copyright (C) 2019  Andreas Lüthi
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.
--
-- Run with: wireshark -X lua_script:canas-protocol.lua

RUN_TESTS = os.getenv("TEST")

if RUN_TESTS then
    _G.debug = require("debug")
    local luacov = require("luacov")
end

-- convert bytes (network order) to a 24-bit two's complement integer
function bytes_to_int(b0, b1, b2)
    local n = b0 * 65536 + b1 * 256 + b2
    return n
end

canId2TextTab = {
    [1200] = "utc",
    [1930] = "debug"
}

function canId2Text(canId)
    if canId2TextTab[canId] == nil then
        return ""
    else
        return "(", canId2TextTab[canId], ")"
    end
end

canas_proto = Proto("canas", "CANaerospace Protocol")
-- create a function to dissect it
function canas_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CANaerospace"
    local subtree = tree:add(canas_proto, buffer(), "CANaerospace Protocol Data")

    -- CAN part
    subtree = subtree:add(buffer(0, 8), "CAN")
    local canId = bytes_to_int(buffer(2, 1):uint(), buffer(1, 1):uint(), buffer(0, 1):uint())
    subtree:add(buffer(0, 3), "CAN-ID: " .. canId, canId2Text(canId))

    -- todo -- get flags, bit32.band(0xf,0x2)
    --* Controller Area Network Identifier structure
    --* bit 0-28	: CAN identifier (11/29 bit)
    --* bit 29	: error message frame flag (0 = data frame, 1 = error message)
    --* bit 30	: remote transmission request flag (1 = rtr frame)
    --* bit 31	: frame format flag (0 = standard 11 bit, 1 = extended 29 bit)
    subtree:add(buffer(3, 1), "flags, xtd: " .. buffer(3, 1), buffer(3, 1), "rtr: " .. buffer(3, 1), buffer(3, 1), "err: " .. buffer(3, 1))
    subtree:add(buffer(4, 1), "len: " .. buffer(4, 1))
    subtree:add(buffer(5, 3), "reserved: " .. buffer(3, 3))

    -- CANaerospace part
    subtree = subtree:add(buffer(8, 8), "aerospace")
    subtree:add(buffer(8, 1), "Node-ID: " .. buffer(8, 1):uint())
    subtree:add(buffer(9, 1), "Data Type: " .. buffer(9, 1):uint())
    subtree:add(buffer(10, 1), "Service Code: " .. buffer(10, 1):uint())
    subtree:add(buffer(11, 1), "Message Code: " .. buffer(11, 1):uint())
    -- todo -- decode message according to https://www.stockflightsystems.com/tl_files/downloads/canaerospace/canas_17.pdf
    subtree:add(buffer(12, 4), "Data: " .. buffer(12, 4):uint())
end

dissector_table = DissectorTable.get("sll.ltype")
dissector_table:add(12, canas_proto)