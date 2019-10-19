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

utils=require("utils")

canas_proto = Proto("canas", "CANaerospace Protocol")

-- todo -- add fields for filters

-- create a function to dissect it
function canas_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CANaerospace"
    local subtree = tree:add(canas_proto, buffer(), "CANaerospace Protocol Data")

    -- CAN part
    subtree = subtree:add(buffer(0, 8), "CAN")
    local canId = buffer(0, 3):le_int()
    subtree:add(buffer(0, 3), "CAN-ID: " .. canId, canId2Text(canId))
    subtree:add(buffer(3, 1), "flags, xtd: " .. buffer(3, 1):bitfield(0,1) .." rtr: " .. buffer(3, 1):bitfield(1,1).." err: " .. buffer(3, 1):bitfield(2,1))
    subtree:add(buffer(4, 1), "len: " .. buffer(4, 1))
    subtree:add(buffer(5, 3), "reserved: " .. buffer(3, 3))

    -- CANaerospace part
    subtree = subtree:add(buffer(8, 8), "aerospace")
    subtree:add(buffer(8, 1), "Node-ID: " .. buffer(8, 1):uint())
    local dataType = buffer(9, 1):uint()
    subtree:add(buffer(9, 1), "Data Type: " .. dataType)
    subtree:add(buffer(10, 1), "Service Code: " .. buffer(10, 1):uint())
    subtree:add(buffer(11, 1), "Message Code: " .. buffer(11, 1):uint())
    subtree:add(buffer(12, 4), "Data: " .. getValue(buffer(12,4), dataType, canId))
end

dissector_table = DissectorTable.get("sll.ltype")
dissector_table:add(12, canas_proto)