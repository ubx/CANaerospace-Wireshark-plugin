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


-- Display version information for Wireshark
local plugin_info = {
    version = "1.0.0",
    author = "Andreas Lüthi",
    repository = "https://github.com/ubx/CANaerospace-Wireshark-plugin"
}
set_plugin_info(plugin_info)

local utils = require("utils")

local canas_proto = Proto("canas", "CANaerospace Protocol")

-- Proto header fields
local header_fields = {
    canid = ProtoField.uint24("canas.canid", "Can Id", base.DEC, utils.defaultIdentifierTable),
    nodeid = ProtoField.uint8("canas.nodeid", "Node Id", base.DEC, utils.defaultNodeIdTable),
    datatype = ProtoField.uint8("canas.datatype", "Data Type", base.DEC, utils.dataTypeTable),
    servicecode = ProtoField.uint8("canas.servicecode", "Service Code", base.DEC, utils.serviceCodeTable)
}
canas_proto.fields = header_fields

-- create a function to dissect it
function canas_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CANaerospace"
    local subtree = tree:add(canas_proto, buffer(), "CANaerospace Protocol Data")

    -- CAN part
    local can_subtree = subtree:add(buffer(0, 8), "CAN")
    local canId = buffer(0, 3):le_int()
    can_subtree:add(header_fields.canid, buffer(0, 3), canId)
    can_subtree:add(buffer(3, 1), "flags, xtd: " .. buffer(3, 1):bitfield(0, 1) .. " rtr: " .. buffer(3, 1):bitfield(1, 1) .. " err: " .. buffer(3, 1):bitfield(2, 1))
    can_subtree:add(buffer(4, 1), "len: " .. buffer(4, 1))
    can_subtree:add(buffer(5, 3), "reserved: " .. buffer(3, 3))

    -- CANaerospace part
    local aerospace_subtree = subtree:add(buffer(8, 8), "aerospace")
    aerospace_subtree:add(header_fields.nodeid, buffer(8, 1), buffer(8, 1):uint())
    local dataType = buffer(9, 1):uint()
    aerospace_subtree:add(header_fields.datatype, buffer(9, 1), dataType)
    aerospace_subtree:add(header_fields.servicecode, buffer(10, 1), buffer(10, 1):uint())
    aerospace_subtree:add(buffer(11, 1), "Message Code: " .. buffer(11, 1):uint())
    aerospace_subtree:add(buffer(12, 4), "Data: " .. utils.getValue(buffer(12, 4), dataType, canId))
    local info = utils.defaultIdentifierTable[canId]
    if info == nil then
        info = "Identifier " .. canId
    end
    pinfo.cols.info = info
end

local dissector_table = DissectorTable.get("sll.ltype")
dissector_table:add(12, canas_proto)