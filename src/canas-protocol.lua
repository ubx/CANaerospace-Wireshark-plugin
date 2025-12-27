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

-- Ensure we can load utils.lua if it's in the same directory as this script
local script_path = debug.getinfo(1).source:match("@?(.*[\\/])")
if script_path then
    package.path = script_path .. "?.lua;" .. package.path
end

local utils = require("utils")

-- Compatibility for bitwise operations
local bit = bit or bit32

local can_id_field = Field.new("can.id")

local canas_proto = Proto("canas", "CANaerospace Protocol")

-- Proto header fields
local header_fields = {
    canid = ProtoField.uint32("canas.canid", "CAN ID", base.DEC, utils.defaultIdentifierTable),
    nodeid = ProtoField.uint8("canas.nodeid", "Node ID", base.DEC, utils.defaultNodeIdTable),
    datatype = ProtoField.uint8("canas.datatype", "Data Type", base.DEC, utils.dataTypeTable),
    servicecode = ProtoField.uint8("canas.servicecode", "Service Code", base.DEC, utils.serviceCodeTable)
}
canas_proto.fields = header_fields

-- create a function to dissect it
function canas_proto.dissector(buffer, pinfo, tree)
    --- print("[CANAS] Dissector called! Length: " .. buffer:len())

    pinfo.cols.protocol = "CANaerospace"
    local subtree = tree:add(canas_proto, buffer(), "CANaerospace Protocol Data")

    local canId
    local aerospace_buffer
    local aerospace_offset

    if buffer:len() >= 16 then
        -- Assume full CAN frame (e.g. from Linux SocketCAN)
        -- Bytes 0-3: CAN ID (little-endian, includes flags)
        local can_subtree = subtree:add(buffer(0, 8), "CAN Frame")
        local raw_canid = buffer(0, 4):le_uint()
        canId = bit.band(raw_canid, 0x1FFFFFFF)
        
        can_subtree:add(header_fields.canid, buffer(0, 4), canId)
        
        local is_xtd = bit.band(raw_canid, 0x80000000) ~= 0
        local is_rtr = bit.band(raw_canid, 0x40000000) ~= 0
        local is_err = bit.band(raw_canid, 0x20000000) ~= 0
        
        can_subtree:add(buffer(0, 4), "Flags: " .. 
            (is_xtd and "XTD " or "") .. 
            (is_rtr and "RTR " or "") .. 
            (is_err and "ERR" or ""))
            
        can_subtree:add(buffer(4, 1), "DLC: " .. buffer(4, 1):uint())
        can_subtree:add(buffer(5, 3), "Reserved")

        aerospace_buffer = buffer(8, 8)
        aerospace_offset = 8
    else
        -- Assume CAN payload (e.g. from can.subdissector)
        -- We need to get the CAN ID from the parent dissector
        local can_id_info = can_id_field()
        if can_id_info then
            canId = can_id_info.value
        else
            canId = 0 -- Default if not found
        end

        aerospace_buffer = buffer(0, buffer:len())
        aerospace_offset = 0
    end

    -- CANaerospace part
    local aerospace_subtree = subtree:add(aerospace_buffer, "CANaerospace")
    
    if canId then
        local canid_range = (aerospace_offset == 8) and buffer(0, 4) or buffer(0,0)
        aerospace_subtree:add(header_fields.canid, canid_range, canId)
    end

    if aerospace_buffer:len() < 4 then
        return
    end

    aerospace_subtree:add(header_fields.nodeid, aerospace_buffer(0, 1), aerospace_buffer(0, 1):uint())
    local dataType = aerospace_buffer(1, 1):uint()
    aerospace_subtree:add(header_fields.datatype, aerospace_buffer(1, 1), dataType)
    aerospace_subtree:add(header_fields.servicecode, aerospace_buffer(2, 1), aerospace_buffer(2, 1):uint())
    aerospace_subtree:add(aerospace_buffer(3, 1), "Message Code: " .. aerospace_buffer(3, 1):uint())

    if aerospace_buffer:len() > 4 then
        local data_len = aerospace_buffer:len() - 4
        aerospace_subtree:add(aerospace_buffer(4, data_len), "Data: " .. utils.getValue(aerospace_buffer(4, data_len), dataType, canId))
    end

    local info = utils.defaultIdentifierTable[canId]
    if info == nil then
        info = "Identifier " .. canId
    end
    pinfo.cols.info = info
end

local sll_dissector_table = DissectorTable.get("sll.ltype")
if sll_dissector_table then
    pcall(function()
        sll_dissector_table:add(12, canas_proto)
    end)
end

local can_dissector_table = DissectorTable.get("can.subdissector")
if can_dissector_table then
    pcall(function()
        can_dissector_table:add_for_decode_as(canas_proto)
    end)
end

-- Also register for standard CAN ID based dissection if possible
-- Some Wireshark versions use "can.id"
local can_id_table = DissectorTable.get("can.id")
if can_id_table then
    -- Some Wireshark versions don't support add_for_decode_as for can.id.
    -- We'll add it for all CANaerospace IDs defined in utils.defaultIdentifierTable.
    for id, _ in pairs(utils.defaultIdentifierTable) do
        pcall(function()
            can_id_table:add(id, canas_proto)
        end)
    end
end

-- Try to register for Link Layer types if they are used directly
local wtap_table = DissectorTable.get("wtap_encap")
if wtap_table then
    if wtap and wtap.CANRAW then
        pcall(function()
            wtap_table:add(wtap.CANRAW, canas_proto)
        end)
    end
    if wtap and wtap.CAN_ETH then
        pcall(function()
            wtap_table:add(wtap.CAN_ETH, canas_proto)
        end)
    end
end
