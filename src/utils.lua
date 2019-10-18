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

-- convert bytes (network order) to a 24-bit two's complement integer
function bytes2int(b0, b1, b2)
    local n = b0 * 65536 + b1 * 256 + b2
    return n
end

function canId2Text(canId)
    if canId2TextTable[canId] == nil then
        return ""
    else
        return "(", canId2TextTable[canId], ")"
    end
end

canId2TextTable = {
    [1200] = "utc",
    [1930] = "debug"
}