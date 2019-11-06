--- -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--- This file is licensed under the terms of the Modified BSD license:
---
---  Redistribution and use in source and binary forms, with or without
---  modification, are permitted provided that the following conditions
---  are met:
---
---  * Redistributions of source code must retain the above copyright
---    notice, this list of conditions and the following disclaimer.
---  * Redistributions in binary form must reproduce the above copyright
---    notice, this list of conditions and the following disclaimer in the
---    documentation and/or other materials provided with the distribution.
---  * Neither the name of the authors nor the names of its contributors
---    may be used to endorse or promote products derived from this software
---    without specific prior written permission.
---
---  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
---  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
---  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
---  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
---  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
---  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
---  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
---  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
---  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
---  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
---  POSSIBILITY OF SUCH DAMAGE.
--- -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

--
-- Created under CLion IDE.
-- Date: Friday, 8th May, 2018
-- Time: 9:46 AM
--
-- Wireless Sensor Node Project
-- DissectorProjectWSN.lua
-- Program Purpose:
--  -> To dissect the AM and CTP Protocol Layer of the data colected during experiments in Wireshark
--
-- User: Aryan Kukreja (100651838)
-- Contact Information: aryan.kukreja@uoit.net
--

-- The dissector below is a modification of an original dissector found at the following link:
--      -> https://github.com/Pinoccio/hardware-pinoccio/blob/master/firmware/bootloader/p2p-wireshark-dissector.lua

-- The following block of comments belong to the author of the original code:
-- Declaring the Protocol (parameters are name of protocol, and long description of it respectively)
local CTP_Protocol = Proto ("CTP_Protocol", "802.15.4 I-Frame Payload Dissection")

-- Declare the 3 types of Frames according to 6LowPAN ID (information obtained from TinyOS source code)
local SixLowPAN_ID =
{
    [0x70] = "RoutingFrame",
    [0x71] = "DataFrame",
    [0x72] = "DebugFrame"
}

--- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

-- Declaring Field Values of Dissector (grouped on purpose/function)
-- Format: Each entry is a property of the fields property of the CTP_Protocol Proto object.
--      -> Each field is assigned a 16-bit storage space. Can be optimized depending on the maximum size required by the field
--      -> Parameters of Protofield() are: Name of Field, and Long Description of Field

-- Non-CTP Fields (Active Message Layer and 6LowPAN ID)
CTP_Protocol.fields.LowPAN_ID = ProtoField.uint16("CTP_Protocol.LowPAN_ID", "6LowPAN ID")
CTP_Protocol.fields.AM_Type = ProtoField.uint16("CTP_Protocol.AM_Type", "Active Message Type")

-- CTP Fields common to Data Frame and Routing Frame (6LowPAN ID: 0x70 and 0x71)
CTP_Protocol.fields.Expected_Transmission = ProtoField.uint16("CTP_Protocol.Expected_Transmission", "Expected Transmissions Value")
CTP_Protocol.fields.P_Bit = ProtoField.bool("CTP_Protocol.P_Bit", "Routing Pull Bit")
CTP_Protocol.fields.C_Bit = ProtoField.bool("CTP_Protocol.C_Bit", "Congestion Notification Bit")
CTP_Protocol.fields.Fixed_Bit = ProtoField.bool("CTP_Protocol.Fixed_Bit", "Fixed Node Bit")
CTP_Protocol.fields.Reserved_Bit = ProtoField.uint16("CTP_Protocol.Reserved_Bit", "Reserved Bits")

-- Specific to Data Frame (6LowPAN ID: 0x71)
CTP_Protocol.fields.Time_Has_Lived = ProtoField.uint16("CTP_Protocol.Time_Has_Lived", "TimeHasLived Value")
CTP_Protocol.fields.Origin_ID = ProtoField.uint16("CTP_Protocol.Origin_ID", "Origin")
CTP_Protocol.fields.Sequence_Number = ProtoField.uint16("CTP_Protocol.Sequence_Number", "CTP Sequence Number")
CTP_Protocol.fields.Collection_ID = ProtoField.uint16("CTP_Protocol.Collection_ID", "Collection ID")

-- Specific to Routing Frame (6LowPAN ID: 0x70)
CTP_Protocol.fields.Parent_ID = ProtoField.uint16("CTP_Protocol.Parent_ID", "Parent_ID")
CTP_Protocol.fields.NumberEntries = ProtoField.uint16("CTP_Protocol.NumberEntries", "Number of Entries")
CTP_Protocol.fields.Reserved_LE_Bits = ProtoField.uint16("CTP_Protocol.Reserved_LE_Bits", "Reserved Bits LE Header")
CTP_Protocol.fields.Sequence_Value = ProtoField.uint16("CTP_Protocol.Sequence_Value", "Sequence Number")

-- Capturing the errors (part of original code - left unmodified)
CTP_Protocol.experts.too_short = ProtoExpert.new("short", "Packet too short", expert.group.MALFORMED, expert.severity.ERROR)
CTP_Protocol.experts.too_long = ProtoExpert.new("long", "Packet too long", expert.group.MALFORMED, expert.severity.ERROR)
CTP_Protocol.experts.unknown_cmd = ProtoExpert.new("unknown_cmd", "Unknown command", expert.group.MALFORMED, expert.severity.ERROR)

--- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

-- Declare and define all the functions here

-- Init function, called before any packet is dissected
function CTP_Protocol.init()
    -- Nothing required from init() function
end

-- Function called only for dissecting the Routing Frames
-- Parameters: buffer => captured data | pinfo => Packet Information | tree => Detail Dissection
-- Consists of tree:add() functions.
--      -> Parameters: Protocol Field name, allocated buffer
function Dissect_CTP_Routing_Fields(buffer, pinfo, tree)
    tree:add(CTP_Protocol.fields.LowPAN_ID, buffer(0, 1))
    tree:add(CTP_Protocol.fields.AM_Type, buffer(1, 1))

    tree:add(CTP_Protocol.fields.NumberEntries, buffer(2, 1):bitfield(4, 4))
    tree:add(CTP_Protocol.fields.Reserved_LE_Bits, buffer(2, 1):bitfield(0, 4))
    tree:add(CTP_Protocol.fields.Sequence_Value, buffer(3, 1))

    tree:add(CTP_Protocol.fields.P_Bit, buffer(4, 1):bitfield(0, 1))
    tree:add(CTP_Protocol.fields.C_Bit, buffer(4, 1):bitfield(1, 1))
    tree:add(CTP_Protocol.fields.Fixed_Bit, buffer(4, 1):bitfield(2, 1))
    tree:add(CTP_Protocol.fields.Reserved_Bit, buffer(4, 1):bitfield(3, 5))
    tree:add(CTP_Protocol.fields.Parent_ID, buffer(5, 2))
    tree:add(CTP_Protocol.fields.Expected_Transmission, buffer(7, 2))

    return buffer:len()
end

-- Function called only for dissecting the Data Frames
-- Parameters: buffer => captured data | pinfo => Packet Information | tree => Detail Dissection
-- Consists of tree:add() functions.
--      -> Parameters: Protocol Field name, allocated buffer
function Dissect_CTP_Data_Fields(buffer, pinfo, tree)
    tree:add(CTP_Protocol.fields.LowPAN_ID, buffer(0, 1))
    tree:add(CTP_Protocol.fields.AM_Type, buffer(1, 1))

    tree:add(CTP_Protocol.fields.P_Bit, buffer(2, 1):bitfield(0,1))
    tree:add(CTP_Protocol.fields.C_Bit, buffer(2, 1):bitfield(1,1))
    tree:add(CTP_Protocol.fields.Fixed_Bit, buffer(2, 1):bitfield(2, 1))
    tree:add(CTP_Protocol.fields.Reserved_Bit, buffer(2, 1):bitfield(3, 5))

    tree:add(CTP_Protocol.fields.Time_Has_Lived, buffer(3, 1))
    tree:add(CTP_Protocol.fields.Expected_Transmission, buffer(4, 2))
    tree:add(CTP_Protocol.fields.Origin_ID, buffer(6, 2))
    tree:add(CTP_Protocol.fields.Sequence_Number, buffer(8, 1))
    tree:add(CTP_Protocol.fields.Collection_ID, buffer(9, 1))
    return buffer:len()
end

-- The main dissector function (part of original code)
--  -> The only modifications made are the names of the variables and tables; the code is not changed
function real_dissector (buffer, pinfo, subtree)
    cmdname = SixLowPAN_ID[buffer(1,1):uint()]
    if (not cmdname) then
        subtree:add_tvb_expert_info(CTP_Protocol.experts.unknown_cmd, buffer(0,1))
        return false
    end

    subbuf = buffer(0):tvb()

    -- decode frame internals
    if (cmdname == "DataFrame") then
        len, msg = Dissect_CTP_Data_Fields(buffer(0), pinfo, subtree)
    elseif (cmdname == "RoutingFrame") then
        len, msg = Dissect_CTP_Routing_Fields(buffer(0), pinfo, subtree)
    else
        len = 0
        msg = nil
    end

    if subbuf:len() ~= len then
        subtree:add_tvb_expert_info(CTP_Protocol.experts.too_long, subbuf(len))
        return false
    end

    -- Only set the protocol info last, so we only set it for
    -- packets that look valid.
    pinfo.cols.protocol = "Collection Tree Protocol"
    pinfo.cols.info = string.format("%s %s", cmdname, msg or "")

    return true
end

function dissector(buffer, pinfo, tree)
    local subtree = tree:add(CTP_Protocol, "CTP Protocol")

    ok, result = pcall(real_dissector, buffer, pinfo, subtree)
    if not ok and result:match("Range is out of bounds$") then
        return false
    elseif not ok then
        error(result)
    else
        return result
    end
end

--- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
-- Dissector is registered and activated here. Apart from the variable names, the original code is left unchanged
CTP_Protocol.dissector = dissector

CTP_Protocol:register_heuristic("wpan", dissector)
table = DissectorTable.get("wpan.panid")
table:add(-1, CTP_Protocol)