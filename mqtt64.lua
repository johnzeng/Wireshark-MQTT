--
-- mqtt.lua is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Lesser General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- mqtt.lua is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with mqtt.lua.  If not, see <http://www.gnu.org/licenses/>.
--
--
-- Copyright 2012 Vicente Ruiz Rodríguez <vruiz2.0@gmail.com>. All rights reserved.
--

do

	-- Create a new dissector
	MQTTPROTO = Proto("MQTT64", "MQ Telemetry Transport on 64Bits MessageId")


    global_mqtt_version_map = {}

	local f = MQTTPROTO.fields
	-- Fix header: byte 1
	f.message_type = ProtoField.uint8("mqtt64.message_type", "Message Type", base.HEX, nil, 0xF0)
	f.dup = ProtoField.uint8("mqtt64.dup", "DUP Flag", base.DEC, nil, 0x08)
	f.qos = ProtoField.uint8("mqtt64.qos", "QoS Level", base.DEC, nil, 0x06)
	f.retain = ProtoField.uint8("mqtt64.retain", "Retain", base.DEC, nil, 0x01)
	-- Fix header: byte 2
	f.remain_length = ProtoField.uint8("mqtt64.remain_length", "Remain Length")

	-- Connect
	f.connect_protocol_name = ProtoField.string("mqtt64.connect.protocol_name", "Protocol Name")
	f.connect_protocol_version = ProtoField.uint8("mqtt64.connect.protocol_version", "Protocol Version")
	f.connect_username = ProtoField.uint8("mqtt64.connect.username", "Username Flag", base.DEC, nil, 0x80)
	f.connect_password = ProtoField.uint8("mqtt64.connect.password", "Password Flag", base.DEC, nil, 0x40)
	f.connect_will_retain = ProtoField.uint8("mqtt64.connect.will_retain", "Will Retain Flag", base.DEC, nil, 0x20)
	f.connect_will_qos = ProtoField.uint8("mqtt64.connect.will_qos", "Will QoS Flag", base.DEC, nil, 0x18)
	f.connect_will = ProtoField.uint8("mqtt64.connect.will", "Will Flag", base.DEC, nil, 0x04)
	f.connect_clean_session = ProtoField.uint8("mqtt64.connect.clean_session", "Clean Session Flag", base.DEC, nil, 0x02)
	f.connect_keep_alive = ProtoField.uint16("mqtt64.connect.keep_alive", "Keep Alive (secs)")
	f.connect_payload_clientid = ProtoField.string("mqtt64.connect.payload.clientid", "Client ID")
	f.connect_payload_username = ProtoField.string("mqtt64.connect.payload.username", "Username")
	f.connect_payload_password = ProtoField.string("mqtt64.connect.payload.password", "Password")

	f.connack_flags_reseverd = ProtoField.uint8("mqtt64.connack.resverd", "resverd", base.DEC, nil, 0xFE)
	f.connack_flags_present = ProtoField.uint8("mqtt64.connack.present", "present", base.DEC, nil, 0x01)
	f.connack_status_code = ProtoField.uint8("mqtt64.connack.status", "status code")
	-- Publish
	f.publish_topic = ProtoField.string("mqtt64.publish.topic", "Topic")
	f.topic_len = ProtoField.int16("mqtt64.publish.topic_len", "TopicLength")
	f.publish_message_id = ProtoField.uint64("mqtt64.publish.message_id", "Message ID")
	f.publish_data = ProtoField.string("mqtt64.publish.data", "Data")

	-- Subscribe
	f.subscribe_message_id = ProtoField.uint64("mqtt64.subscribe.message_id", "Message ID")
	f.subscribe_topic = ProtoField.string("mqtt64.subscribe.topic", "Topic")
	f.subscribe_qos = ProtoField.uint8("mqtt64.subscribe.qos", "QoS")

	-- SubAck
	f.suback_qos = ProtoField.uint8("mqtt64.suback.qos", "QoS")

	-- Suback
	f.suback_message_id = ProtoField.uint64("mqtt64.suback.message_id", "Message ID")
	f.suback_qos = ProtoField.uint8("mqtt64.suback.qos", "QoS")
	--
	f.payload_data = ProtoField.bytes("mqtt64.payload", "Payload Data")

	-- ext
	f.ext_status = ProtoField.uint8("mqtt64.ext.status", "Status")
	f.ext_data = ProtoField.string("mqtt64.ext.data", "Ext Data")
	f.ext_command = ProtoField.string("mqtt64.ext.comand", "Command name")
	f.ext_command_code = ProtoField.uint8("mqtt64.ext.comand_code", "Command code")
	f.ext_payload_length = ProtoField.uint16("mqtt64.ext.payload_length", "ext payload lenght")
	f.ext_message_id = ProtoField.uint64("mqtt64.ext.message_id", "Ext Message ID")
    f.ext_publish_topic = ProtoField.string("mqtt64.ext.publish_key.topic", "Topic")
    f.ext_publish_payload = ProtoField.string("mqtt64.ext.publish_key.payload", "Payload")
    f.ext_publish_qos = ProtoField.string("mqtt64.ext.publish_key.qos", "QoS")
    f.ext_publish_ttl = ProtoField.string("mqtt64.ext.publish_key.ttl", "TTL")
    f.ext_publish_delay = ProtoField.string("mqtt64.ext.publish_key.delay", "Time delay")
    f.ext_publish_location = ProtoField.string("mqtt64.ext.publish_key.location", "Location")
    f.ext_publish_apns_json = ProtoField.string("mqtt64.ext.publish_key.apns_json", "Apns Json")
    f.ext_publish_third_party_push = ProtoField.string("mqtt64.ext.publish_key.third_party_json", "Third party Json")
    f.ext_publish_platform = ProtoField.string("mqtt64.ext.publish_key.platform", "platform")

    local new_publish_types = { 1, 2, 3, 4, 5, 6, 7, 8}
    -- new_publish_types[0] = "TOPIC"
    new_publish_types[0] = f.ext_publish_topic
    new_publish_types[1] = f.ext_publish_payload
    new_publish_types[2] = f.ext_publish_platform
    new_publish_types[3] = f.ext_publish_ttl
    new_publish_types[4] = f.ext_publish_delay
    new_publish_types[5] = f.ext_publish_location
    new_publish_types[6] = f.ext_publish_qos
    new_publish_types[7] = f.ext_publish_apns_json
    new_publish_types[8] = f.ext_publish_third_party_push

    local f_tcp_stream = Field.new("tcp.stream")
    mqtt_version_map = {}

	-- decoding of fixed header remaining length
	-- according to MQTT V3.1
	function lengthDecode(buffer, offset)
		local multiplier = 1
		local value = 0
		local digit = 0
		repeat
			 digit = buffer(offset, 1):uint()
			 offset = offset + 1
			 value = value + bit32.band(digit,127) * multiplier
			 multiplier = multiplier * 128
		until (bit32.band(digit,128) == 0)
		return offset, value
	end

	-- The dissector function
	function MQTTPROTO.dissector(buffer, pinfo, tree)
		pinfo.cols.protocol = "MQTT"
		local msg_types = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 }
		msg_types[1] = "CONNECT"
		msg_types[2] = "CONNACK"
		msg_types[3] = "PUBLISH"
		msg_types[4] = "PUBACK"
		msg_types[5] = "PUBREC"
		msg_types[6] = "PUBREL"
		msg_types[7] = "PUBCOMP"
		msg_types[8] = "SUBSCRIBE"
		msg_types[9] = "SUBACK"
		msg_types[10] = "UNSUBSCRIBE"
		msg_types[11] = "UNSUBACK"
		msg_types[12] = "PINGREQ"
		msg_types[13] = "PINGRESP"
		msg_types[14] = "DISCONNECT"
		msg_types[15] = "EXT CMD"


        local ext_cmd_type = { -1, 1, 2, 3, 13, 4, 14, 5, 15, 6, 16, 7, 8, 9, 19, 10, 20, 11 }
        ext_cmd_type[-1] = "CMD_UNKOWN"
        ext_cmd_type[1] = "CMD_GET_ALIAS"
        ext_cmd_type[2] = "CMD_GET_ALIAS_ACK"
        ext_cmd_type[3] = "CMD_GET_TOPIC_LIST"
        ext_cmd_type[13] = "CMD_GET_TOPIC_LIST2"
        ext_cmd_type[4] = "CMD_GET_TOPIC_LIST_ACK"
        ext_cmd_type[14] = "CMD_GET_TOPIC_LIST_ACK2"
        ext_cmd_type[5] = "CMD_GET_ALIASLIST"
        ext_cmd_type[15] = "CMD_GET_ALIASLIST2"
        ext_cmd_type[6] = "CMD_GET_ALIASLIST_ACK"
        ext_cmd_type[16] = "CMD_GET_ALIASLIST_ACK2"
        ext_cmd_type[7] = "CMD_PUBLISH2"
        ext_cmd_type[8] = "CMD_PUBLISH2_ACK"
        ext_cmd_type[9] = "CMD_GET_STATUS"
        ext_cmd_type[19] = "CMD_GET_STATUS2"
        ext_cmd_type[10] = "CMD_GET_STATUS_ACK"
        ext_cmd_type[20] = "CMD_GET_STATUS_ACK2"
        ext_cmd_type[11] = "CMD_RECVACK"


        local total_offset = 0

        while total_offset < buffer:len() do
            local offset = total_offset
            local msgtype = buffer(offset, 1)

            offset = offset + 1
            local remain_length =0 
            offset, remain_length = lengthDecode(buffer, offset)

            local msgindex = msgtype:bitfield(0,4)

            local subtree = tree:add(MQTTPROTO, buffer())
            local fixheader_subtree = subtree:add("Fixed Header", nil)

            subtree:append_text(", Message Type: " .. msg_types[msgindex])
            local old_info = pinfo.cols.info
            local new_info = "[MQTT " .. msg_types[msgindex] .. "] "  .. tostring(old_info)
            pinfo.cols.info:set(new_info)

            fixheader_subtree:add(f.message_type, msgtype)
            fixheader_subtree:add(f.dup, msgtype)
            fixheader_subtree:add(f.qos, msgtype)
            fixheader_subtree:add(f.retain, msgtype)

            fixheader_subtree:add(f.remain_length, remain_length)

            local fixhdr_qos = msgtype:bitfield(5,2)
            subtree:append_text(", QoS: " .. fixhdr_qos)

            if(msgindex == 1) then -- CONNECT

                local varheader_subtree = subtree:add("Variable Header", nil)

                local name_len = buffer(offset, 2):uint()
                offset = offset + 2
                local name = buffer(offset, name_len)
                offset = offset + name_len
                local version = buffer(offset, 1)
                offset = offset + 1
                local flags = buffer(offset, 1)
                offset = offset + 1
                local keepalive = buffer(offset, 2)
                offset = offset + 2

                varheader_subtree:add(f.connect_protocol_name, name)
                varheader_subtree:add(f.connect_protocol_version, version)

                local f_stream = f_tcp_stream().value
                mqtt_version_map[f_stream] = tostring(version)

                global_mqtt_version = version

                local flags_subtree = varheader_subtree:add("Flags", nil)
                flags_subtree:add(f.connect_username, flags)
                flags_subtree:add(f.connect_password, flags)
                flags_subtree:add(f.connect_will_retain, flags)
                flags_subtree:add(f.connect_will_qos, flags)
                flags_subtree:add(f.connect_will, flags)
                flags_subtree:add(f.connect_clean_session, flags)

                varheader_subtree:add(f.connect_keep_alive, keepalive)

                local payload_subtree = subtree:add("Payload", nil)
                -- Client ID
                local clientid_len = buffer(offset, 2):uint()
                offset = offset + 2
                local clientid = buffer(offset, clientid_len)
                offset = offset + clientid_len
                payload_subtree:add(f.connect_payload_clientid, clientid)
                -- Flags
                if(flags:bitfield(0) == 1) then -- Username flag is true
                    local username_len = buffer(offset, 2):uint()
                    offset = offset + 2
                    payload_subtree:add("username_len", tostring(username_len))
                    local username = buffer(offset, username_len)
                    offset = offset + username_len
                    payload_subtree:add(f.connect_payload_username, username)
                end

                if(flags:bitfield(1) == 1) then -- Password flag is true
                    local password_len = buffer(offset, 2):uint()
                    offset = offset + 2
                    payload_subtree:add("password_len", tostring(password_len))
                    local password = buffer(offset, password_len)
                    offset = offset + password_len
                    payload_subtree:add(f.connect_payload_password, password)
                end

            elseif(msgindex == 2) then -- CONNACK 
                local connect_acknowlege_flags = buffer(offset, 1)
                offset = offset + 1
                local varheader_subtree = subtree:add("Variable Header", nil)
                local flags_subtree = varheader_subtree:add("Ack Flags", nil)
                flags_subtree:add(f.connack_flags_reseverd, connect_acknowlege_flags)
                flags_subtree:add(f.connack_flags_present, connect_acknowlege_flags)

                local connect_return_code = buffer(offset, 1)
                offset = offset + 1
                local flags_subtree = varheader_subtree:add(f.connack_status_code, connect_return_code)

            elseif(msgindex == 3) then -- PUBLISH
                local f_stream = f_tcp_stream().value
                local version_num = mqtt_version_map[f_stream]

                local varhdr_init = offset -- For calculating variable header size
                local varheader_subtree = subtree:add("Variable Header", nil)

                local topic_len = buffer(offset, 2):uint()
                offset = offset + 2
                local topic = buffer(offset, topic_len)
                offset = offset + topic_len

                varheader_subtree:add(f.publish_topic, topic)

                if(fixhdr_qos > 0) then
                    local message_id_length = 8
                    if (version_num ~= "13") then
                        message_id_length = 2
                    end
                    local message_id = buffer(offset, message_id_length)
                    offset = offset + message_id_length
                    varheader_subtree:add(f.publish_message_id, message_id)
                end

                local payload_subtree = subtree:add("Payload", nil)
                -- Data
                local data_len = remain_length - (offset - varhdr_init)
                local data = buffer(offset, data_len)
                offset = offset + data_len
                payload_subtree:add(f.publish_data, data)


            elseif(msgindex == 8 or msgindex == 10) then -- SUBSCRIBE & UNSUBSCRIBE
                local varheader_subtree = subtree:add("Variable Header", nil)

                local f_stream = f_tcp_stream().value
                local version_num = mqtt_version_map[f_stream]

                local message_id_length = 8
                if (version_num ~= "13") then
                    message_id_length = 2
                end
                local message_id = buffer(offset, message_id_length)
                offset = offset + message_id_length
                varheader_subtree:add(f.subscribe_message_id, message_id)

                local payload_subtree = subtree:add("Payload", nil)
                while(offset < buffer:len()) do
                    local topic_len = buffer(offset, 2):uint()
                    offset = offset + 2
                    local topic = buffer(offset, topic_len)
                    offset = offset + topic_len

                    local topic_subtree = payload_subtree:add(f.subscribe_topic, topic)
                    topic_subtree:add(f.topic_len, topic_len)
                    if(msgindex == 8) then -- QoS byte only for subscription
                        local qos = buffer(offset, 1)
                        offset = offset + 1
                        topic_subtree:add(f.subscribe_qos, qos)
                    end
                end

            elseif(msgindex == 9 or msgindex == 11) then -- SUBACK & UNSUBACK
                local varheader_subtree = subtree:add("Variable Header", nil)

                local f_stream = f_tcp_stream().value
                local version_num = mqtt_version_map[f_stream]

                local message_id_length = 8
                if (version_num ~= "13") then
                    message_id_length = 2
                end
                local message_id = buffer(offset, message_id_length)
                offset = offset + message_id_length
                varheader_subtree:add(f.suback_message_id, message_id)

                local payload_subtree = subtree:add("Payload", nil)
                while(offset < buffer:len()) do
                    local qos = buffer(offset, 1)
                    offset = offset + 1
                    payload_subtree:add(f.suback_qos, qos);
                end

            elseif(msgindex == 15) then -- EXT CMD
                local varhdr_init = offset -- For calculating variable header size
                local varheader_subtree = subtree:add("Variable Header", nil)

                --this ext command is set to 8 bytes
                local message_id = buffer(offset, 8)
                offset = offset + 8
                varheader_subtree:add(f.ext_message_id, message_id)


                local payload_subtree = subtree:add("Payload", nil)
                -- Data
                local command_name = buffer(offset, 1)
                offset = offset + 1

                payload_subtree:add(f.ext_command, ext_cmd_type[command_name:uint()])
                payload_subtree:add(f.ext_command_code, command_name)

                if(command_name:uint() % 2 == 0) then -- ext_ack
                    local ret_status = buffer(offset, 1)
                    offset = offset + 1
                    payload_subtree:add(f.ext_status, ret_status)
                end

                local data_len = buffer(offset, 2)
                offset = offset + 2
                payload_subtree:add(f.ext_payload_length, data_len)
                if(command_name:uint() == 7)then -- new_publish_tlv
                    while (offset < buffer:len()) do

                        local publish_type = buffer(offset, 1)
                        offset = offset + 1

                        local value_lenght = buffer(offset, 2)
                        offset = offset + 2

                        local ext_value = buffer(offset, value_lenght:uint())
                        payload_subtree:add(new_publish_types[publish_type:uint()], ext_value)
                        offset = offset + value_lenght:uint()
                    end
                else
                    local data = buffer(offset, data_len:uint())
                    offset = offset + data_len:uint()

                    payload_subtree:add(f.ext_data, data)
                end

            else
                if((buffer:len()-offset) > 0) then
                    local payload_subtree = subtree:add("Payload", nil)
                    payload_subtree:add(f.payload_data, buffer(offset, buffer:len()-offset))
                    offset = buffer:len()
                end
            end
            total_offset = offset
        end


	end

	-- Register the dissector
	tcp_table = DissectorTable.get("tcp.port")
	tcp_table:add(1883, MQTTPROTO)
end
