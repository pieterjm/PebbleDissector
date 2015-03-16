-- A simple Pebble protocol dissector
pebble_proto = Proto("pebble","Pebble Protocol")

pebble_endpoint = ProtoField.uint16("pebble.endpoint","Endpoint")
pebble_length = ProtoField.uint16("pebble.length","Length")

lookup_amsg_type = {
	  [1] = "PUSH",
	  [2] = "REQUEST",
	  [127] = "NACK",
	  [255] = "ACK"	  
}

lookup_endpoint = {
 [11] = "TIME",
 [16] = "VERSION",
 [17] = "PHONE_VERSION",
 [18] = "SYSTEM_MESSAGE",
 [32] = "MUSIC_CONTROL",
 [33] = "PHONE_CONTROL",
 [48] = "APPLICATION_MESSAGE",
 [49] = "LAUNCHER",
 [2000] = "LOGS",
 [2001] = "PING",
 [2002] = "LOG_DUMP",
 [2003] = "RESET",
 [2004] = "APP",
 [2006] = "APP_LOGS",
 [3010] = "EXTENSIBLE_NOTIFS",
 [4000] = "RESOURCE",
 [5000] = "SYS_REG",
 [5001] = "FCT_REG",
 [6778] = "DATA_LOG",
 [6000] = "APP_MANAGER",
 [6001] = "APP_FETCH",
 [8000] = "SCREENSHOT",
 [9000] = "COREDUMP",
 [45531] = "BLOB_DB",
 [48879] = "PUTBYTES",
 [10000] = "AUDIO",
}

function pebble_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "PEBBLE"
    local subtree = tree:add(pebble_proto,buffer(),"Pebble Protocol Data")

    -- extract length and endpoint from the four byte header    
    local len = buffer(0,2):uint()	
    local endpoint = buffer(2,2):uint()

    subtree:add(buffer(0,2),"Length: " .. len)    
    subtree:add(buffer(2,2),"Endpoint: " .. lookup_endpoint[endpoint] .. "(" .. endpoint .. ")")

    pinfo.cols.info = lookup_endpoint[endpoint]

    subtree = subtree:add(buffer(4,len),lookup_endpoint[endpoint])	

    -- here we only decode the first bytes of the application message
    if endpoint == 48 then
       -- application message
       local amsg_type = buffer(4,1):uint()
       local amsg_tid = buffer(5,1):uint()  
       

       subtree:add(buffer(4,1),"Type: " .. lookup_amsg_type[amsg_type] .. "(" .. amsg_type .. ")" )    
       subtree:add(buffer(5,1),"Transaction Id: " .. amsg_tid)

       pinfo.cols.info:append(" (" .. lookup_amsg_type[amsg_type] .. ")")
    end

end



-- add the dissector
rfcomm_table = DissectorTable.get("btrfcomm.service")
rfcomm_table:add(0,pebble_proto)

