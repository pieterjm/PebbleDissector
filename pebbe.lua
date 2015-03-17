-- A simple Pebble protocol dissector
pebble_proto = Proto("pebble","Pebble Protocol")

pebble_endpoint = ProtoField.uint16("pebble.endpoint","Endpoint")
pebble_length = ProtoField.uint16("pebble.length","Length")

lookup_tuple_type = {
		 [0] = "BYTE_ARRAY",
		 [1] = "CSTRING",
		 [2] = "UINT",
		 [3] = "INT"
}

lookup_amsg = {
	  [1] = {
	      name = "PUSH",
	      dissector = function(buffer,pinfo,tree)
	      		local uuid = buffer(0,16)
			local numtuples = buffer(16,1):uint()
			tree:add(buffer(0,16),"UUID: " ..uuid)
			tree:add(buffer(16,1),"Number of tuples: " .. numtuples)

			offset = 17
			for i = 1,numtuples do
			    subtree = tree:add(buffer(0,0),"Tuple " .. i)
			    subtree:add(buffer(offset,4),"Key: " .. buffer(offset,4):le_uint())

			    local type = buffer(offset + 4,1):uint()
			    subtree:add(buffer(offset + 4,1),"Type: " .. lookup_tuple_type[type] .. " (" .. type .. ")")

			    local length = buffer(offset + 5,2):le_uint()
			    subtree:add(buffer(offset + 5,2),"Length: " .. length )

			    local value = "undefined"
			    if type == 2 then
			       value = buffer(offset + 7,length):le_uint()
			    elseif type == 3 then
			       value = buffer(offset + 7,length):le_int()
			    end

			    subtree:add(buffer(offset + 7,length),"Value: " .. value )
			    offset = offset + 7 + length
			end
	      end
	  },
	  [2] = {
	      name = "REQUEST"
	  },
	  [127] = {
	  	name = "NACK"
	  },
	  [255] = {
	  	name = "ACK"	 
	  } 
}

lookup_endpoint = {
 [11] = {
      name = "TIME"
 },
 [16] = {
      name = "VERSION"
 },
 [17] = {
	name = "PHONE_VERSION"
	},
 [18] = {
	name = "SYSTEM_MESSAGE"
	},
 [32] = {
	name = "MUSIC_CONTROL"
	},
 [33] = {
	name = "PHONE_CONTROL"
	},
 [48] = {
	name = "APPLICATION_MESSAGE",
	dissector = function(buffer,pinfo,tree) 
       		  local type = buffer(0,1):uint()
       		  local transactionid = buffer(1,1):uint() 
		  local len = buffer:len()
       		  

		  local amsg = lookup_amsg[type]
		  if amsg then
		  	 pinfo.cols.info:append(" (" .. amsg.name .. ")")
			 tree:add(buffer(0,1),"Type: " .. amsg.name .. "(" .. type .. ")" )    
       		  	 tree:add(buffer(1,1),"Transaction Id: " .. transactionid)		  
			 if len > 2 and amsg.dissector then
			    tree = tree:add(buffer(2,len - 2),amsg.name)
		     	    amsg.dissector(buffer(2, len - 2),pinfo,tree)
		  	 end	
		  else
		  	 pinfo.cols.info = "ERROR: Unknown application message type (" .. type .. ")"
		  end
        end
	},
 [49] = {
	name = "LAUNCHER"
	},
 [2000] = {
	name = "LOGS"
	},
 [2001] = {
	name = "PING"
	},
 [2002] = {
	name = "LOG_DUMP"
	},
 [2003] = {
	name = "RESET"
	},
 [2004] = {
	name = "APP"
	},
 [2006] = {
	name = "APP_LOGS"
	},
 [3010] = {
	name = "EXTENSIBLE_NOTIFS"
	},
 [4000] = {
	name = "RESOURCE"
	},
 [5000] = {
	name = "SYS_REG"
	},
 [5001] = {
	name = "FCT_REG"
	},
 [6778] = {
	name = "DATA_LOG",
	dissector = function(buffer,pinfo,tree) 
       		  local type = buffer(0,1):uint()
       		  local logid = buffer(1,1):uint()  
       		  tree:add(buffer(0,1),"Type: " .. type )
       		  tree:add(buffer(1,1),"Log Id: " .. logid)
       		  pinfo.cols.info:append(" (" .. type .. ")")
        end

	},
 [6000] = {
	name = "APP_MANAGER"
	},
 [6001] = {
	name = "APP_FETCH"
	},
 [8000] = {
	name = "SCREENSHOT"
	},
 [9000] = {
	name = "COREDUMP"
	},
 [45531] = {
	name = "BLOB_DB"
	},
 [48879] = {
	name = "PUTBYTES"
	},
 [10000] = {
	name = "AUDIO"
  }
}


function pebble_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "PEBBLE"
    local subtree = tree:add(pebble_proto,buffer(),"Pebble Protocol Data")

    if buffer:len() < 4 then
       pinfo.cols.info = "ERROR: header too short"
       return
    end

    -- extract length and endpoint from the four byte header    
    local len = buffer(0,2):uint()	
    local endpoint = buffer(2,2):uint()

    if not buffer:len() == len + 4 then
       pinfo.cols.info = "ERROR: message length mismatch"
       return
    end

    local ep = lookup_endpoint[endpoint]
    if not ep then
       pinfo.cols.info = "ERROR: Unknown endpoint (" .. endpoint .. ")"
       return
    end

    subtree:add(buffer(0,2),"Length: " .. len)    
    subtree:add(buffer(2,2),"Endpoint: " .. ep.name .. "(" .. endpoint .. ")")

    pinfo.cols.info = ep.name

    subtree = subtree:add(buffer(4,len),ep.name)	

    -- here we only decode the first bytes of the application message
    if ep.dissector then
       ep.dissector(buffer(4,len),pinfo,subtree)
    end

end



-- add the dissector
rfcomm_table = DissectorTable.get("btrfcomm.service")
rfcomm_table:add(0,pebble_proto)

