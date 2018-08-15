__author__ = 'Fel1iZ'

import socket
import threading
import struct
import select
import callovsdb
from collections import namedtuple
import logging
import datetime, time
import sys
import learningTopo
import connectDB
import json
from Queue import Queue


IP_FGBAM = "172.16.132.134"
PORT_FGBAM = 6634

IP_CONTROLLER = "172.16.132.134"
PORT_CONTROLLER = 6633

THREAD_LIST = []
RECVBUFFER = 65565

OFPT = {'0': "OFPT_HELLO",
        '1': "OFPT_ERROR",
        '2': "OFPT_ECHO_REQ",
        '3': "OFPT_ECHO_RES",
        '4': "OFPT_VENDOR",
        '5': "OFPT_FEATURE_REQ",
        '6': "OFPT_FEATURE_RES",
        '7': "OFPT_GET_CONFIG_REQ",
        '8': "OFPT_GET_CONFIG_RES",
        '9': "OFPT_SET_CONFIG",
        '10': "OFPT_PACKET_IN",
        '11': "OFPT_FLOW_REMOVED",
        '12': "OFPT_PORT_STATUS",
        '13': "OFPT_PACKET_OUT",
        '14': "OFPT_FLOW_MOD",
        '15': "OFPT_PORT_MOD",
        '16': "OFPT_STATS_REQ",
        '17': "OFPT_STATS_RES",
        '18': "OFPT_BARRIER_REQ",
        '19': "OFPT_BARRIER_RES",
        '20': "OFPT_QUEUE_GET_CONFIG_REQ",
        '21': "OFPT_GET_CONFIG_RES"}

_PAD = b'\x00'
_PAD2 = _PAD*2
_PAD3 = _PAD*3
_PAD6 = _PAD*6

Rules = namedtuple('Rules', ['protocol_id','src_ip', 'dst_ip','proto','src_port','dst_port','bandwidth','queue_id','uuid_queue'])

q = Queue(maxsize=1)
switches_list = []

def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b

class ofp_header(object):
    def __init__(self, msg = None):
        self.msg = msg
        self.current_index = 0
        self.version = None
        self.type = None
        self.l = None
        self.xid = None

    def unpack(self):
        current_index = 0
        # print "OpenFlow Header"
        of_header_hex = self.msg[current_index:current_index + 8]
        of_header = struct.unpack('!BBHL', of_header_hex)
        #print(of_header)
        self.version = of_header[0]
        self.type = of_header[1]
        self.l = of_header[2]
        self.xid = of_header[3]
        #print "version: %s type: %s length: %s xid: %s"% (str(version),OFPT[str(type)] + '(' + str(type) + ')',str(l),str(xid))

    def pack(self):
        temp = struct.pack('!BBHL',self.version,self.type,self.l,self.xid)

        return temp

class ofp_match(object):
    def __init__(self,match_tuple):
        self.match_tuple = match_tuple
        self.wildcards = 0
        self.in_port = 0
        self.dl_src = None
        self.dl_dst = None
        self.dl_vlan = None
        self.dl_pcp = None
        self.pad1 = _PAD
        self.dl_type = None
        self.nw_tos = None
        self.nw_proto = None
        self.pad2 = _PAD2
        self.nw_src = None
        self.nw_dst = None
        self.tp_src = None
        self.tp_dst = None



    def unpack(self):
        current_index = 8
        of_match_hex = self.match_tuple[current_index:current_index+40]
        of_match = struct.unpack('!LH6s6sHBBHBBH4s4sHH',of_match_hex)
	print of_match
        self.wildcards = of_match[0]
        self.in_port = of_match[1]
        self.dl_src = eth_addr(self.match_tuple[current_index+6:current_index+6+6])
        self.dl_dst = eth_addr(self.match_tuple[current_index+12:current_index+12+6])
        self.dl_vlan = of_match[4]
        self.dl_pcp = of_match[5]
        self.dl_type = of_match[7]
        self.nw_tos = of_match[8]
        self.nw_proto = of_match[9]
        self.nw_src = socket.inet_ntoa(of_match[11])
        self.nw_dst = socket.inet_ntoa(of_match[12])
        self.tp_src = of_match[13]
        self.tp_dst = of_match[14]

    def pack(self):
        packet = b""
        packet += struct.pack('!LH',self.wildcards,self.in_port)
        packet += struct.pack('!6B',*(int(x,16) for x in self.dl_src.split(':')))
        packet += struct.pack('!6B',*(int(x,16) for x in self.dl_dst.split(':')))
        packet += struct.pack('!HB',self.dl_vlan,self.dl_pcp)
        packet += self.pad1
        packet += struct.pack('!HBB',self.dl_type,self.nw_tos,self.nw_proto)
        packet += self.pad2
        packet += struct.pack('!4B',*(int(x) for x in self.nw_src.split('.')))
        packet += struct.pack('!4B',*(int(x) for x in self.nw_dst.split('.')))
        packet += struct.pack('!HH',self.tp_src,self.tp_dst)

        return packet


class ofp_action_output(object):
    def __init__(self,action_out):
        self.action_out = action_out
        self.type = 0
        self.len = 0
        self.out_port = 0
        self.max_bytes = 0

    def pack(self):
        packed = struct.pack('!HHHH',self.type,self.len,self.out_port,self.max_bytes)
        return packed

    def unpack(self):
        act_out = struct.unpack('!HHHH',self.action_out)
        self.type = act_out[0]
        self.len = act_out[1]
        self.out_port = act_out[2]
        self.max_bytes = act_out[3]


class ofp_action_enqueue(object):
    def __init__(self,port,queue_id):
        self.type = 11
        self.len = 16
        self.port = port
        self.pad = _PAD6
        self.queue_id = queue_id

    def pack(self):
        packed = b""
        packed += struct.pack('!HHH',self.type,self.len,self.port)
        packed += self.pad
        packed += struct.pack('!L',self.queue_id)

        return packed


class ofp_flow_mod(ofp_header):
    def __init__(self,msg):
        self.msg = msg
        ofp_header.__init__(self,self.msg)
        ofp_header.unpack(self)
        self.match = None
        self.cookie = 0
        self.command = 0
        self.idle_timeout = None
        self.hard_tineout = None
        self.priority = None
        self.buffer_id = None
        self.out_port = None
        self.flags = None
        self.type_action = None
        self.actions = []
        self.status_id = None

    """
    def check_inverse(self,flowmod_msg):
        condition1 = self.match.nw_src == flowmod_msg.match.nw_dst
        condition2 = self.match.nw_dst == flowmod_msg.match.nw_src
        condition3 = self.match.tp_src == flowmod_msg.match.tp_dst
        condition4 = self.match.tp_dst == flowmod_msg.match.tp_src
        condition5 = self.match.nw_proto == flowmod_msg.match.nw_proto

        if condition1 and condition2 and condition3 and condition4 and condition5:
            return True
        else:
            return False
    """
    def check_rules(self):
        temp_list = []
        connect_db = connectDB.get_QoS_setting();

        #Connected with DB Success!!
        if connect_db.connection_failed == False:

            connect_db.select_qosSetting_fgbamDB()
            protocol_number = {'tcp' : "6" , 'TCP' : "6" , 'udp' : "17" , 'UDP' : "17" ,'17' : "17" ,'6' : "6" ,'icmp' : "1"  , 'ICMP' : "1", '1' : "1", 'any' : "any"}

            table_qos_setting = connect_db.table_qos_setting
            print table_qos_setting

	    print "nw_src: " + str(self.match.nw_src)
	    print "nw_dst: " + str(self.match.nw_dst)
	    print "nw_proto: " + str(self.match.nw_proto)
	    print "tp_src: " + str(self.match.tp_src)
	    print "tp_dst: " + str(self.match.tp_dst)

            for record_qos_setting in table_qos_setting:
                flag = True
                count_any = 0
                if record_qos_setting[1] != self.match.nw_src and record_qos_setting[1] != "any":
                    flag = False
                else:
                    if record_qos_setting[1] != "any":
                        count_any += 1
                    if record_qos_setting[2] != self.match.nw_dst and record_qos_setting[2] != "any":
                        flag = False
                    else:
                        if record_qos_setting[2] != "any":
                            count_any += 1
                        if protocol_number[record_qos_setting[5]] != str(self.match.nw_proto) and protocol_number[record_qos_setting[5]] != "any":
                            flag = False
                        else:
                            if record_qos_setting[5] != "any":
                                count_any += 1
                            if record_qos_setting[3] != str(self.match.tp_src) and record_qos_setting[3] != "any":
                                flag = False
                            else:
                                if record_qos_setting[3] != "any":
                                    count_any += 1
                                if record_qos_setting[4] != str(self.match.tp_dst) and record_qos_setting[4] != "any":
                                    flag = False
                                else:
                                    if record_qos_setting[4] != "any":
                                        count_any += 1

                if flag == True:
                    temp_rule = Rules(record_qos_setting[0],record_qos_setting[1],record_qos_setting[2],record_qos_setting[5],record_qos_setting[3],record_qos_setting[4],record_qos_setting[6],None,None)
                    on_process = {'rule': temp_rule , 'count_any': count_any , 'status_id' : record_qos_setting[8]}
                    temp_list.append(on_process)


        #Have not any rules
        if len(temp_list) == 0:
            return False,None
        else:
            temp_list.sort()
            self.status_id = temp_list[0]['status_id']
            return True,temp_list[0]['rule']



    def unpack(self):

        self.match = ofp_match(self.msg)
        self.match.unpack()
        index = 48
        of_flow_mod_hex = self.msg[index:index+28]
        index += 24
        of_flow_mod = struct.unpack('!QHHHHLHHL',of_flow_mod_hex)
        self.cookie = of_flow_mod[0]
        self.command = of_flow_mod[1]
        self.idle_timeout = of_flow_mod[2]
        self.hard_timeout = of_flow_mod[3]
        self.priority = of_flow_mod[4]
        self.buffer_id = of_flow_mod[5]
        self.out_port = of_flow_mod[6]
        self.flags = of_flow_mod[7]
        self.type_action = (of_flow_mod[8] & 0xFFFF0000) >> 16

        #print(of_flow_mod)
        #print(self.type_action)

        if self.type_action == 0:
            action_out = ofp_action_output(self.msg[index:index+8])
            action_out.unpack()
            self.actions.append(action_out)


    def pack(self):
        packet = b""
        packet += self.match.pack()
        packet += struct.pack('!QHHHHLHH',self.cookie,self.command,self.idle_timeout,self.hard_timeout,self.priority,self.buffer_id,self.out_port,self.flags)
        for action in self.actions:
            packet += action.pack()

        return packet


class ofp_feature_response(ofp_header):
    def __init__(self,msg):
        self.msg = msg
        ofp_header.__init__(self,self.msg)
        ofp_header.unpack(self)
        self.datapath_id = 0
        self.n_buffers = 0
        self.n_tables = 0
        self.pad = _PAD3
        self.capabilities = 0
        self.actions = 0
        self.phy_port = []

    def convert_name_port(self,n):
        name_converted = ''
        for index in range(16):
            if (ord(n[index]) != 0):
                name_converted += "%x" % ord(n[index])

        if len(name_converted) % 2 == 1:
            name_converted += "0"

        temp = name_converted.decode("hex")
        return str(temp)

    def unpack(self):
        current_index = 8
        of_feaRes_hex = self.msg[current_index:current_index+24]
        of_feaRes = struct.unpack('!QLB3sLL',of_feaRes_hex)

        self.datapath_id = of_feaRes[0]
        self.n_buffers = of_feaRes[1]
        self.n_tables = of_feaRes[2]
        self.capabilities = of_feaRes[4]
        self.actions = of_feaRes[5]

        current_index += 24

        num_of_port = (len(self.msg) - current_index) / 48

        port = namedtuple('port', ['number', 'mac_addr', 'name' , 'neighbor'])

        for index in range(num_of_port):
            port_def_hex = self.msg[current_index:current_index+48]
            port_def = struct.unpack('!H6s16sLLLLLL',port_def_hex)



            p = port(port_def[0],eth_addr(port_def[1]),self.convert_name_port(port_def[2]),None)
            self.phy_port.append(p)

            current_index += 48

        return self.phy_port

#list_localPort = []

class communication_SwCtrler(threading.Thread):
    def __init__(self, conn, ip, port):
        super(communication_SwCtrler,self).__init__()
        self._stop = threading.Event()
        self.ip = ip
        self.port = port
        self.conn = conn
        self.list_sock = []
        self.list_sock.append(self.conn)
        self.list_ports = []
        self.list_rule_added = []
        self.current_id = 0
        self.datapath_id = None # id of switch
        self.numOfphyPort = 0
        self.neighbor = {}
        self.localPort = None
        self.nameOfSwitch = None
        self.list_hostsIP = []

    def match_nameport(self,outport):
        if self.list_ports:
            for nameport in self.list_ports:
                #print "outport: " + str(outport)
                #print "dasd: " + nameport.name[-1:]
                if outport == nameport.number:
                    return nameport.name

    def isAdded(self,r):
        for rule in self.list_rule_added:
            codition1 = rule.src_ip == r.src_ip
            codition2 = rule.dst_ip == r.dst_ip
            codition3 = rule.proto == r.proto
            codition4 = rule.src_port == r.src_port
            codition5 = rule.dst_port == r.dst_port
            if codition1 and codition2 and codition3 and codition4 and codition5:
                return True,rule.queue_id

        return False,None

    def onProcessed(self,fm,command):
        temp_list = []
        #print self.list_rule_added
        for rule in self.list_rule_added:
            flag = True
            count_any = 0
            if command == "update":
                if str(rule.protocol_id) == str(fm.protocol_id):
                    return True
            elif command == "delete":
                if str(rule.protocol_id) == str(fm.protocol_id):
                    temp_queue_id = rule.queue_id
                    self.list_rule_added.remove(rule)
                    return True,temp_queue_id
            else:
                if str(rule.src_ip) != str(fm.match.nw_src) and str(rule.src_ip) != "any":
                    flag = False
                else:
                    if str(rule.src_ip) == "any":
                        count_any += 1
                    if str(rule.dst_ip) != str(fm.match.nw_dst) and str(rule.dst_ip) != "any":
                        flag = False
                    else:
                        if str(rule.dst_ip) == "any":
                            count_any += 1
                        if str(rule.proto) != str(fm.match.nw_proto) and str(rule.proto) != "any":
                            flag = False
                        else:
                            if str(rule.proto) == "any":
                                count_any += 1
                            if str(rule.src_port) != str(fm.match.tp_src) and str(rule.src_port) != "any":
                                flag = False
                            else:
                                if str(rule.src_port) == "any":
                                    count_any += 1
                                if str(rule.dst_port) != str(fm.match.tp_dst) and str(rule.dst_port) != "any":
                                    flag = False
                                else:
                                    if str(rule.dst_port) == "any":
                                        count_any += 1


                if flag == True:
                    on_process = {'rule': rule , 'count_any': count_any}
                    temp_list.append(on_process)

        if command == "check":
            #print "Hellooooooooooooooooooooooooooooooo"
            if len(temp_list) == 0:
                return False,None
            else:
                print "Match Rule On Processing!!!!!"
                temp_list.sort()
                return True,temp_list[0]['rule'].queue_id

        return False


    def update_list_rule_added(self,r):
        for index,rule in enumerate(self.list_rule_added):
            if rule.protocol_id == r.protocol_id:
                temp = Rules(rule.protocol_id,r.src_ip,r.dst_ip,r.proto,r.src_port,r.dst_port,r.bandwidth,rule.queue_id,rule.uuid_queue)
                self.list_rule_added[index] = temp
                return temp

    def isInverse(self,flowmod):
        if self.list_rule_added:
            for rule in self.list_rule_added:
                codition1 = rule.src_ip == flowmod.match.nw_dst
                codition2 = rule.dst_ip == flowmod.match.nw_src
                codition3 = rule.proto == flowmod.match.nw_proto
                codition4 = rule.src_port == flowmod.match.tp_dst
                codition5 = rule.dst_port == flowmod.match.tp_src

                if codition1 and codition2 and codition3 and codition4 and codition5:
                    return (True,rule)
                else:
                    return (False,None)
        else:
            return (False,None)

    def stopped(self):
        return self._stop.isSet()

    def stop(self):
        self._stop.set()

    def update_listPort(self,neighbor_port_mac,in_port):
        port = namedtuple('port', ['number', 'mac_addr', 'name' , 'neighbor'])
        for _port in self.list_ports:
            if _port.number == in_port:

                for _thread in THREAD_LIST:
                    try:
                        if _thread.localPort.mac_addr == neighbor_port_mac:
                            neighbor_port = _thread.localPort
                            self.neighbor[str(in_port)] = _thread.localPort.name
                            temp_port = port(_port.number,_port.mac_addr,_port.name,neighbor_port)
                            self.list_ports.append(temp_port)
                            self.list_ports.remove(_port)
                            break
                        else:
                            for list_port in _thread.list_ports:
                                if list_port.mac_addr == neighbor_port_mac:
                                    neighbor_port = _thread.localPort
                                    self.neighbor[str(in_port)] = _thread.localPort.name
                                    temp_port = port(_port.number,_port.mac_addr,_port.name,neighbor_port)
                                    self.list_ports.append(temp_port)
                                    try:
                                        self.list_ports.remove(_port)
                                    except ValueError:
                                        print "all port: "  + str(self.list_ports)
                                        print "port: " + str( _port)
                                    break
                    except AttributeError:
                        try:
                            for list_port in _thread.list_ports:
                                    if list_port.mac_addr == neighbor_port_mac:
                                        neighbor_port = _thread.localPort
                                        self.neighbor[str(in_port)] = _thread.localPort.name
                                        temp_port = port(_port.number,_port.mac_addr,_port.name,neighbor_port)
                                        self.list_ports.append(temp_port)
                                        self.list_ports.remove(_port)

                                        break
                        except AttributeError:
                            print "NoneType"
                            break



    def isIP(self,temp):
        try:
            _arr = temp.split(".")
        except AttributeError:
            return False

        if len(_arr) == 4:
            for index in _arr:
                if int(index) > 255 or int(index) < 0:
                    return False
        else:
            return False

        return True
    def isMac(self,temp):
        try:
            _arr = temp.split(":")
        except AttributeError:
            return False

        if len(_arr) == 6:
            for index in _arr:
                if int(index,16) > 255 or int(index,16) < 0:
                    return False
        else:
            return False

        return True
    def isHostAdded(self,ip_host):
        for _thread in THREAD_LIST:
            for host in _thread.list_hostsIP:
                if host == ip_host:
                    return True

        return False



    def run(self):
        port = namedtuple('port', ['number', 'mac_addr', 'name' , 'neighbor'])
        sockCtrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sockCtrl.connect((IP_CONTROLLER, PORT_CONTROLLER))
        self.list_sock.append(sockCtrl)
        print str(self.ip) + ':' + str(self.port) + " connected with controller"
        flag2 = True
	t1=0

        while not self.stopped():
            readsocks, writesocks, errorsocks = select.select(self.list_sock, [], [])

            for sock in readsocks:
                #Handle data from SDN Controller
                if sock == sockCtrl:
                    data_from_controller = sockCtrl.recvfrom(RECVBUFFER)
		    t1 = time.time()
		    #print "data_from_controller: ",data_from_controller
                    data_from_controller = data_from_controller[0]
		    #print "data_from_controller[0]: ",data_from_controller[0]
                    if len(data_from_controller) >= 8:
                        of_header = ofp_header(data_from_controller)
                        #print "From Controller:"
                        of_header.unpack()


                        if of_header.type == 14 and len(data_from_controller) >= 80:

                            #print "flowmod"
                            flowmod_msg = ofp_flow_mod(data_from_controller)
                            flowmod_msg.unpack()
				
                            flag1,rule = flowmod_msg.check_rules()
                            if flag1:
                                flag2,queue_id = self.isAdded(rule)
                            

                            print 'flag1: ' + str(flag1)
                            print 'flag2: ' + str(flag2)
                            print 'rule' + str(rule)

                            if flowmod_msg.actions:
                                name_port = self.match_nameport(flowmod_msg.actions[0].out_port)
			    	print "flowmod_msg.actions: ", flowmod_msg.actions
                            	print "flowmod_msg.actions[0].out_port: "  + str(flowmod_msg.actions[0].out_port)
				if name_port:
			    		print "nameport: " + str(name_port)

                            #flag,rule_inverse = self.isInverse(flowmod_msg)
                            #print 'flag: ' + str(flag)
                            update_db = connectDB.get_QoS_setting()
			    #print "flowmod_msg.actions: ", flowmod_msg.actions
                            #print "flowmod_msg.actions[0].out_port: "  + str(flowmod_msg.actions[0].out_port)
                            #print "nameport: " + str(name_port)

                            if flag1 and name_port is not None and (flowmod_msg.match.nw_proto == 6 or flowmod_msg.match.nw_proto == 17 or flowmod_msg.match.nw_proto == 1):
                                print "flowmod_msg.status_id: " + str(flowmod_msg.status_id)


                                if not flag2 and  flowmod_msg.status_id == 0:

                                    self.current_id ,queue_id,uuid_queue = callovsdb.create_queue(name_port,rule.bandwidth,self.current_id,str(self.ip),6640)
                                    logging.info('create queue: '+str(datetime.datetime.now().date())+' '+str(datetime.datetime.now().time()) +' queue#' + str(queue_id) + ' in ' + str(name_port))
                                    r = Rules(rule.protocol_id,rule.src_ip,rule.dst_ip,rule.proto,rule.src_port,rule.dst_port,rule.bandwidth,queue_id,uuid_queue)

                                    #r = Rules(rule.protocol_id,flowmod_msg.match.nw_src,flowmod_msg.match.nw_dst,flowmod_msg.match.nw_proto,flowmod_msg.match.tp_src,flowmod_msg.match.tp_dst,rule.bandwidth,queue_id,uuid_queue)
                                    logging.info(str(datetime.datetime.now().date())+' '+str(datetime.datetime.now().time())+ ' ' +str(r) )
                                    #self.list_rule_added.append(r)

                                elif flowmod_msg.status_id == 1:
                                    print "DELETE"
                                    temp,queue_id = self.onProcessed(rule,"delete")

                                    if temp:
                                        for _port in self.list_ports:
                                            if str(_port.number) == str(flowmod_msg.actions[0].out_port):
                                                callovsdb.delete_queue(queue_id,_port.name,1,str(self.ip),6640)
                                                break

                                    queue_id = 0



                                elif flowmod_msg.status_id == 2:
                                    print "UPDATE"
                                    flag_on_process = self.onProcessed(rule,"update")
                                    #print "flag_on_prosses: " + str(flag_on_process)

                                    if flag_on_process:
                                        #print "On Process!!!!"
                                        rule_update = self.update_list_rule_added(rule)
                                        callovsdb.update_queue(rule_update.uuid_queue,rule_update.bandwidth,rule_update.bandwidth,1,str(self.ip),6640)
                                        queue_id = rule_update.queue_id

                                    else:
                                        self.current_id ,queue_id,uuid_queue = callovsdb.create_queue(name_port,rule.bandwidth,self.current_id,str(self.ip),6640)
                                        logging.info('create queue: '+str(datetime.datetime.now().date())+' '+str(datetime.datetime.now().time()) +' queue#' + str(queue_id) + ' in ' + str(name_port))

                                        r = Rules(rule.protocol_id,flowmod_msg.match.nw_src,flowmod_msg.match.nw_dst,flowmod_msg.match.nw_proto,flowmod_msg.match.tp_src,flowmod_msg.match.tp_dst,rule.bandwidth,queue_id,uuid_queue)
                                        logging.info(str(datetime.datetime.now().date())+' '+str(datetime.datetime.now().time())+ ' ' +str(r) )
                                        #self.list_rule_added.append(r)

                                print "queue_id: ", queue_id
				print "flowmod_msg.actions", flowmod_msg.actions
                                enqueue_msg = ofp_action_enqueue(flowmod_msg.actions[0].out_port,queue_id)

                                for _port in self.list_ports:
                                    if str(_port.number) == str(flowmod_msg.actions[0].out_port):
                                        if self.isIP(_port.neighbor):
                                            update_db.update_qosSetting_fgbamDB(rule.protocol_id)

                                new_ofp_header = ofp_header()
                                new_ofp_header.version = 1
                                new_ofp_header.type = 14
                                new_ofp_header.l = 88
                                new_ofp_header.xid = of_header.xid

                                #data_from_controller = new_ofp_header.pack() + data_from_controller[8:len(data_from_controller)-(flowmod_msg.actions[0].len)] + enqueue_msg.pack()

                                flowmod_msg.actions.pop()
                                flowmod_msg.actions.append(enqueue_msg)
                                #flowmod_msg.match.nw_tos = 0


                                data_from_controller = new_ofp_header.pack() + flowmod_msg.pack()



                            else:
                                flag,queue_id = self.onProcessed(flowmod_msg,"check")
				print "TEST@1"
                                if flag1 == False and flag == True:
				    print "TEST@2"
                                    enqueue_msg = ofp_action_enqueue(flowmod_msg.actions[0].out_port,queue_id)
                                    new_ofp_header = ofp_header()
                                    new_ofp_header.version = 1
                                    new_ofp_header.type = 14
                                    new_ofp_header.l = 88
                                    new_ofp_header.xid = of_header.xid

                                    #data_from_controller = new_ofp_header.pack() + data_from_controller[8:len(data_from_controller)-(flowmod_msg.actions[0].len)] + enqueue_msg.pack()

                                    flowmod_msg.actions.pop()
                                    flowmod_msg.actions.append(enqueue_msg)
                                    #flowmod_msg.match.nw_tos = 0
                                    data_from_controller = new_ofp_header.pack() + flowmod_msg.pack()
				#data_from_controller = of_header.pack() + 
				else:
				    print "FlowMod: ",flowmod_msg.match.nw_src,flowmod_msg.match.tp_src,flowmod_msg.match.nw_dst,flowmod_msg.match.tp_dst
				    #data_from_controller = of_header.pack() + flowmod_msg.pack()

		    #print "SEND PACKET: ",data_from_controller
                    self.conn.send(data_from_controller)
                #Handle data from open_vswitch
                else:
                    data_from_device = self.conn.recvfrom(RECVBUFFER)
                    data_from_device = data_from_device[0]
                    if len(data_from_device) >= 8:
                        ofp_msg = ofp_header(data_from_device)
                        #print "From Device:"
                        ofp_msg.unpack()
                        #feature res
                        if ofp_msg.type == 6:
                            ofp_feature_res_msg = ofp_feature_response(data_from_device)
                            self.list_ports = ofp_feature_res_msg.unpack()
                            print "list_ports: " + str(self.list_ports)
                            for _port in self.list_ports:
                                if str(_port.number) == "65534":
                                    self.localPort = _port
                                    self.nameOfSwitch = _port.name


                            self.numOfphyPort = len(self.list_ports)
                            self.datapath_id = ofp_feature_res_msg.datapath_id
                            #list_localPort.append(self.localPort)
                            #list_datapath_id.append(self.datapath_id)

                        #packet-in
                        # elif ofp_msg.type == 10:
                        #     lt = learningTopo.handle_packetIn(data_from_device)
                        #
                        #     if lt.total_len >= 14:
                        #         lt.analyse_packet()
                        #
                        #         if len(self.neighbor) < self.numOfphyPort and lt.neighbor != None and lt.neighbor != self.localPort.mac_addr:
                        #
                        #             try:
                        #                 temp_datapath = int("".join(lt.neighbor.split(":")))
                        #                 for _thread in THREAD_LIST:
                        #                     if _thread.datapath_id == temp_datapath:
                        #                         self.neighbor[str(lt.in_port)] = _thread.localPort.name
                        #                         for _port in self.list_ports:
                        #                             if _port.number == lt.in_port:
                        #                                 temp_port = port(_port.number,_port.mac_addr,_port.name,_thread.localPort)
                        #                                 self.list_ports.append(temp_port)
                        #                                 self.list_ports.remove(_port)
                        #
                        #                 print self.list_ports
                        #             except ValueError:
                        #                 if self.isIP(lt.neighbor):
                        #                     print(lt.neighbor)
                        #                     for _port in self.list_ports:
                        #                         if _port.number == lt.in_port and not self.isHostAdded(lt.neighbor):
                        #                             self.neighbor[str(lt.in_port)] = lt.neighbor
                        #                             temp_port = port(_port.number,_port.mac_addr,_port.name,lt.neighbor)
                        #                             self.list_ports.append(temp_port)
                        #                             self.list_ports.remove(_port)
                        #                             self.list_hostsIP.append(lt.neighbor)
                        #
                        #                             #print self.list_ports
                        #
                        #                 elif self.isMac(lt.neighbor):
                        #                     self.update_listPort(lt.neighbor,lt.in_port)
                        #                     #print self.list_ports
                        #
                        #
                        #             with open('topology.json','w+') as filetopo:
                        #                 temp_list_port = []
                        #                 temp_dict_switch = {}
                        #                 temp_dict_switches = {}
                        #                 for _port in self.list_ports:
                        #                     temp_dict_port = {}
                        #                     temp_dict_port['port#'] = _port.number
                        #                     temp_dict_port['mac_addr'] = _port.mac_addr
                        #                     temp_dict_port['port_name'] = _port.name
                        #
                        #                     if self.isIP(_port.neighbor):
                        #                         temp_neightbor = {'host_ip' : _port.neighbor}
                        #                     elif _port.neighbor != None :
                        #                         temp_neightbor = {'port#' : _port.neighbor.number ,'mac_addr' : _port.neighbor.mac_addr , 'port_name' : _port.neighbor.name , 'neighbor' : _port.neighbor.neighbor }
                        #                     else:
                        #                         temp_neightbor = None
                        #
                        #                     temp_dict_port['neighbor'] = temp_neightbor
                        #                     temp_list_port.append(temp_dict_port)
                        #
                        #                 temp_dict_switch[self.nameOfSwitch] = temp_list_port
                        #                 if not q.empty():
                        #                     switches_list = q.get()
                        #                     _added = True
                        #                     for index, switch in enumerate(switches_list):
                        #                         for key in switch:
                        #                             if key == self.nameOfSwitch:
                        #                                 switches_list[index] = temp_dict_switch
                        #                                 _added = False
                        #                                 break
                        #                     if _added:
                        #                         switches_list.append(temp_dict_switch)
                        #
                        #                     temp_dict_switches['switches'] = switches_list
                        #                     json.dump(temp_dict_switches,filetopo)
                        #                     q.task_done()
                        #                     q.put(switches_list)



                            #print 'S' + str(self.datapath_id)+": "+str(self.neighbor)

                    sockCtrl.send(data_from_device)
		    t2 = time.time()
		    #logging.info(str(datetime.datetime.now().date())+' '+str(datetime.datetime.now().time())+ ' ' +'Time: '+str(t2-t1)) 


        conn.close()
        sockCtrl.close()


if __name__ == "__main__":

    logging.basicConfig(filename='/home/wisarutk/FGBAM/fgbam.log',level=logging.DEBUG)
    sock_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_serv.bind((IP_FGBAM, PORT_FGBAM))
    q.put(switches_list)
    sock_serv.listen(10)
    print "Starting FGBAM on" + IP_FGBAM + ":" + str(PORT_FGBAM)
    try:
        while True:
            conn, addr = sock_serv.accept()
            print "Device %s:%s connected" % addr
            newThread = communication_SwCtrler(conn, addr[0], addr[1])
            THREAD_LIST.append(newThread)
            newThread.daemon = True
            newThread.name = "%s:%s" % addr
            newThread.start()
    except KeyboardInterrupt:
        sock_serv.close()
        for thread in THREAD_LIST:
            callovsdb.destroy_all_ovsdb(0,thread.ip)
        sys.exit()














