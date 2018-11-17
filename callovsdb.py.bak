import socket
import json
from logging import info
import ast

DEFAULT_DB = 'Open_vSwitch'
BUFFER_SIZE = 4096



def gather_reply(socket):

    result = ""
    while "error" not in result or "id" not in result or "result" not in result:
        reply = socket.recv(BUFFER_SIZE)
        result += reply
    return json.loads(result)

def insert_queue(socket,maxRate,minRate,db_name,current_id,db = DEFAULT_DB):
    #transact_insert_Queue = {"method":"transact", "params":[db_name,{"op":"insert" , "table":"Queue" , "row":{"other_config":["map",[["max-rate",str(maxRate)],["min-rate",str(minRate)]]]} } ] , "id": current_id}
    transact_insert_Queue = {"method":"transact", "params":[db_name,{"op":"insert" , "table":"Queue" , "row":{"other_config":["map",[["min-rate",str(minRate)]]]} } ] , "id": current_id}
    socket.send(json.dumps(transact_insert_Queue))
    response = gather_reply(socket)
    return  response

def insert_QoS(socket,uuid,maxRate,db_name,current_id,type = "linux-htb",db = DEFAULT_DB):
    transact_insert_QoS = {"method":"transact", "params":[db_name,{"op":"insert" , "table":"QoS" , "row":{"queues":["map",[[0,["uuid",uuid]]]] , "type":type , "other_config":["map",[["max-rate",str(maxRate)]]] } } ], "id": current_id}
    socket.send(json.dumps(transact_insert_QoS))
    response = gather_reply(socket)
    return response

def update_port(socket,uuidQoS,db_name,current_id,name_port,db = DEFAULT_DB):
    transact_update_Port = {"method":"transact", "params":[db_name,{"op":"update" , "table":"Port" ,"where":[["name","==",name_port]], "row":{"qos":["uuid",uuidQoS]} } ] , "id": current_id}
    socket.send(json.dumps(transact_update_Port))
    response = gather_reply(socket)
    return response

def update_queue(uuid_queue,maxRate,minRate,current_id,ovsdb_IP=None,ovsdb_Port=6640):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ovsdb_IP, ovsdb_Port))
    maxRate = float(maxRate) * 1000000
    minRate = float(minRate) * 1000000
    result = list_dbs(s,current_id)
    current_id += 1
    db_name = result['result'][0]

    transact_update_Queue = {"method":"transact", "params":[db_name,{"op":"update" , "table":"Queue" ,"where":[["_uuid","==",["uuid",uuid_queue]]], "row":{"other_config":["map",[["max-rate",str(maxRate)],["min-rate",str(minRate)]]]} } ] , "id": current_id}
    s.send(json.dumps(transact_update_Queue))
    respose = gather_reply(s)
    return respose

def mutate_QoS(socket,uuid_QoS,list_queue,current_id,db_name,command = "insert"):
    array_queue = ast.literal_eval(list_queue)
    #print list_queue
    transact_mutate_qos = {"method":"transact", "params":[db_name,{"op":"mutate" , "table":"QoS" ,"where":[["_uuid","==",["uuid",uuid_QoS]]], "mutations":[["queues",command,["map",array_queue]]] } ] , "id": current_id}
    socket.send(json.dumps(transact_mutate_qos))
    response = gather_reply(socket)
    return response

def list_dbs(socket,current_id):
    list_dbs_query =  {"method":"list_dbs", "params":[] , "id": current_id}
    socket.send(json.dumps(list_dbs_query))
    response = gather_reply(socket)
    return response

def select_data(socket,table,column,current_id,db_name,name_port):
    transact_select = {"method":"transact", "params":[db_name,{"op":"select" , "table":table  ,"where":[["name","==",name_port]], "columns":[column] } ] , "id": current_id}
    socket.send(json.dumps(transact_select))
    response = gather_reply(socket)
    return response

def get_uuid_QoS(socket,current_id,db_name,name_port):
    result = select_data(socket,"Port","qos",current_id,db_name,name_port)
    qos_temp = result['result'][0]
    qos_temp = qos_temp['rows'][0]
    qos_in_port = qos_temp['qos'][1]
    return qos_in_port


def get_queue_in_QoS(socket,uuid_qos,current_id,db_name):
    queue_in_QoS = {"method":"transact", "params":[db_name,{"op":"select" , "table":"QoS"  ,"where":[["_uuid","==",["uuid",uuid_qos]]], "columns":["queues"] } ] , "id": current_id}
    socket.send(json.dumps(queue_in_QoS))
    response = gather_reply(socket)
    return response

def append_queue_in_QoS(socket,uuid_qos,uuid_queue,current_id,db_name):
    result = get_queue_in_QoS(socket,uuid_qos,current_id,db_name)
    #print result
    queue_in_QoS = result['result'][0]

    #if queue_in_QoS['rows']:
    queue_in_QoS = queue_in_QoS['rows'][0]
    queue_in_QoS = queue_in_QoS['queues'][1]
    queue_lastOfindex = len(queue_in_QoS)
    queue_in_QoS.append([queue_lastOfindex ,["uuid",uuid_queue]])
    return json.dumps(queue_in_QoS),queue_lastOfindex

def create_defaultQueue(socket,link_speed,db_name,current_id):
    result = insert_queue(socket,str(link_speed),str(link_speed),db_name,current_id)
    uuid_queue_temp = result['result'][0]
    uuid_queue = uuid_queue_temp['uuid'][1]

    return  uuid_queue

def delete_queue(queue_id,name_port,current_id,ovsdb_IP=None,ovsdb_Port=6640):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ovsdb_IP,ovsdb_Port))
    db_name = "Open_vSwitch"

    qos_inPort = get_uuid_QoS(s,current_id,db_name,name_port)
    current_id += 1

    result = get_queue_in_QoS(s,qos_inPort,current_id,db_name)
    current_id += 1
    queue_inQoS = result['result'][0]['rows'][0]['queues'][1]

    for queue in queue_inQoS:
        if queue[0] != queue_id:
            queue_inQoS.remove(queue)

    result = mutate_QoS(s,qos_inPort,json.dumps(queue_inQoS),current_id,db_name,"delete")
    current_id += 1

    #print queue_inQoS[0][1][1]
    delete_q = {"method":"transact", "params":[db_name,{"op":"delete" , "table":"Queue"  ,"where":[["_uuid","==",["uuid",queue_inQoS[0][1][1]]]] } ] , "id": current_id}
    s.send(json.dumps(delete_q))
    response = gather_reply(s)
    #print response


#,"where":[["name","==",name_port]]

def create_queue(name_port,bw,id,ovsdb_IP=None,ovsdb_Port=6640):

    print "create queue ..."
    print "connect OVSDB: "+str(ovsdb_IP)+":"+str(ovsdb_Port)

    print "name_port: " + str(name_port)
    print "bw: " + str(bw)
    print "id: " + str(id)


    bw = float(bw) * 1000000

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ovsdb_IP, ovsdb_Port))

    current_id = id

    result = list_dbs(s,current_id)
    current_id += 1
    db_name = result['result'][0]


    result = select_data(s,"Interface","link_speed",current_id,db_name,name_port)
    current_id += 1
    link_speed_temp = result['result'][0]
    link_speed_temp = link_speed_temp['rows'][0]
    link_speed = link_speed_temp['link_speed']

    result = insert_queue(s,str(bw),str(bw),db_name,current_id)
    current_id += 1
    uuid_queue_temp = result['result'][0]
    uuid_queue = uuid_queue_temp['uuid'][1]




    qos_in_port = get_uuid_QoS(s,current_id,db_name,name_port)
    current_id += 1

    if not qos_in_port:
        uuid_default_queue = create_defaultQueue(s,100000000000,db_name,current_id)
        current_id += 1
        #result = insert_QoS(s,uuid_default_queue,str(link_speed),db_name,current_id)
        result = insert_QoS(s,uuid_default_queue,str(100000000000),db_name,current_id)

        current_id += 1
        uuid_qos_temp = result['result'][0]
        uuid_qos = uuid_qos_temp['uuid'][1]

        result = update_port(s,uuid_qos,db_name,current_id,name_port)
        current_id += 1

        #####################################################
        uuid_qos = get_uuid_QoS(s,current_id,db_name,name_port)
        current_id += 1
        list_queue,queue_id = append_queue_in_QoS(s,uuid_qos,uuid_queue,current_id,db_name)
        current_id += 1
        result = mutate_QoS(s,uuid_qos,list_queue,current_id,db_name)
        current_id += 1


    else:
        uuid_qos = get_uuid_QoS(s,current_id,db_name,name_port)
        current_id += 1
        list_queue,queue_id = append_queue_in_QoS(s,uuid_qos,uuid_queue,current_id,db_name)
        current_id += 1

        result = mutate_QoS(s,qos_in_port,list_queue,current_id,db_name)
        current_id += 1



    print "create success"
    s.close()
    return current_id,queue_id,uuid_queue
