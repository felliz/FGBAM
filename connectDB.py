import MySQLdb


class get_QoS_setting(object):
    def __init__(self):
        self.table_qos_setting = []

        self.db = None
        self.cursor = None
        self.connection_failed = False
        self.connect_fgbamDB()


    def connect_fgbamDB(self):
        #Open database connection
        try:
            self.db = MySQLdb.connect("localhost","root","fgbam","fgbam" )
        except:
            self.connection_failed = True


        # prepare a cursor object using cursor() method
        if self.connection_failed == False:
            self.cursor = self.db.cursor()

        # execute SQL query using execute() method.
    def select_qosSetting_fgbamDB(self):
        sql = "SELECT * FROM qos_setting WHERE status_id < '%d'" % (3)

        try:
           # Execute the SQL command
           self.cursor.execute(sql)
           # Fetch all the rows in a list of lists.
           results = self.cursor.fetchall()
           for row in results:
              self.table_qos_setting.append(row)
        except:
           print "Error: unable to fecth data"

        # disconnect from server


    def update_qosSetting_fgbamDB(self,protocol_id):
        print protocol_id
        sql = "UPDATE qos_setting SET status_id = %d WHERE Protocol_ID= '%d'" %(3,protocol_id)
        try:
           # Execute the SQL command
           self.cursor.execute(sql)
           self.db.commit()

        except:
           print "Error: unable to update data"

        # disconnect from server







