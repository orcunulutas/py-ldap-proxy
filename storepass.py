from pykeepass import PyKeePass

class storePass ():
    def __init__(self,db,key,passwd,group):
        self.database=db
        self.kefFile=key
        self.dbPass=passwd
        self.dbGroup=group
        self.kp = None
        self.entriesGroup=None
        self.connect()
    def connect(self):
        self.kp=PyKeePass(self.database,password=self.dbPass,keyfile=self.kefFile)
        self.entriesGroup=self.kp.find_groups(name=self.dbGroup,first=True)
    def findPass(self,username,userPass):
        try:
            return self.kp.find_entries(title=username,string={'hidepass': userPass.decode('utf-8')},first=True).password.encode("ascii")
        except:
            return userPass