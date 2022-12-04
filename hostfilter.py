import pandas as pd
from time import time

class hostfilter ():
    def __init__(self,csvFile,ttl=600):
        self.dataFile=csvFile
        self.expire=time()+ttl
        self.df=pd.read_csv(self.dataFile)
    def reloadCSv(self):
        self.df=pd.read_csv(self.dataFile)

    def filter(self,username):
        if self.expire<time():
            self.reloadCSv
        queryString = "username == '{}'".format(username)
        # return format list
        return self.df.query(queryString)["host"].values.tolist()