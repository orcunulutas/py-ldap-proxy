import itertools
from time import time, sleep
from threading import Thread, RLock

class Entry():
    def __init__(self,deger,ttl=600):
        self.deger=deger
        self.ttl=ttl
        self.expire=time()+ttl
        self._expire=False

    def expiredF(self):
        if self._expire is False:
            return (self.expire<time())
        else:
            return self._expire

class Cache():
    def __init__(self):
        self.liste=[]
        self.lock=RLock()
    def add(self,deger,ttl=600):
        with self.lock:
            self.liste.append(Entry(deger,ttl))
    def read(self):
        with self.lock:
            self.liste=list(itertools.dropwhile(lambda x:x.expiredF(),self.liste))
        return self.liste
    def varmi(self,item):
        with self.lock:
            for i in self.liste:
                if str(i.deger)==item:
                    return True
    def count(self,item):
        with self.lock:
            return self.liste.count(item)
        return False

