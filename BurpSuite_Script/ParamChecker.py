"""
-------------------------ParamChecker------------------------
this module check request priviledge in http/https queries as followed way:
    0 request as normal
    1 replace param with a previously valid one (check before)
    2 replace param with modifing with one different character
    3 replace param with bradamsa output
    4 remove the param
    5 replace request body with bradamsa output
    ...to be continued (do we need add param)
notice: param contains queries string as well as body part data

example:
    input=http://www.a.com?b=1&c=2
    output=
    type  request                      response
    0     http://www.a.com?b=1&c=2     200 OK ...
    1     http://www.a.com?b=3&c=2     ...
    1     http://www.a.com?b=1&c=3     ...
    2     http://www.a.com?b=3xb&c=2   ...
    2     .....
	
dependency:
	radamsa	https://github.com/aoh/radamsa
"""

from burp import IBurpExtender
from javax.swing import JMenuItem
from os import popen
from thread import start_new_thread
import random
import re
# constants
helpers = None
callbacks = None
db = {}  # must be in global area

# for edit
radamsa_path = "D:/cygwin/bin/radamsa.exe"
type1_maxreplaytime = 3  # replace with X different values occurred before for each param in request;include ""
type2_maxreplaytime = 3  # replace param with a previously valid one
type3_maxreplaytime = 16 # replace each param in request with radamsa output for X times;
type5_maxreplaytime = 16 # replace body(may contain param) with radamsa output for X times


class BurpExtender(IBurpExtender):
    """
    Named BurpExtender for burp to recognize
    """
    callbacks = None
    helpers = None
    messages = []
    radamsa_tmpfile = None
    radamsa_tmp = "radamsa.tmp"

    def doInit(self, _callbacks):
        """
        init job
        """
        # init burp
        self.callbacks = _callbacks
        self.helpers = _callbacks.getHelpers()
        for item in self.callbacks.getContextMenuFactories():
            self.callbacks.removeContextMenuFactory(item)
        self.callbacks.registerContextMenuFactory(self.createMenuItems)
        # init radamsa
        self.radamsa_tmpfile = open(self.radamsa_tmp, "w")

    def run_radamsa(self, inputdata):
        outputdata = ""
        try:
            self.radamsa_tmpfile.write(inputdata)
            self.radamsa_tmpfile.flush()
            outputdata = popen(radamsa_path + " " + self.radamsa_tmp).read()
        except Exception as e:
            print e
        print inputdata, outputdata
        return outputdata

    def updatedb(self, host, params):
        """
        store data to database like {"a.com":{"x":set(["1"]), "y":set(["2"])}, "b.com":{"z":set(["3"])}}
        :param host: split parameters in request for each host
        :param params: parameters
        """
        if host not in db:
            db[host] = {}
        for param in params:
            k = param.getName().encode("utf-8")
            v = param.getValue().encode("utf-8")
            if k not in db[host]:
                db[host][k] = set([v,""])
            else:
                db[host][k].add(v)
        print "updated db:", db

    def make_request_thread(self, service, request):
        """
        if make request in origin thread, burp will throw an exception
        we need logger++ plugin to see result
        """
        requestResponse = self.callbacks.makeHttpRequest(service, request)
        print self.helpers.analyzeRequest(requestResponse).getUrl().toString()

    def run_replace_param_with_a_previously_valid_one(self, requestInfo, messageInfo):
        """
        1 replace param with a previously valid one
        :param requestInfo: IRequestInfo
        :param messageInfo: IHttpRequestResponse
        """
        params = requestInfo.getParameters()
        host = messageInfo.getHttpService().getHost()
        oldrequestBytes = messageInfo.getRequest()  # save for future use
        if host not in db:
            return
        for param in params:
            k = param.getName().encode("utf-8")
            v = param.getValue().encode("utf-8")
            start = param.getValueStart()
            end = param.getValueEnd()
            if k not in db[host]:
                continue
            count = 0
            for item in db[host][k]:
                if item == v:
                    continue
                if count == type1_maxreplaytime:
                    break
                #the simplest way to construct a request I found
                newrequest = oldrequestBytes[0:start].tostring() + item + oldrequestBytes[end:].tostring()
                service = messageInfo.getHttpService()
                start_new_thread(self.make_request_thread, (service, newrequest,))
                count = count + 1

    def get_random_char(self, s):
        if re.match(ur"[0-9]+", s) != None:
            arr = "0123456789"
        elif re.match(ur"[A-Z]+", s) != None:
            arr = "abcdefghijklmnopqrstuvwxyz"
        elif re.match(ur"[a-z]+", s) != None:
            arr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        else:#what is going on?
            return '0'
        return arr[random.randint(0, len(arr) - 1)]

    def run_replace_param_with_modifying_with_one_different_character(self, requestInfo, messageInfo):
        """
        2 replace param with modifing with one different character (replace head/tail/ )
        :param requestInfo: IRequestInfo
        :param messageInfo: IHttpRequestResponse
        """
        params = requestInfo.getParameters()
        oldrequestBytes = messageInfo.getRequest()  # save for future use
        for param in params:
            k = param.getName().encode("utf-8")
            v = param.getValue().encode("utf-8")
            start = param.getValueStart()
            end = param.getValueEnd()
            if len(v) == 0:
                continue
            count = 0
            while count !=  type2_maxreplaytime:
                pos = random.randint(0, len(v) - 1)
                v = v[0:pos] + self.get_random_char(v) + v[pos + 1:]
                newrequest = oldrequestBytes[0:start].tostring() + v + oldrequestBytes[end:].tostring()
                service = messageInfo.getHttpService()
                start_new_thread(self.make_request_thread, (service, newrequest,))
                count = count + 1

    def run_replace_param_with_radamsa_output(self, requestInfo, messageInfo):
        """
        3 replace param with radamsa output
        :param requestInfo: IRequestInfo
        :param messageInfo: IHttpRequestResponse
        """
        params = requestInfo.getParameters()
        oldrequestBytes = messageInfo.getRequest()  # save for future use
        for param in params:
            k = param.getName().encode("utf-8")
            v = param.getValue().encode("utf-8")
            start = param.getValueStart()
            end = param.getValueEnd()
            if len(v) == 0:
                continue
            count = 0
            while count !=  type3_maxreplaytime:
                newrequest = oldrequestBytes[0:start].tostring() + self.run_radamsa(v) + oldrequestBytes[end:].tostring()
                service = messageInfo.getHttpService()
                start_new_thread(self.make_request_thread, (service, newrequest,))
                count = count + 1

    def run_remove_param(self, requestInfo, messageInfo):
        """
        4 remove param
        :param requestInfo: IRequestInfo
        :param messageInfo: IHttpRequestResponse
        """
        params = requestInfo.getParameters()
        oldrequestBytes = messageInfo.getRequest()  # save for future use
        for param in params:
            k = param.getName().encode("utf-8")
            v = param.getValue().encode("utf-8")
            start = param.getValueStart()
            end = param.getValueEnd()
            # we need to find the real start position because current start is start of value
            tmpstr = oldrequestBytes.tostring()
            start = tmpstr.rfind(k ,0, start) # so we can find the whole string like "a=1"
            if tmpstr[start - 1] == '&':
                start = start - 1
            elif end < len(tmpstr) and tmpstr[end] == '&':
                end = end + 1
            newrequest = oldrequestBytes[0:start].tostring() + oldrequestBytes[end:].tostring()
            service = messageInfo.getHttpService()
            start_new_thread(self.make_request_thread, (service, newrequest,))

    def run_replace_body_with_radamsa_output(self, requestInfo, messageInfo):
        """
        5 replace request body with radamsa output
        :param requestInfo: IRequestInfo
        :param messageInfo: IHttpRequestResponse
        """
        params = requestInfo.getParameters()
        oldrequestBytes = messageInfo.getRequest()  # save for future use
        bodypart = oldrequestBytes[requestInfo.getBodyOffset():]
        if 0 == len(bodypart):
            return
        count = 0
        while count != type5_maxreplaytime:
            newrequest = oldrequestBytes[0:requestInfo.getBodyOffset()].tostring() + self.run_radamsa(bodypart)
            service = messageInfo.getHttpService()
            start_new_thread(self.make_request_thread, (service, newrequest,))
            count = count + 1

    def handleMessage(self, e):
        """
        handle single one a time
        """
        if len(self.messages) == 0:
            return
        messageInfo = self.messages[0]
        requestInfo = self.helpers.analyzeRequest(messageInfo)
        # run cheker
        self.run_replace_param_with_a_previously_valid_one(requestInfo, messageInfo)
        self.run_replace_param_with_modifying_with_one_different_character(requestInfo, messageInfo)
        self.run_replace_param_with_radamsa_output(requestInfo, messageInfo)
        self.run_remove_param(requestInfo, messageInfo)
        self.run_replace_body_with_radamsa_output(requestInfo, messageInfo)
        self.updatedb(messageInfo.getHttpService().getHost(), requestInfo.getParameters())

    def createMenuItems(self, invocation):
        self.messages = invocation.getSelectedMessages()
        menuItem = JMenuItem("Send request(s) to ParamChecker")
        menuItem.addActionListener(self.handleMessage)
        return [menuItem]

    def registerExtenderCallbacks(self, _callbacks):
        """
        install from burpsuite
        """
        self.doInit(_callbacks)


if __name__ == "__main__":
    """
    install from burpkit
    """
    if "burp" in locals().keys():
        BurpExtender().doInit(burp)
