# pylint: disable=C0301, C0103, C1001, C0111

# declare commonly used items as global
globalLibrary = {
    # gen-2.cloudapp.net was an azure testing server that we used
    'domain': 'gen-2.cloudapp.net',
    'listdir': 'easylist.txt',
    # server address of the socket we proxied ads through
    'server_address': './uds_socket2'
}

# global dependencies
import re
import timeit

# unix sockets implementation
import socket
import sys
import os

# encryption
import base64
from Crypto.Cipher import AES
from Crypto import Random

# Look up class
# This generates a look up table based on easylist.txt
# Can be used to check if a string will be blocked by adblock filter
# Uses a python dict, equivalent of a hash table to allow for O(1) look up time, assuming no hash collision
# Will take O(F) [F is size of filters] to generate hash tables at beginning
class lookup:

    # Function to parse element rules and put into look up table
    # Can either by class or ID
    # This is determined by whether the rule starts with '#' or '.'
    def __parseElemRule(self, elemText):

        # Function to convert elem rules into regex
        def __toRegexp(elemText):
            # parse rule text into regexp
            regexp = re.escape(elemText)
            regexp.replace("/*", ".*")
            regexp.replace("/^", r"""[^A-Za-z0-9_\-.%]""")
            return regexp

        # Function to generate lookup ID
        def __genLookupId(idRule):
            if "*" in idRule['T'] or "^" in idRule['T']:
                self.__lookup['id']['ex'].append(idRule)
            else:
                self.__lookup['id']['short'][idRule['T']] = idRule

        # Function to generate lookup class
        def __genLookupClass(classRule):
            if "*" in classRule['T'] or "^" in classRule['T']:
                self.__lookup['class']['ex'].append(classRule)
            else:
                self.__lookup['class']['short'][classRule['T']] = classRule

        # If beginning of easylist line is '#'
        # Then assemble dictionary by storing it as an ID
        # This is done according to how easylist is created
        if elemText[0] == "#":
            # assemble rule (dict)
            rule = {}
            # rule['T'] stores raw rule
            rule['T'] = elemText[1:]
            # rule['R'] stores regexp rule
            rule['R'] = __toRegexp(elemText)
            # rule['X'] stores the compiled regexp rule
            rule['X'] = re.compile(rule['R'])
            # store rule
            self.__rules['id'].append(rule)
            __genLookupId(self.__rules['id'][len(self.__rules['id'])-1])

        # If beginning of easylist line is '.'
        # Then assemble dictionary by storing it as a class
        elif elemText[0] == ".":
            # assemble rule (dict)
            rule = {}
            # rule['T'] stores raw rule
            rule['T'] = elemText[1:]
            # rule['R'] stores rule turned into regex
            rule['R'] = __toRegexp(elemText)
            # rule['X'] stores compiled regex
            rule['X'] = re.compile(rule['R'])
            # store rule
            self.__rules['class'].append(rule)
            __genLookupClass(self.__rules['class'][len(self.__rules['class'])-1])

    # Function to parse URL blocking rules and put into lookup table
    def __parseUrlRule(self, urlText):

        # Function to convert url rules into regex
        def __toRegexp(urlText):
            # parse rule text into regexp
            regexp = re.escape(urlText)
            if regexp[0:1] == "/|":
                regexp = "^" + regexp[2:]
            if regexp[(len(regexp) - 2):(len(regexp) - 1)] == "/|":
                regexp = regexp[:(len(regexp) - 3)] + "$"
            regexp.replace("/*", ".*")
            regexp.replace("/^", r"""[^A-Za-z0-9_\-.%]""")
            return regexp

        # Main function to generate look up table for URLs with substrings
        # This function takes a substring of 8 from each easylist filter
        # These substrings are set as the hash table look up values
        # because these substr are bound to match, we only check against filters if there is a match in substr
        def __genLookup(urlRule):
            # find longest consecutive (uninterrupted by regexp) substring
            cStrs = re.compile(r"""[^\|\^\*]*""").findall(urlRule['T'])
            if len(cStrs) > 0:
                # set preferred number of substrings
                n = self.__pref['n']['url']
                maxLen = 0
                # loop through all substrings
                for i in range(len(cStrs)-1):
                    # find longest uninterrupted substring
                    if len(str(cStrs[i])) > len(str(cStrs[maxLen])):
                        # set that substring to maxLen
                        maxLen = i
                # if longest consecutive substring is longer than n - 1 chars
                if len(cStrs[maxLen]) > (n - 1):
                    # take shortcut from maxLen to n
                    shortcut = cStrs[maxLen][:n]
                    # if lookup key already exists (another rule with same substring/key)
                    if shortcut in self.__lookup['url']['short']:
                        # append shortcut to rule
                        self.__lookup['url']['short'][shortcut].append(urlRule)
                    else:
                        # if lookup key does not already exist
                        self.__lookup['url']['short'][shortcut] = []
                        self.__lookup['url']['short'][shortcut].append(urlRule)
                else:
                    # if less than 7 chars, append to manual lookup table
                    self.__lookup['url']['ex'].append(urlRule)
            else:
                # if no chars, append to manual lookup table
                self.__lookup['url']['ex'].append(urlRule)

        # assemble rule (dict)
        rule = {}
        # store raw rules into rule['T']
        rule['T'] = urlText
        # store regex rules into rule['R']
        rule['R'] = __toRegexp(urlText)
        # store compiled regex rule into rule['R']
        rule['X'] = re.compile(rule['R'])
        # store rule under the URL class
        self.__rules['url'].append(rule)
        __genLookup(self.__rules['url'][len(self.__rules['url'])-1])

    def parseList(self, listdir=globalLibrary['listdir']):
        # parse easylist
        filterList = open(listdir)
        breakAll = False
        for line in filterList:
            # escape lines
            line = line.replace("\n", "")
            # end parsing, since asset listings signifies end
            if line.find('! Asset Listings') != -1:
                print("Easylist.txt has been loaded into hashtable~")
                breakAll = True
            # if entry is not a comment
            if line[0] != "!" and breakAll != True:
                # if entry is a universal element hiding rule
                if line[:2] == "##":
                    self.__parseElemRule(line[2:])
                # if entry is a whitelist rule, do nothing
                elif line[:2] == "@@":
                    pass
                # if entry is a url rule (no identifier defaults to url rule)
                else:
                    self.__parseUrlRule(line)

    # initialize class
    def __init__(self):
        # preferred number for various substrings
        self.__pref = {
            'n': {
                'url': 8,
                'id': 5,
                'class': 5
            }
        }
        # rules dict for storing url, id, class, elem rules
        self.__rules = {
            'url': [],
            'id': [],
            'class': [],
            'elem': []
        }
        # create look up table for short cut and substrings
        self.__lookup = {
            'url': {
                'short': {},
                'ex': []
            },
            'id': {
                'short': {},
                'ex': []
            },
            'class': {
                'short': {},
                'ex': []
            },
            'elem': {
                'short': {},
                'ex': []
            }
        }
        self.parseList()

    # function to match elements and classes against easylist
    def match_elem(self, elemType, elemVals):
        # TO-DO: add iteration through EX rules
        # If element is ID, then look through ID list
        if elemType == 'id':
            if elemVals in self.__lookup['id']['short']:
                return [True]
            else:
                return [False]
        # if element is of type class, look through class list for each class item
        elif elemType == 'class':
            # split up classes
            elemVals = elemVals.split(" ")
            # check individually for each one
            if len(elemVals) > 1:
                eachResult = []
                for elemVal in elemVals:
                    if elemVal in self.__lookup['class']['short']:
                        eachResult.append(True)
                    else:
                        eachResult.append(False)
                return eachResult
            else:
                if elemVals[0] in self.__lookup['class']['short']:
                    return [True]
                else:
                    return [False]
        else:
            return [False]

    # Function to match URL against easylist hashtable
    def match_url(self, queryUrl):
        # get substr max length
        n = self.__pref['n']['url']
        # if query url is at least as long as n
        if n < len(queryUrl) + 1:
            substrings = []
            # extract substrings of length n
            i = len(queryUrl) - n
            while i > -1:
                substrings.append(queryUrl[i:(n+i)])
                i = i - 1
            # lookup substrings in shortcut table
            for substring in substrings:
                #print substring
                # If substring exists in shortcut table
                if substring in self.__lookup['url']['short']:
                    # Search regex in depth to see if match
                    for rule in self.__lookup['url']['short'][substring]:
                        if rule['X'].search(queryUrl) != None:
                            return True
        # if less than substring length, then check raw rules
        for rawRule in self.__lookup['url']['ex']:
            if rawRule['X'].search(queryUrl) != None:
                return True

    # Function used to debug
    def debug(self):
        counter = 0
        for item in self.__lookup['url']['short']:
            counter = counter + len(self.__lookup['url']['short'][item])
        print( counter)
        print(len(self.__lookup['url']['short']))
        print(len(self.__lookup['url']['ex']))
        print(len(self.__rules['url']))


# This class was originally used to encrypt and proxy ads through the publisher's server
# Doing so would unblock ads from the ad-blocker
# It would be impossible for adblockers to block ads unless they listed the root domain on easylist.txt
# Please note that this section of the code if not 100% complete, and it can't be tested unless an apache server with web sockets is available
# Therefore I have decided to comment out the code that initializes this class. Feel free to read through it if you like.
class dataHandler:
    # We used standard aes encrypt and decrypt function for testing. This would've had to be changed
    # should adblock eventually figure out we were using this type of encryption
    def __aesEncrypt(self, path):
        # checking if string is a multipe of 16 in lenght if not make it a multiple of 16
        BS = 16
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        # unpad = lambda s : s[:-ord(s[len(s)-1:])]
        # run aes encryption code from the library
        urlPath = pad(path)
        key = '0123456789abcdef'
        iv = Random.new().read(AES.block_size)
        mode = AES.MODE_CBC
        # Use AES
        cipher = AES.new(key, mode, iv)
        text = urlPath
        cipherText = cipher.encrypt(text)
        return base64.b64encode(iv + cipherText)

    # this function takes a piece of text and calls the encrypt function on that text
    def __elemEncrypt(self, elemText):
        # return elemText[len(elemText) - 2:] + elemText[:len(elemText) - 2]
        temp = base64.b64encode(elemText)
        # temp = temp.replace("=", "")
        # temp = temp.replace("+", "")
        # temp = temp.replace("/", "")
        return temp

    # this function is made to handle HTML tags that are blocked by adblocker
    def handleHTMLTag(self, htmltag):
        def __handle(attr, val):
            # if html tag blocked is an ID
            if attr == 'id':
                # lookup ID, if indeed blocked
                if self.mylookup.match_elem('id', val) == [True]:
                    # encrypt value
                    return self.__elemEncrypt(val)
            # if html tag blocked if a class
            elif attr == 'class':
                # lookup CLASS, if indeed true
                post = self.mylookup.match_elem('class', val)
                # sockets didn't handle classes well since there were multiple classes
                # ie class="col-md-6 pull-right"
                if len(post) > 1:
                    # split classes and check each class individually, otherwise leave them alone
                    vals = val.split(" ")
                    mustReturn = False
                    for i in range(len(post) - 1):
                        if post[i] == True:
                            # replace in-place
                            mustReturn = True
                            vals[i] = self.__elemEncrypt(vals[i])
                    if mustReturn == True:
                        return " ".join(vals)
                else:
                    if post == [True]:
                        return self.__elemEncrypt(val)
            # otherwise html tag blocked is a url
            else:
                if val.find('http') != -1:
                    # lookup url, if indeed true
                    if self.mylookup.match_url(val) == True:
                        # replace url with aes encrypted
                        return "http://" + globalLibrary['domain'] + "/" + self.__aesEncrypt(val)
        returntag = htmltag
        pairs = []
        # check against html attr regex to see if matches are available
        htmlattrs = self.regexps['htmlattrs'].findall(htmltag[1])
        # if length of findall returned is greater than 1, append entire item
        if len(htmlattrs) > 1:
            for item in htmlattrs:
                pairs.append(item)
        # else if length is just 1, then append the first item
        elif len(htmlattrs) == 1:
            pairs.append(htmlattrs[0])

        # if there was a match at all
        if len(pairs) > 0:
            # loop through items generated in pairs
            for item in pairs:
                # check against htmlkey regex to see if match
                thekey = self.regexps['htmlkey'].findall(item)
                if len(thekey) == 0:
                    thekey = ""
                else:
                    thekey = thekey[0]
                # check against htmlval to see if match
                theval = self.regexps['htmlval'].findall(item)
                if len(theval) == 0:
                    theval = ""
                else:
                    theval = theval[0]
                # run matched keys through handler
                thecheck = __handle(thekey, theval)
                # debugging
                if thecheck != None:
                    print >>sys.stderr, "---TC--- " + str(thecheck) + " ---K--- " + str(thekey) + " ---V--- " + str(theval)
                    theitem = item
                    theitem = theitem.replace(theval, thecheck)
                    returntag = (returntag[0], returntag[1].replace(item, theitem))

        return returntag

    # TO-DO: CSS handler, similar to html handler, just need to write regex to parse css files
    # should be relatively straight forward since css files are very structured
    def handleCSS(self, cssval):
        pass

    # TO-DO: JS handler, similar to html handler, just need to write regex to parse javascript files
    # This one may be slightly more complicated, since js files are more varied...
    def handleJS(self, jsval):
        pass

    # main handler to determine whether to direct databit into handleCSS, handleJS or handleHTMLTag
    # TO-DO: currently unfinished, need to write a regex to determine from string
    def handle(self, dataBit):
        # check against regex for html tags
        HTMLTags = self.regexps['htmltag'].findall(dataBit)
        # if matched regex
        if len(HTMLTags) > 0:
            # send into html tag handle
            for HTMLTag in HTMLTags:
                post = self.handleHTMLTag(HTMLTag)
                if post != HTMLTag:
                    dataBit = dataBit.replace(HTMLTag[1], post[1])
        return dataBit

    # Init function to call class
    def __init__(self):
        # Make sure the socket does not already exist
        try:
            os.unlink(globalLibrary['server_address'])
        except OSError:
            if os.path.exists(globalLibrary['server_address']):
                raise
        # Create UDS socket
        self.mySock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Bind the socket to the port
        print >>sys.stderr, 'starting up on %s' % globalLibrary['server_address']
        self.mySock.bind(globalLibrary['server_address'])
        # Initialize lookup tables
        self.mylookup = lookup()
        self.mylookup.debug()
        # Initialize regex for checking HTML items
        # TO-DO: Regex for JS and CSS items
        self.regexps = {
            "htmltag": re.compile(r"""<([\w\-_]+) ((?:[\w\-_:]+ ?= ?["'].*?["'] ?)+)\\?>"""),
            "htmlattrs": re.compile(r""".+? ?= ?["'].*?["']"""),
            "htmlkey": re.compile(r"""(.+?) ?= ?"""),
            "htmlval": re.compile(r""".+? ?= ?["'](.*?)["']""")
        }
        # self.encryptLib = {
        #     'seed': [4, 2, 1],
        #     'charmap': {},
        #     'lookup': {}
        # }
        startTime = None
        # Listen for incoming connections
        self.mySock.listen(1)
        while True:
            # Wait for a connection
            print >>sys.stderr, 'waiting for a connection'
            self.connection, self.client_address = self.mySock.accept()
            try:
                print >>sys.stderr, 'connection from', self.client_address
                # Receive the data in small chunks and retransmit it
                while True:
                    if startTime == None:
                        startTime = timeit.default_timer()
                    dataBit = self.connection.recv(8192)
                    #print >>sys.stderr, 'received "%s"' % data
                    if dataBit:
                        dataBit = self.handle(dataBit)
                        print >>sys.stderr, 'sending data back to the client'
                        self.connection.sendall(dataBit)
                    else:
                        endTime = timeit.default_timer()
                        print >>sys.stderr, 'no more data from', self.client_address, "total time = " + str(endTime - startTime)
                        startTime = None
                        break
            finally:
                # Clean up the connection
                self.connection.close()

# lookup = lookup()
# test.debug()
# sina = lookup()
# print(sina.match_url("https://bidder.criteo.com/cdb?ptv=65&profileId=154&cb=58087590260"))
# print(sina.match_url("http://pagead2.googlesyndication.com/simgad/2710810634177601288"))