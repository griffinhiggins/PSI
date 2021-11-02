from Crypto.Hash import SHA256
import json
import sys

clc = lambda i, s : f"\u001b[{i}m{s}\u001b[0m"
title = lambda i, s : clc(i,s).center(73,'=')

class Agent:
    def __init__(self,file):
        # This can be changed to use getElementHashSet with the element
        # files but its a much easier than this case.
        self.hashes = self.genObjectHashSet(file)

    def genElementHashSet(self,file):
        hashes = {}
        with open(file) as f:
            for e in json.load(f):
                hashes[SHA256.new(e.encode('utf-8')).hexdigest()] = e
        return hashes

    def genObjectHashSet(self,file):
        hashes = {}
        with open(file) as f:
            for o in json.load(f):
                h = bytearray([1] * 100)
                for e in o.values():
                    h = SHA256.new(f"{h}{e}".encode('utf-8')).digest()
                hashes[h.hex()] = o
        return hashes

    def sendHashSet(self):
        return set(self.hashes.keys())

    def intersect(self,set_i):
        print(title(31, "SENDER(ALICE)"))
        for i in set_i:
            print(i)

        print(title(31, "RECIEVER(BOB)"))
        set_j = set(self.hashes.keys())
        for i in set_j:
            print(i)
        # POSSIBLE MITIGATION        
        # threasholdPower = 2
        # if((len(set_i)//len(set_j)) < pow(len(set_j),threasholdPower)):
        print(title(33, "PSI"))
        for i in set_i.intersection(set_j):
            print(i, clc(33,self.hashes[i]))
        # else:
        #     print(title(31, "POSSIBLE MALICIOUS SENDER"))

class EvilAgent(Agent):
    def __init__(self, file):     
        super().__init__(file)
        self.bruteForce()
 
    def bruteForce(self):
        hashes = {}
        x = [chr(i) for i in range(97,97+26)]
        for i in x: 
            for j in x: 
                for k in x: 
                    h = bytearray([1] * 100)
                    for e in [i,j,k]:
                        h = SHA256.new(f"{h}{e}".encode('utf-8')).digest()
                    hashes[h.hex()] = { "i":i, "j":j, "k":k }
        self.hashes = hashes

    def sendEvilHashSet(self):
        return set(self.hashes.keys())

    def evilIntersect(self,set_i):
        print(title(31, "SENDER(ALICE)"))
        for i in set_i:
            print(i)

        print(title(31, "RECIEVER(BOB)"))
        set_j = set(self.hashes.keys())
        for i in set_j:
            print(i)

        # This would give a full intersection to alice everytime
        # so this would likely need to be replaced with the 
        # original intersection if it would be returned to alice
        # to avoide detection
        print(title(33, "PSI"))
        for i in set_i.intersection(set_j):
            print(i, clc(33,self.hashes[i]))
        
if __name__ == "__main__":
    if(sys.argv[1] == "-a"):
        # CASE 1 (BOTH GOOD)
        bob = Agent("./objects/bob.json")
        alice = Agent("./objects/alice.json")
        bob.intersect(alice.sendHashSet())
    elif(sys.argv[1] == "-b"):
        # CASE 2 (MALICIOUS SENDER)
        bob = Agent("./objects/bob.json")
        alice = EvilAgent("./objects/alice.json")
        bob.intersect(alice.sendEvilHashSet())
    elif(sys.argv[1] == "-c"):
        # CASE 2 (MALICIOUS SENDER)
        bob = EvilAgent("./objects/bob.json")
        alice = Agent("./objects/alice.json")
        bob.evilIntersect(alice.sendHashSet())
