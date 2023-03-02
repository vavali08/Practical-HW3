from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

import random

DEBUG = True
DEFAULT = 0

class Message:
    def __init__(self, value, sig):
        self.value = value
        self.sig = sig


#class for party
class Party:
    def __init__(self, is_leader, num, honest):
        self.is_leader = is_leader
        self.sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pk = self.sk.public_key()
        self.num = num
        self.msgs = []
        self.is_honest = honest
        self.output = None

    def sign(self, v):
        msg = bytes((v, self.num))
        return Message(v, self.sk.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()))

    def send(self, party, msg, PKI):
         if not self.is_honest:
            #TODO: Implement a dishonest send protocol

         if DEBUG: print("Sending", msg.value, "from", self.num, "to", party.num)

         party.recieve(msg, PKI)

    def recieve(self, msg, PKI):
        _sig = msg.sig
        _msg = bytes((msg.value, 0))
        
        try:
            #Verify that the message was signed by the general
            PKI[0].verify(_sig, _msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except InvalidSignature:
            return

        self.msgs.append(msg)

    def relay(self, party, PKI):
        #TODO: Implement relay for honest party: If you recieved a message, forward it to the specified party
        #TODO: Implement relay for dishonest party
        

    def decide(self):
        #TODO: implement decision step for both honest and dishonest parties
        if self.is_honest:  

        else:


def validity(general, v, parties):
    if general.is_honest:
        all_outputs = set([p.output for p in parties if p.is_honest])
        return len(all_outputs) == 1 and all_outputs.pop() == v
    else:
        return True

def agreement(parties):
    return len(set([p.output for p in parties if p.is_honest])) == 1


'''
    Naive Byzantine Agreement Protocol Implementation
    Takes a list of parties and a public key mapping
    (Check the tests for usage)
'''


def protocol(parties, PKI):
    
    #Round 1 
    v = 0

    leader = [p for p in parties if p.is_leader]
    assert(len(leader) == 1)
    G = leader[0]

    msg = G.sign(v)
    
    if DEBUG: print("ROUND 1")

    for party in parties:
        if not party.num == G.num:
            G.send(party, msg, PKI)


    if DEBUG:
        print()
        print("ROUND 2")

    #Round 2 
    for party in parties:
        for partyj in parties:
            if not party.num == partyj.num:
                party.relay(partyj, PKI)


    #Decision rule
    for party in parties:
        party.decide()
        
        
    if DEBUG: print("OUTPUTS", [p.output for p in parties])

    _valid = validity(G, v, parties[1:])
    _agreed = agreement(parties)

    return _valid and _agreed

