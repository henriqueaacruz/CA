import sys, getopt
import string
import random
import cryptography
import time

from cryptography.hazmat.primitives.ciphers import Cipher,algorithms, modes, CipherAlgorithm
from cryptography.hazmat.backends import default_backend

rfCounter = 0

def randomPassword(pwLength):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits + '?' + '!') for _ in range(pwLength))

def extendPassword(password, pwLength):
    x = list(password)
    while len(x) < 16:
        for i in range(pwLength):
            x.append(password[i])
    password = ''.join(x[:16]) 

    return password

def hashPW(pwKey):

    cipher = Cipher(algorithms.AES(pwKey), modes.ECB(), default_backend())
    enc = cipher.encryptor()
    result = enc.update(pwKey)

    return result.hex()

def produceChain(chainSize, password, pwLength):
    passwordI = password
    hashI = ''

    i = 0

    while i < chainSize:
        hashI = hashPW(bytes(passwordI, 'ascii'))
        passwordI = reduceHash(hashI, pwLength)
        #print("{} - {}".format(i, hashI))
        i += 1

    return hashI

def reduceHash(hashI, pwLength):
    global rfCounter

    if rfCounter == 0:
        rfCounter += 1
        return extendPassword(hashI[:pwLength], pwLength)
    elif rfCounter ==  1:
        rfCounter += 1
        return extendPassword(hashI[pwLength:2*pwLength], pwLength)
    elif rfCounter ==  2:
        rfCounter += 1
        return extendPassword(hashI[2*pwLength:3*pwLength], pwLength)
    elif rfCounter ==  3:
        rfCounter += 1
        return extendPassword(hashI[3*pwLength:4*pwLength], pwLength)
    elif rfCounter ==  4:
        rfCounter = 0
        return extendPassword(hashI[4*pwLength:5*pwLength], pwLength)
        

def main(argv):

    pwLength = int(argv[0])
    rbSize = int(argv[1])
    pw0 = []
    hashK = []
    outputfileName = argv[2]

    rbNrOfRows = 2**rbSize // 2

    chainSize =  (64**pwLength) / rbNrOfRows

    rtfile = open(outputfileName+".txt", "w")
    print(time.perf_counter())
    i = 0

    while i < rbNrOfRows:
        randomPw = randomPassword(pwLength)
        extendedPw = extendPassword(randomPw, pwLength)

        pw0.append(randomPw)
        hashK.append(produceChain(chainSize, extendedPw, pwLength))

        rtfile.write(pw0[i] + hashK[i] + "\n")

        i += 1

    print(time.perf_counter())

    rtfile.close()

if __name__ == "__main__":
    main(sys.argv[1:])
    