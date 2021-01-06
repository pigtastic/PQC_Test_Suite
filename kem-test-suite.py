from pprint import pprint
import oqs
import ctypes as ct  # to call native
import ctypes.util as ctu
from loguru import logger
import sys
from datetime import datetime
import platform

logger.add(sys.stderr, format="{time} {level} {message}", filter="kem-test-suite.py", level="INFO")

#######################################################################
# KEM test suite
#######################################################################

kems = oqs.get_enabled_KEM_mechanisms()

# print("Enabled KEM mechanisms:")
# pprint(kems, compact="True")

mcelise = 'Classic-McEliece-348864'
saber = 'Saber-KEM'
kyper = 'Kyber512'

# CONFIG
kemalg = saber
iterations = 100000


# FILE WRITER
system = platform.system()
platform = platform.platform()
filename = kemalg + "-" + system + "-" + platform + ".csv"

file = open("logs/" + filename, "a")
logger.info("Open logfile: " + filename)

file.write(system)
file.write(";")
file.write(platform)
file.write(";")

with oqs.KeyEncapsulation(kemalg) as client:
    with oqs.KeyEncapsulation(kemalg) as server:

        logger.info("Selected algorithm: " + kemalg)
        logger.info("Number of iterations " + str(iterations))
        logger.info("Test start...")

        i = 0
        proz = iterations / 10
        while i <= iterations:
            i = i + 1

            
            if i % proz == 0:
                logger.info(str(i / iterations * 100) + "%")

            # client generates its keypair
            public_key = client.generate_keypair()

            # the server encapsulates its secret using the client's public key
            first = datetime.now()

            ciphertext, shared_secret_server = server.encap_secret(public_key)
            shared_secret_client = client.decap_secret(ciphertext)

            second = datetime.now()
            dif = second - first

            if shared_secret_client == shared_secret_server:
                file.write(str(dif.microseconds) + ";")

file.write("\n")
logger.info("Test done!")
file.close()
