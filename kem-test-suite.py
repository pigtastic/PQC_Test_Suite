from pprint import pprint
import oqs
import ctypes as ct  # to call native
import ctypes.util as ctu
from loguru import logger
import sys
from datetime import datetime
import platform
import time

logger.add(sys.stderr,
           format="{time} {level} {message}",
           filter="kem-test-suite.py",
           level="INFO")

#######################################################################
# KEM test suite
#######################################################################

# kems = oqs.get_enabled_KEM_mechanisms()

kems = ['Classic-McEliece-348864', 'Classic-McEliece-348864f',
 'Classic-McEliece-460896', 'Classic-McEliece-460896f',
 'Classic-McEliece-6688128', 'Classic-McEliece-6688128f',
 'Classic-McEliece-6960119', 'Classic-McEliece-6960119f',
 'Classic-McEliece-8192128', 'Classic-McEliece-8192128f', 
 'Kyber512', 'Kyber768', 'Kyber1024', 'Kyber512-90s', 'Kyber768-90s',
 'Kyber1024-90s', 'NTRU-HPS-2048-509', 'NTRU-HPS-2048-677', 'NTRU-HPS-4096-821',
 'NTRU-HRSS-701', 'ntrulpr653', 'ntrulpr761', 'ntrulpr857', 'sntrup653',
 'sntrup761', 'sntrup857', 'LightSaber-KEM', 'Saber-KEM', 'FireSaber-KEM']

iterations = 1000
system = platform.system()
platform = platform.platform()


def prepWriter(writer):
    writer.write(system)
    writer.write(";")
    writer.write(platform)
    writer.write(";")


counter = 1
for algo in kems:
    if algo != "DEFAULT":
        logger.info("################# " + algo + " (" + str(counter) + "/" +
                    str(len(kems)) + ")" + " #################")

        # FILE WRITERS

        filename = algo + "" + ".csv"

        file_decap = open("logs/decap/" + filename, "a")
        file_encap = open("logs/encap/" + filename, "a")
        file_cap = open("logs/cap/" + filename, "a")
        file_roundtrip = open("logs/roundtrip/" + filename, "a")
        file_keygen = open("logs/keygen/" + filename, "a")

        prepWriter(file_decap)
        prepWriter(file_encap)
        prepWriter(file_cap)
        prepWriter(file_keygen)
        prepWriter(file_roundtrip)

        logger.info("Open logfiles: " + filename)

        with oqs.KeyEncapsulation(algo) as client:
            with oqs.KeyEncapsulation(algo) as server:

                logger.info("Iterations " + str(iterations))
                logger.info("Test start...")

                i = 0
                while i <= iterations:
                    i = i + 1

                    # output of progress in %
                    if i % (iterations / 10) == 0:
                        logger.info(str(i / iterations * 100) + "%")

                    # FIRST time
                    first = datetime.now()

                    # client generates its keypair
                    public_key = client.generate_keypair()

                    # KEYGEN duration
                    second = datetime.now()
                    dif = second - first
                    file_keygen.write(str(dif.microseconds) + ";")

                    # ENCAP
                    ciphertext, shared_secret_server = server.encap_secret(
                        public_key)

                    # ENCAP duration
                    third = datetime.now()
                    dif = third - second
                    file_encap.write(str(dif.microseconds) + ";")

                    # DECAP
                    shared_secret_client = client.decap_secret(ciphertext)

                    # DECAP duration
                    fourth = datetime.now()
                    dif = fourth - third
                    file_decap.write(str(dif.microseconds) + ";")

                    # CAP duration
                    dif = fourth - second
                    if shared_secret_client == shared_secret_server:
                        file_cap.write(str(dif.microseconds) + ";")
                    else:
                        file_cap.write("0" + ";")

                    # ROUNDTRIP duration
                    dif = fourth - first
                    if shared_secret_client == shared_secret_server:
                        file_roundtrip.write(str(dif.microseconds) + ";")
                    else:
                        file_roundtrip.write("0" + ";")

        file_decap.write("\n")
        file_encap.write("\n")
        file_keygen.write("\n")
        file_roundtrip.write("\n")
        file_cap.write("\n")

        logger.info("Test done!\n")

        file_decap.close()
        file_encap.close()
        file_cap.close()
        file_keygen.close()
        file_roundtrip.close()

        counter = counter + 1
        logger.info("Sleep 60 seconds to cool down cpu...")
        time.sleep(20)
        logger.info("40...")
        time.sleep(20)
        logger.info("20...")
        time.sleep(20)
        logger.info("##########################################\n")