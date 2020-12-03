try:
    import tuxedotouch
except ImportError:
    import pytuxedotouch as tuxedotouch

import asyncio
import sys

def usage():
    print("Usage: {0} <ip/host> <username> <password>".format(sys.argv[0]))


async def test_basic(host, username, password):
    tux = tuxedotouch.TuxedoTouchWiFi(host, username, password)

    await tux.initial_login()
    await tux.get_enc_keys()
    foo = await tux.GetSecurityStatus()
    print(foo)
    exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        usage()
        exit(1)

    print("******** Testing basic commands **********")
    asyncio.run(test_basic(sys.argv[1], sys.argv[2], sys.argv[3]))
