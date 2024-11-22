from ctypes import *
import socket
import logging
import binascii
from eip_adapter import EIP_Adapter


# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


# Example usage:
while True:
    try:
        with EIP_Adapter(host='', tcp_port=44818) as adapter:
            # This block will execute once a client connects
            adapter.serve()
    except ConnectionResetError:
        logging.debug(f"Connection reset. Reopening...")