import logging
import socket
import threading
import time
from ctypes import c_uint8
from ethernetip import EthernetIP
from eip_structs import CIP_IO_Reply

class Adapter:
    def __init__(self, host='localhost', tcp_port=44818, udp_port=2222):
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.client_socket = None
        self.client_address = None
        self.server_socket = None
        self.udp_socket = None
        self.udp_thread = None
        self.udp_running = False
        self.io_read_data = (c_uint8 * 30)()  # I/O Buffer to PLC 
        self.io_write_data = (c_uint8 * 32)()  # I/O Buffer from PLC 
        self.connection_id = None
        self.remote_connection_id = None
        self.cip_sequence_count = 1
        self.ethip = EthernetIP(self)  # Pass a reference of itself

    def start_server(self):
        """Start the TCP server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.tcp_port))
        self.server_socket.listen(1)
        logging.info(f"Adapter listening on {self.host}:{self.tcp_port}")

        self.client_socket, self.client_address = self.server_socket.accept()
        logging.info(f"Connection established with {self.client_address}")
        self.listen_for_requests()

    def listen_for_requests(self):
        """Listen for TCP requests."""
        while True:
            try:
                data = self.client_socket.recv(1024)
                if data:
                    self.ethip.handle_request(data)
            except Exception as e:
                logging.error(f"Error receiving data: {e}")
                break

    def send_data(self, data):
        """Send data to the TCP client."""
        try:
            self.client_socket.send(data)
            logging.debug(f"Sent data: {data.hex()}")
        except Exception as e:
            logging.error(f"Error sending data: {e}")

    def setup_udp(self, rpi):
        """Set up UDP cyclic data."""
        if self.udp_running:
            logging.warning("UDP already running.")
            return

        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.host, self.udp_port))
        self.udp_running = True
        self.udp_thread = threading.Thread(target=self._udp_sender, args=(rpi,), daemon=True)
        self.udp_thread.start()

    def _udp_sender(self, rpi):
        """Send cyclic data over UDP."""
        while self.udp_running:
            try:
                recv_data = self.udp_socket.recv(1024)
                logging.debug(f"Recieved UDP data: {recv_data.hex()}")
                data = CIP_IO_Reply(self.remote_connection_id,
                                    self.cip_sequence_count, self.io_read_data).to_bytes()
                self.udp_socket.sendto(data, (self.client_address[0], self.udp_port))
                #logging.debug(f"Sent UDP data: {data.hex()}")
                self.cip_sequence_count = (1 + self.cip_sequence_count) & 0xFFFFFFF #roll over
                time.sleep(rpi)
            except Exception as e:
                logging.error(f"Error sending UDP data: {e}")
                self.stop_udp()

    def stop_udp(self):
        """Stop the UDP connection."""
        self.udp_running = False
        if self.udp_socket:
            self.udp_socket.close()
        logging.info("UDP connection stopped.")

    def close(self):
        """Close all resources."""
        self.stop_udp()
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()
