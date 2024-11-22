from ctypes import *
import socket
import threading
import time
import logging
import binascii
from eip_structs import hex_escape, set_from_buffer, \
                parse_param_data, \
                EIP_Header, CIP_List_Services_Reply, \
                Register_Session_Reply, Send_RR_Data_Reply, \
                Send_RR_Data_Request

class EIP_Adapter:

    def __init__(self, host='localhost', tcp_port=44818, udp_port=2222):
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.server_socket = None
        self.client_socket = None
        self.client_address = None
        self.connected = False
        self.session_handle = 1
        self.rpi = None  # RPI in milliseconds
        self.udp_socket = None
        self.udp_thread = None
        self.udp_running = False
        self.eip_commands = {0x0004: self.list_services,
                             0x0065: self.register_session,
                             0x006F: self.send_rr_data}

    def setup_udp_connection(self, rpi):
        """Set up a UDP connection and start sending at the RPI rate."""
        if rpi > 60000:  # Limit RPI to 60 seconds for practical purposes
            logging.warning(f"RPI value {rpi}ms is too large. Clamping to 60,000ms.")
            rpi = 60000  # Clamp to a maximum of 60 seconds

        self.rpi = rpi / 1000.0  # Convert RPI to seconds
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.udp_running = True
        self.udp_thread = threading.Thread(target=self._udp_sender, daemon=True)
        self.udp_thread.start()

        logging.info(f"UDP connection setup on port {self.udp_port} with RPI {rpi}ms.")

    def _udp_sender(self):
        """Send cyclic data over UDP at the RPI rate."""
        while self.udp_running:
            try:
                # Example cyclic data
                data = b'\x00' * 32  # Replace with actual data to send
                self.udp_socket.sendto(data, (self.client_address[0], self.udp_port))
                logging.debug(f"Sent cyclic UDP data: {data.hex()}")
                time.sleep(self.rpi)
            except socket.error as e:
                logging.error(f"UDP send error: {e}")
                break

    def stop_udp_connection(self):
        """Stop the UDP connection."""
        self.udp_running = False
        if self.udp_thread:
            self.udp_thread.join()
        if self.udp_socket:
            self.udp_socket.close()
        self.udp_socket = None
        self.udp_thread = None
        logging.info("UDP connection stopped.")

    def list_services(self, data):
        reply = CIP_List_Services_Reply()
        reply.item_count = 0x0001
        reply.type_id = 0x0100 #Type ID: List Services Response (0x0100)
        reply.len = 0x0014 # 20 bytes after this
        reply.encapaver = 0x0001 # Encapsulation Protocol Version: 1
        reply.capaflags = 0x0120 # Capability Flags: 0x0120, Supports CIP Encapsulation via TCP, Supports CIP Class 0 or 1 via UDP
        reply.servicename = 'Communications'.encode('ascii') #Name of Service: Communications
        
        header = set_from_buffer(EIP_Header, data[:sizeof(EIP_Header)])
        header.len = sizeof(reply)
        response = bytes(header) + bytes(reply)
        return response

    def register_session(self, data):
        reply = Register_Session_Reply()
        reply.version = 1
        header = set_from_buffer(EIP_Header, data[:sizeof(EIP_Header)])
        header.len = sizeof(reply)
        self.session_handle += 1 #increment by 1 on every new connection
        header.session_handle = self.session_handle
        response = bytes(header) + bytes(reply)
        return response

    def send_rr_data(self, data):
        """
        Handles the Send RR Data command.
        Parses the request, processes it, and sends an appropriate reply.
        """
        # Parse the incoming Send RR Data Request
        data += b'\x00' * max((sizeof(Send_RR_Data_Request) - len(data[24:])), 0) # Pad with null bytes
        request = Send_RR_Data_Request.from_buffer_copy(data[24:])  # Skip Ethernet/IP header

        logging.debug(f"Received Send RR Data Request: {request}")

        # Parse the CIP data from the request
        service = request.service

        if service == 0x54:  # Forward Open
            # Extract O->T RPI (Requested Packet Interval)
            o_t_rpi_offset = 44  # Offset for O->T RPI in the CIP data
            o_t_rpi_bytes = request.param_data[o_t_rpi_offset:o_t_rpi_offset + 4]
            o_t_rpi_microseconds = int.from_bytes(o_t_rpi_bytes, byteorder='little')
            o_t_rpi_milliseconds = o_t_rpi_microseconds / 1000.0  # Convert to milliseconds

            # Extract T->O RPI (Requested Packet Interval)
            t_o_rpi_offset = 50  # Offset for T->O RPI in the CIP data
            t_o_rpi_bytes = request.param_data[t_o_rpi_offset:t_o_rpi_offset + 4]
            t_o_rpi_microseconds = int.from_bytes(t_o_rpi_bytes, byteorder='little')
            t_o_rpi_milliseconds = t_o_rpi_microseconds / 1000.0  # Convert to milliseconds

            # Log the parsed RPIs
            logging.info(f"O->T RPI: {o_t_rpi_microseconds} µs ({o_t_rpi_milliseconds} ms)")
            logging.info(f"T->O RPI: {t_o_rpi_microseconds} µs ({t_o_rpi_milliseconds} ms)")

        elif service == 0x4E:  # Forward Close
            logging.info("Received Forward Close request. Stopping UDP connection.")
            # Stop the UDP connection
            self.stop_udp_connection()

        try:
            cip_data = parse_param_data(service, request.param_data)
            logging.info(f"Parsed CIP data: {cip_data}")
        except ValueError as e:
            logging.error(f"Unsupported CIP service: {e}")
            return None

        # Prepare the Send RR Data Reply
        reply = Send_RR_Data_Reply()
        reply.interface_handle = request.interface_handle
        reply.timeout = request.timeout
        reply.item_count = 2  # Typically Address + Data items

        # Address Item (Null Address)
        reply.item0_type_id = 0x0000  # Null address
        reply.item0_len = 0x0000     # Null address length

        # Data Item (Unconnected Data)
        reply.item1_type_id = 0x00B2  # Unconnected Data
        reply.item1_len = len(data[24:])  # CIP response length (set dynamically)

        # CIP-Specific Reply (example for Forward Open or Close)
        reply.service = service | 0x80  # Mark as response (0x80)
        reply.reserved = 0x00
        reply.path_size = request.path_size
        reply.path_class = request.path_class
        reply.path_instance = request.path_instance

        # Populate CIP data in the reply (echo request or mock response)
        # For testing, this could simply echo back some fields:
        response_data = b"\x00" * 30  # Mock response data
        reply.cip_data[:len(response_data)] = response_data

        logging.debug(f"Generated Send RR Data Reply: {reply}")

        # Send the reply back to the client
        response_bytes = bytes(reply)
        self.send_data(response_bytes)


    def serve(self):
        while self.server_socket:
            self.parse_request(self.receive_data())
            
            
    
    def parse_request(self, data):
        header = set_from_buffer(EIP_Header, data[:sizeof(EIP_Header)])
        response = None
        try:
            response = self.eip_commands[header.cmd](data)
        except KeyError:
            logging.info(f"Unknown CIP Service Requested: 0x{header.cmd:02X}")
        if response:
            self.send_data(response)

    def __enter__(self):
        # Called when entering the 'with' block
        logging.debug(f"Initializing server socket on {self.host}:{self.tcp_port}")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.tcp_port))  # Bind to address and port
        self.server_socket.listen(5)  # Start listening for connections (max 5 clients in queue)
        logging.info(f"Server listening on {self.host}:{self.tcp_port}...")

        # Accept a connection from a client
        self.client_socket, self.client_address = self.server_socket.accept()
        logging.info(f"Connection established with {self.client_address}")
        return self  # Return the adapter

    def __exit__(self, exc_type, exc_value, traceback):
        # Called when exiting the 'with' block
        if self.client_socket:
            logging.debug(f"Closing connection with {self.client_address}")
            self.client_socket.close()  # Close the client socket
            logging.info(f"Client connection to {self.client_address} closed.")
        if self.server_socket:
            logging.debug("Closing server socket.")
            self.server_socket.close()  # Close the server socket
            logging.info("Server socket closed.")
        self.client_socket = None
        self.server_socket = None

    def receive_data(self, buffer_size=1024):
        """Method to receive data from the client."""
        data = self.client_socket.recv(buffer_size)
        # Log the received binary data with escaped hex format
        logging.debug(f"Received data: {hex_escape(data)}")  # Log the binary data as escaped hex bytes
        return data

    def send_data(self, data):
        """Method to send data to the client."""
        # Log the binary data being sent with escaped hex format
        logging.debug(f"Sending data: {hex_escape(data)}")  # Log the binary data as escaped hex bytes
        self.client_socket.send(data)
        logging.info(f"Data sent to {self.client_address}: {hex_escape(data)}")  # Log the sent data with escaped hex
