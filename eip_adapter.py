import logging
import socket
import threading
import time
from ctypes import c_uint16, sizeof, c_uint8
from eip_structs import (
    EIP_Header,
    Send_RR_Data_Request,
    Send_RR_Data_Reply,
    CIP_IO_Reply,
    parse_param_data,
)
from cip_service_structs import (ForwardOpenRequest,
                                 ForwardOpenResponse,
                                 ForwardCloseData,
                                 CIP_Response)


class EIP_Adapter:
    def __init__(self, host='localhost', tcp_port=44818, udp_port=2222):
        self.cip_io_data = (c_uint8 * 32)() # data back to PLC
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.udp_sequence_counter = 1
        self.server_socket = None
        self.client_socket = None
        self.client_address = None
        self.connected = False
        self.session_handle = 1
        self.eip_commands = {
            0x0004: self.handle_list_services,       # List Services
            0x0063: self.handle_list_identity,       # List Identity
            0x0064: self.handle_list_interfaces,     # List Interfaces (optional, rarely used)
            0x0065: self.handle_register_session,    # Register Session
            0x0066: self.handle_unregister_session,  # Unregister Session
            0x006F: self.handle_send_rr_data,        # Send RR Data
            0x0070: self.handle_send_unit_data,      # Send Unit Data
        }
        self.udp_socket = None
        self.udp_thread = None
        self.udp_running = False

    def serve(self):
        """Main loop for handling connections."""
        while self.server_socket:
            data = self.receive_data()
            if data:
                self.parse_request(data)
            

    def parse_request(self, data):
        """Parse the incoming EtherNet/IP request."""
        eip_header = EIP_Header.from_buffer_copy(data[:24])
        logging.debug(f"Parsed EIP Header: {eip_header}")

        if eip_header.cmd in self.eip_commands:
            self.eip_commands[eip_header.cmd](data)
        else:
            logging.warning(f"Unsupported EtherNet/IP command: 0x{eip_header.cmd:04X}")


    def handle_send_rr_data(self, data):
        """
        Handle the Send RR Data (0x6F) command.
        Parse the request and construct a valid response.
        """
        logging.info("Handling Send RR Data command.")

        # Parse the EtherNet/IP header (24 bytes)
        eip_header = EIP_Header.from_buffer_copy(data[:24])
        logging.debug(f"Parsed EIP Header: {eip_header}")

        # Parse the Send RR Data Request
        rr_request = Send_RR_Data_Request.from_buffer_copy(data[24:])
        logging.debug(f"Parsed Send RR Data Request: {rr_request}")

        # Calculate the offset to the CIP data
        cip_data_offset = 24 + sizeof(Send_RR_Data_Request)
        cip_data_offset += rr_request.item0_len  # Add Address Item length
        cip_data = data[cip_data_offset: cip_data_offset + rr_request.item1_len]
        logging.debug(f"Extracted CIP Data: {cip_data.hex()}")

        # Get the CIP service code
        service_code = cip_data[0]
        logging.info(f"CIP Service Code: 0x{service_code:02X}")

        # CIP Service Handlers
        cip_service_handlers = {
            0x54: self.handle_forward_open,          # Forward Open
            0x4E: self.handle_forward_close,         # Forward Close
            0x0E: self.handle_read_attribute_single, # Read Attribute Single
            0x10: self.handle_write_attribute_single # Write Attribute Single
        }

        # Dispatch to the appropriate CIP service handler
        handler = cip_service_handlers.get(service_code, self.unsupported_service)

        # Extract the fixed portion of the CIP response
        fixed_cip_offset = 2  # Service Code (1) + Path Size (1)
        path_size = cip_data[1] * 2  # Path size in bytes (Path Size * 2)
        general_status_offset = fixed_cip_offset + path_size  # Path data ends
        additional_status_offset = general_status_offset + 1  # General Status (1 byte)
        additional_status_size = cip_data[general_status_offset] * 2  # Additional Status Size in bytes

        # Extract service-specific data after additional status
        service_specific_data_offset = additional_status_offset + additional_status_size
        cip_service_response = handler(cip_data[service_specific_data_offset:], eip_header)

        # Prepare the CIP response
        cip_response = CIP_Response()
        cip_response.service = service_code | 0x80  # Set the reply bit
        cip_response.general_status = 0x00  # 0x00 = success
        cip_response.additional_status_size = 0x00  # 0 words

        cip_response_data = bytes(cip_response) + cip_data[fixed_cip_offset:service_specific_data_offset] + cip_service_response

        # Align the CIP response to 16-bit boundary
        cip_response_data = cip_response.align_to_word(cip_response_data)

        # Build the Send RR Data Reply structure
        send_rr_response = Send_RR_Data_Reply()
        send_rr_response.interface_handle = rr_request.interface_handle
        send_rr_response.timeout = rr_request.timeout
        send_rr_response.item_count = 2  # Address Item + Data Item
        send_rr_response.item0_type_id = 0x0000  # Null Address Item
        send_rr_response.item0_len = 0x0000
        send_rr_response.item1_type_id = 0x00B2  # Unconnected Data Item
        send_rr_response.item1_len = len(cip_response_data)  # CIP Response Length

        # Combine the Send RR Data reply and CIP response
        command_response = bytes(send_rr_response) + cip_response_data
        logging.debug(f"Constructed Command Response: {command_response.hex()}")

        # Build the EtherNet/IP header
        eip_response_header = EIP_Header()
        eip_response_header.cmd = 0x6F  # Send RR Data response
        eip_response_header.len = len(command_response)  # Total payload length
        eip_response_header.session_handle = eip_header.session_handle
        eip_response_header.status = 0x0000  # Success
        eip_response_header.sender_context = eip_header.sender_context  # Echo sender context
        eip_response_header.options = 0x0000  # Default options

        # Combine the EIP header and command response
        full_response = bytes(eip_response_header) + command_response
        logging.debug(f"Full Response: {full_response.hex()}")

        # Send the response back to the client
        self.send_data(full_response)
        logging.info(f"Sent Full Response to Client.")


    def unsupported_service(self, cip_data, eip_header):
        """
        Handle unsupported or unimplemented CIP services.
        Returns an EtherNet/IP response with a CIP error payload.
        """
        service_code = cip_data[0]
        logging.warning(f"Unsupported CIP service code: 0x{service_code:02X}")

        # CIP Error Response
        cip_response = bytes([
            service_code | 0x80,  # Add 0x80 to indicate it's a response
            0x08,                # General Status: Service Not Supported
            0x00                 # No additional status
        ])

        # Build the EtherNet/IP header
        response_header = EIP_Header()
        response_header.cmd = 0x6F  # Send RR Data
        response_header.len = len(cip_response)  # Length of CIP payload
        response_header.session_handle = eip_header.session_handle
        response_header.status = 0x0000  # Success
        response_header.sender_context = eip_header.sender_context  # Echo sender context
        response_header.options = 0x0000  # Default options

        # Combine the EIP header and CIP error response
        response = bytes(response_header) + cip_response

        return response

    def handle_forward_open(self, cip_data, eip_header):
        """
        Handle the Forward Open CIP service (0x54).
        Generate a response based on the parsed request data and EIP header.
        """
        logging.info("Handling Forward Open service.")

        # Parse the Forward Open request
        forward_open_request = ForwardOpenRequest.from_buffer_copy(cip_data+b'\x00'*(sizeof(ForwardOpenRequest)-len(cip_data)))
        logging.debug(f"Parsed Forward Open Request: {forward_open_request}")

        # Prepare the Forward Open Response structure
        forward_open_response = ForwardOpenResponse()

        # Populate response using request fields
        forward_open_response.o_t_connection_id = forward_open_request.o_t_connection_id
        forward_open_response.t_o_connection_id = forward_open_request.t_o_connection_id
        forward_open_response.connection_serial_number = forward_open_request.connection_serial_number
        forward_open_response.originator_vendor_id = forward_open_request.originator_vendor_id
        forward_open_response.originator_serial_number = forward_open_request.originator_serial_number
        forward_open_response.o_t_rpi = forward_open_request.o_t_rpi
        forward_open_response.t_o_rpi = forward_open_request.t_o_rpi
        forward_open_response.application_reply_size = 0x00

        logging.info(f"Setting up UDP connection with RPI: {forward_open_request.t_o_rpi} and Connection ID: {forward_open_request.t_o_connection_id}")
        # Set up the UDP connection
        self.setup_udp_connection(rpi = forward_open_request.t_o_rpi,
                                  connection_id = forward_open_request.t_o_connection_id)
        # Convert the response structure to bytes
        cip_response = bytes(forward_open_response)


        logging.debug(f"Constructed Forward Open Response: {cip_response.hex()}")

        return cip_response


    def handle_forward_close(self, cip_data, eip_header):
        """Handle the Forward Close CIP service."""
        logging.info("Handling Forward Close service.")
        # Example response (mocked):
        return b'\x4E\x00\x00\x00'  # Success response
    
    def handle_read_attribute_single(self, cip_data, eip_header):
        """Handle the Read Attribute Single CIP service."""
        logging.info("Handling Read Attribute Single service.")
        # Example response: attribute value (mocked)
        return b'\x0E\x00\x00\x00\xAB\xCD'  # Example attribute value (0xABCD)
    
    def handle_write_attribute_single(self, cip_data, eip_header):
        """Handle the Write Attribute Single CIP service."""
        logging.info("Handling Write Attribute Single service.")
        # Example response (mocked):
        return b'\x10\x00\x00\x00'  # Success response

    def handle_send_unit_data(self, data):
        """Handle the Send Unit Data command."""
        logging.info("Received Send Unit Data command. Not implemented.")
        # Parse and handle unit-specific data as needed
        #TODO
        raise NotImplementedError("EIP_Adapter.handle_send_unit_data() is not complete")

    def handle_register_session(self, data):
        """
        Handle the Register Session (0x0065) command.
        Generate a response to establish a session.
        """
        logging.info("Handling Register Session command.")

        # Parse the received EtherNet/IP header
        eip_header = EIP_Header.from_buffer_copy(data[:24])

        # Increment the session handle (unique identifier for each session)
        self.session_handle += 1

        # Construct the response EtherNet/IP header
        response_header = EIP_Header()
        response_header.cmd = 0x0065  # Command: Register Session
        response_header.len = 4       # Payload length (Protocol Version + Option Flags)
        response_header.session_handle = self.session_handle
        response_header.status = 0x0000  # Status: Success
        response_header.sender_context = eip_header.sender_context  # Echo sender context
        response_header.options = 0x0000  # Default options

        # Construct the payload
        protocol_version = b'\x01\x00'  # Protocol Version: 1 (little-endian)
        option_flags = b'\x00\x00'      # Option Flags: 0 (no flags set)
        payload = protocol_version + option_flags

        # Combine the header and payload
        response = bytes(response_header) + payload

        # Send the response back to the client
        self.send_data(response)

        logging.debug(f"Sent Register Session response: {response.hex()}")


    def handle_unregister_session(self, data):
        """Handle the Unregister Session command."""
        logging.info("Handling Unregister Session command.")
        self.session_handle = 0  # Reset session handle

    def handle_list_services(self, data):
        """
        Handle the List Services (0x0004) command.
        Generate a response indicating the supported service, including the EtherNet/IP header.
        Ensure response length aligns to 16-bit boundaries.
        """
        logging.info("Handling List Services command.")

        # Build the response components
        item_count = b'\x01\x00'  # Item count: 1 service
        type_id = b'\x00\x01'  # Type ID: 0x0001 (List Services Response)
        encapsulation_version = b'\x01\x00'  # Encapsulation version: 1
        capability_flags = b'\x20\x01'  # Capability flags (TCP, Class 0/1 support)
        service_name = b'Communications\x00'  # Null-terminated service name

        # Ensure the length of the service name is even
        if len(service_name) % 2 != 0:
            service_name += b'\x00'  # Add padding byte if the length is odd

        service_data = encapsulation_version + capability_flags + service_name
        service_length = len(service_data).to_bytes(2, 'little')  # Length in little-endian

        # Combine the CIP response
        cip_response = (
            item_count +  # Number of items
            type_id +     # Type ID
            service_length +  # Length of service-specific data
            service_data  # Actual service data
        )

        # Construct the EtherNet/IP header
        eip_header = EIP_Header()
        eip_header.cmd = 0x0004  # Command: List Services
        eip_header.len = len(cip_response)  # Length of the payload
        eip_header.session_handle = 0x00  # Example session handle (no session for List Services)
        eip_header.status = 0x00  # Status OK
        eip_header.sender_context = 0x00  # Sender context
        eip_header.options = 0x00  # Options

        # Combine the header and response
        response = bytes(eip_header) + cip_response

        # Send the response back to the client
        self.send_data(response)

        logging.debug(f"Sent List Services response: {response.hex()}")


    def handle_list_identity(self, data):
        """Handle the List Identity command."""
        logging.info("Handling List Identity command.")
        response = b'\x00' * 64  # Example: 64 bytes of identity data
        self.send_data(response)

    def handle_list_interfaces(self, data):
        """Handle the List Iterfaces command."""
        logging.info("ReceivedList Iterfaces command. Not implemented.")
        # Parse and handle unit-specific data as needed
        #TODO
        raise NotImplementedError("EIP_Adapter.handle_list_interfaces() is not complete")



    def setup_udp_connection(self, rpi, connection_id):
        """Set up a UDP connection."""
        if self.udp_running:
            logging.warning("UDP connection already running.")
            return

        self.udp_running = True
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_thread = threading.Thread(target=self._udp_sender, args=(rpi,connection_id), daemon=True)
        self.udp_thread.start()
        logging.info(f"UDP connection set up with RPI: {rpi} ms")

    def generate_udp_payload(self, connection_id):
        """Generate the payload data for cyclic UDP transmission."""
        cip_io_reply = CIP_IO_Reply()
        cip_io_reply.item_count = 2
        cip_io_reply.type1_id = 0x8002 # Seq Address Item
        cip_io_reply.type1_len = 8
        cip_io_reply.connection_id = connection_id
        cip_io_reply.encap_seq_count = self.udp_sequence_counter
        cip_io_reply.type2_id = 0x00b1 # Connected Data Item
        cip_io_reply.type2_len = sizeof(c_uint16) + self.cip_io_data._length_


        packet = bytes(cip_io_reply) + bytes(self.cip_io_data)
        # Increment the sequence counter
        self.udp_sequence_counter += 1
        logging.debug(f"CIP I/O Send: {packet.hex()}")
        return packet
        

    def _udp_sender(self, rpi, connection_id):
        """Send cyclic data over UDP at the RPI rate."""
        while self.udp_running:
            try:
                # Generate dynamic payload data (replace this with actual I/O data)
                udp_packet = self.generate_udp_payload(connection_id)
                # Send the packet
                self.udp_socket.sendto(udp_packet, (self.client_address[0], self.udp_port))
                logging.debug(f"Sent cyclic UDP data: {udp_packet.hex()}")
                # Sleep for the RPI (convert milliseconds to seconds)
                time.sleep(rpi / 1000.0)

            except Exception as e:
                logging.error(f"Error sending UDP data: {e}")
                self.udp_running = False  # Stop the loop on error

                raise e


    def stop_udp_connection(self):
        """Stop the UDP connection."""
        self.udp_running = False
        if self.udp_thread:
            self.udp_thread.join()
        if self.udp_socket:
            self.udp_socket.close()
        self.udp_thread = None
        self.udp_socket = None
        logging.info("UDP connection stopped.")

    def receive_data(self, buffer_size=1024):
        """Receive data from the TCP client."""
        try:
            data = self.client_socket.recv(buffer_size)
            logging.debug(f"Received data: {data.hex()}")
            return data
        except ConnectionResetError:
            logging.warning("Connection reset by client.")
        except Exception as e:
            logging.error(f"Error receiving data: {e}")
        return None

    def send_data(self, data):
        """Send data to the TCP client."""
        try:
            self.client_socket.send(data)
            logging.debug(f"Sent data: {data.hex()}")
        except Exception as e:
            logging.error(f"Error sending data: {e}")

    def __enter__(self):
        """Start the TCP server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.tcp_port))
        self.server_socket.listen(5)
        logging.info(f"Server listening on {self.host}:{self.tcp_port}")
        self.client_socket, self.client_address = self.server_socket.accept()
        logging.info(f"Connection established with {self.client_address}")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Clean up resources."""
        self.stop_udp_connection()
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()
