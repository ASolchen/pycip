import logging
from eip_structs import Send_RR_Data
from cip_item_structs import (NullAddressItem,
                              UnconnectedDataItem,
                              SocketAddressInfo)
from cip_service_structs import (ForwardOpenRequest,
        ForwardOpenResponse, CIP_Message)


class CIP_Handler:
    def __init__(self, adapter):
        self.adapter = adapter
        self.rr_service_handlers = {
            0x54: self.handle_forward_open,          # Forward Open
            0x4E: self.handle_forward_close,         # Forward Close
            0x0E: self.handle_read_attribute_single, # Read Attribute Single
            0x10: self.handle_write_attribute_single # Write Attribute Single
        }

    def handle_request(self, cip_data):
        """
        Handle incoming CIP data, delegating to service-specific handlers.
        :param cip_data: Raw CIP data
        :return: Response data
        """
        cip_message = CIP_Message(cip_data)
        service_code = cip_message.service & 0x7F  # Mask out the response bit
        handler = self.rr_service_handlers.get(service_code, self.unsupported_service)
        return handler(cip_message)

    def handle_forward_open(self, send_rr_req):
        """Handle Forward Open (0x54)."""

        fwd_open_req = None
        for item in send_rr_req.items:
            if isinstance(item, UnconnectedDataItem):
                fwd_open_req = ForwardOpenRequest(item.to_bytes())
        if not fwd_open_req:
            raise ValueError("Forward Open Request not found")
        

        reply = Send_RR_Data()
        reply.add_item(NullAddressItem())

        # Create a Forward Open response
        fwd_open_resp = ForwardOpenResponse()
        fwd_open_resp.o_t_connection_id = 0x23d013 #generate random?
        fwd_open_resp.t_o_connection_id = fwd_open_req.t_o_connection_id 
        fwd_open_resp.t_o_rpi = fwd_open_req.t_o_rpi
        fwd_open_resp.o_t_rpi = fwd_open_req.o_t_rpi
        fwd_open_resp.connection_serial_number = fwd_open_req.connection_serial_number
        fwd_open_resp.originator_vendor_id = fwd_open_req.originator_vendor_id
        fwd_open_resp.originator_serial_number = fwd_open_req.originator_serial_number
        fwd_open_resp.connection_to_multiplier = fwd_open_req.connection_to_multiplier
        unconnected_data_item = UnconnectedDataItem(fwd_open_resp.to_bytes())

        reply.add_item(unconnected_data_item)
        sock_params = {
            'family': 0x02, #UDP?
            'port': self.adapter.udp_port,
            'address': 0x0000 # 0.0.0.0
        }
        socket_addr = SocketAddressInfo(sock_params)
        reply.add_item(socket_addr)

        # Setup UDP connection in the adapter (Should probably check if cyclic type?)
        self.adapter.connection_id = fwd_open_resp.o_t_connection_id
        self.adapter.remote_connection_id = fwd_open_resp.t_o_connection_id
        self.adapter.setup_udp(fwd_open_req.o_t_rpi/ 1000000.0)
        reply_data = reply.to_bytes()
        logging.debug(f"Parsed Forward Open Request: {reply_data.hex()}")
        return reply_data

    def handle_forward_close(self, cip_message):
        """Handle Forward Close (0x4E)."""
        # Example: Return a basic success response
        cip_response = CIP_Message()  # Set response bit
        cip_response.service=0x4E | 0x80
        return cip_response.to_bytes()

    def handle_read_attribute_single(self, cip_message):
        """Handle Read Attribute Single (0x0E)."""
        # Respond with mock attribute data
        attribute_data = b'\x01\x02\x03\x04'  # Example data
        cip_response = CIP_Message(service=0x0E | 0x80)  # Set response bit
        return cip_response.to_bytes(response_data=attribute_data)

    def handle_write_attribute_single(self, cip_message):
        """Handle Write Attribute Single (0x10)."""
        # Update the adapter's IO data (mock write)
        self.adapter.io_data = cip_message.items[0].data  # Assuming data is in the first item
        cip_response = CIP_Message(service=0x10 | 0x80)  # Set response bit
        return cip_response.to_bytes()

    def handle_send_unit_data(self, cip_message):
        """
        Handle Send Unit Data (0x0070).
        """
        logging.info("Handling Send Unit Data Request")
        # Example: Mock response to Send Unit Data
        unit_data_response = (
            b'\x01\x00'  # Unit data count (example value)
            b'\x00\x00'  # Reserved
        )

        # Build CIP Response
        cip_response = CIP_Message(service=0x70 | 0x80)  # Set reply bit
        return cip_response.to_bytes(response_data=unit_data_response)

    def handle_send_rr_data(self, cip_data):
        """
        Handle Send RR Data (0x006F).
        """
        logging.info("Handling Send RR Data Request")
        request = Send_RR_Data(cip_data)
        for item in request.items:
            if item.type_id == 0x00b2: # unconnected data item
                if item.to_bytes()[4] in self.rr_service_handlers:
                    return self.rr_service_handlers[item.to_bytes()[4]](request)

    def handle_list_interfaces(self, cip_message):
        """
        Handle List Interfaces (0x0064).
        """
        logging.info("Handling List Interfaces Request")
        interfaces_data = (
            b'\x00\x00'  # Interface Type: Null (no interfaces available)
            b'\x00\x00'  # Reserved
        )

        # Build CIP Response
        cip_response = CIP_Message(service=0x64 | 0x80)  # Set reply bit
        return cip_response.to_bytes(response_data=interfaces_data)

    def handle_list_identity(self, cip_message):
        """
        Handle List Identity (0x0063).
        """
        logging.info("Handling List Identity Request")
        identity_data = (
            b'\x01\x00'  # Item Count
            b'\x0C\x00'  # Item Type
            b'\x36\x00'  # Item Length
            b'\x01\x00'  # Encapsulation Version
            b'\x01\x00'  # Vendor ID
            b'\x64\x00'  # Device Type
            b'\x01\x00'  # Product Code
            b'\x01\x00'  # Major Revision
            b'\x00\x00'  # Minor Revision
            b'\x00\x00\x00\x00'  # Serial Number
            b'Example Device\x00'  # Product Name
        )

        # Build CIP Response
        cip_response = CIP_Message(service=0x63 | 0x80)  # Set reply bit
        return cip_response.to_bytes(response_data=identity_data)

    def unsupported_service(self, cip_message):
        """Handle unsupported CIP services."""
        logging.warning(f"Unsupported CIP Service Code: 0x{cip_message.service:02X}")
        cip_response = CIP_Message(service=cip_message.service | 0x80, general_status=0x08)  # Service not supported
        return cip_response.to_bytes()

    # Additional helper methods for building specific responses

    def build_list_identity_item(self):
        """Build List Identity item for List Identity responses."""
        return (
            b'\x01\x00'  # Item Count
            b'\x0C\x00'  # Item Type
            b'\x36\x00'  # Item Length
            b'\x01\x00'  # Encapsulation Version
            b'\x01\x00'  # Vendor ID
            b'\x64\x00'  # Device Type
            b'\x01\x00'  # Product Code
            b'\x01\x00'  # Major Revision
            b'\x00\x00'  # Minor Revision
            b'\x00\x00\x00\x00'  # Serial Number
            b'Example Device\x00'  # Product Name
        )

    def build_list_services_item(self):
        """Build List Services item for List Services responses."""
        return (
            b'\x01\x00'                 # Item Count
            b'\x00\x01'                 # Encapsulation Version
            b'\x14\x00\x01\x00\x20\x01' # Additional Info
            b'Communications\x00\x00'  # Service Name
        )
