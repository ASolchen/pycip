import logging
from eip_structs import EIP_Header
from cip_handler import CIP_Handler


class EthernetIP:
    def __init__(self, adapter):
        self.adapter = adapter
        self.session_handle = 0
        self.cip_handler = CIP_Handler(adapter)  # Direct reference to CIP_Handler
        self.eip_commands = {
            0x0004: self.handle_list_services,       # List Services (EtherNet/IP-level command)
            0x0063: self.cip_handler.handle_list_identity,  # Delegated to CIP_Handler
            0x0064: self.cip_handler.handle_list_interfaces,  # Delegated to CIP_Handler
            0x0065: self.handle_register_session,    # Register Session
            0x0066: self.handle_unregister_session,  # Unregister Session
            0x006F: self.cip_handler.handle_send_rr_data,    # Delegated to CIP_Handler
            0x0070: self.cip_handler.handle_send_unit_data,  # Delegated to CIP_Handler
        }
        

    def handle_request(self, data):
        """Handle incoming EtherNet/IP request."""
        # Parse the EtherNet/IP header (first 24 bytes)
        eip_header = EIP_Header.from_buffer_copy(data[:24])
        logging.debug(f"Parsed EIP Header: {eip_header}")

        # Dispatch to the appropriate EIP command handler
        handler = self.eip_commands.get(eip_header.cmd)
        if handler:
            response_data = handler(data[24:])
        else:
            self.unsupported_command(eip_header)

        # Construct the response header
        eip_header.len = len(response_data)
        eip_header.status = 0x0000  # Success
        eip_header.session_handle = self.session_handle
        full_response = bytes(eip_header) + response_data
        self.adapter.send_data(full_response)
        logging.debug(f"Full Response Sent: {full_response.hex()}")

    def handle_list_services(self, data):
        """Handle List Services (0x0004)."""
        # Example static response
        service_data = (
            b'\x01\x00'                 # Item Count
            b'\x00\x01'                 # Encapsulation Version
            b'\x14\x00\x01\x00\x20\x01' # Additional Info
            b'Communications\x00\x00'  # Service Name
        )
        return service_data

    def handle_register_session(self, data):
        """Handle Register Session (0x0065)."""
        self.session_handle += 1

        # Example response
        response_data = (
            b'\x01\x00'  # Protocol Version
            b'\x00\x00'  # Option Flags
        )
        return response_data

    def handle_unregister_session(self, data):
        """Handle Unregister Session (0x0066)."""
        # No additional response data needed
        return b''

    def unsupported_command(self, data):
        """Handle unsupported EtherNet/IP commands."""
        logging.warning(f"Unsupported EIP Command: 0x{eip_header.cmd:04X}")
        return None
