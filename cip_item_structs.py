from ctypes import *
import logging
import struct

class NullAddressItem(Structure):
    """CIP: Type ID: 0x0000"""
    type_code = 0x0000
    _pack_ = 1
    _fields_ = [
        ('type_id', c_uint16),             # 0x00 for Null Address
        ('length', c_uint16),              # length of data for the item
        ('data', c_uint8 * 0)              # Placeholder for dynamic data (Always 0 bytes)
    ]

    def __init__(self):
        self.type_id = self.type_code #have both so we can access code of the casee w/o an instance
        self.length = 0

    def to_bytes(self):
        return bytes(self)


class UnconnectedDataItem(Structure):
    """
    Represents the Unconnected Data Item in CIP.
    The length of `data` is determined dynamically based on item1_len.
    """
    type_code = 0x00B2
    _pack_ = 1
    _fields_ = [
        ('type_id', c_uint16),  # Type ID (0x00B2 for Unconnected Data Item)
        ('length', c_uint16),  # Length of the data (dynamic)
    ]

    def __init__(self, data_bytes):
        """
        Initialize the Unconnected Data Item.
        :param data_bytes: The CIP payload (as bytes).
        """
        self.type_id = self.type_code #have both so we can access code of the casee w/o an instance
        self.length = len(data_bytes)
        # Dynamically set the `data` field to the size of the payload
        self.data = (c_uint8 * self.length).from_buffer_copy(data_bytes)

    def to_bytes(self):
        """Convert the Unconnected Data Item to bytes."""
        return bytes(self) + bytes(self.data)


class SocketAddressInfo(Structure):
    type_code = 0x8000
    _pack_ = 1
    _fields_ = [
        ('type_id', c_uint16),             # 0x8000
        ('length', c_uint16),              # length of data for the item
        ('_sin_family', c_uint16),
        ('_sin_port', c_uint16),
        ('_sin_addr', c_uint32),
        ('sin_zero', c_uint8 * 8)
    ]
    
    @property
    def sin_family(self):
        """Convert sin_family to big-endian."""
        return int.from_bytes(self._sin_family.to_bytes(2, 'little'), 'big')

    @sin_family.setter
    def sin_family(self, value):
        """Store sin_family as little-endian."""
        self._sin_family = int.from_bytes(value.to_bytes(2, 'big'), 'little')

    @property
    def sin_port(self):
        """Convert sin_port to big-endian."""
        return int.from_bytes(self._sin_port.to_bytes(2, 'little'), 'big')

    @sin_port.setter
    def sin_port(self, value):
        """Store sin_port as little-endian."""
        self._sin_port = int.from_bytes(value.to_bytes(2, 'big'), 'little')

    @property
    def sin_addr(self):
        """Convert sin_addr to big-endian."""
        return int.from_bytes(self._sin_addr.to_bytes(4, 'little'), 'big')

    @sin_addr.setter
    def sin_addr(self, value):
        """Store sin_addr as little-endian."""
        self._sin_addr = int.from_bytes(value.to_bytes(4, 'big'), 'little')

    def __init__(self, socket_info):
        """Socket info passed from the EIP_Adapter."""
        self.type_id = self.type_code #have both so we can access code of the casee w/o an instance
        self.sin_family = socket_info['family']
        self.sin_port = socket_info['port']
        self.sin_addr = socket_info['address']
        self.length = len(self.to_bytes()) - 4

    def to_bytes(self):
        """Convert to bytes."""
        self.length = len(bytes(self)) - 4
        return bytes(self)