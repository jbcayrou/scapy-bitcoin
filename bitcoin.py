#!/usr/bin/env python

# scapy.contrib.description = Bitcoin
# scapy.contrib.status = loads

"""
Copyright (c) 2016 Jean-Baptiste Cayrou <jb.cayrou [_AT_] gmail [_DOT_] com>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.




Bitcoin extension for Scapy <http://www.secdev.org/scapy>

This module provides Scapy layers for the Bitcoin P2P protocol.
Documentation is available here :

https://en.bitcoin.it/wiki/Protocol_documentation
https://bitcoin.org/en/developer-reference#p2p-network
"""

from scapy.all import *
import binascii
import hashlib
import datetime
import struct


INVENTORY_TYPES = {
                    0x0 : "ERROR",
                    0x1 : "MSG_TX",
                    0x2 : "MSG_BLOCK",
                    0x3 : "MSG_FILTERED_BLOCK"
}

# Magic numbers that correspond to the network used
MAGIC_MAIN = 0xD9B4BEF9
MAGIC_REGTEST = 0xDAB5BFFA
MAGIC_TESTNET3 = 0x0709110B
MAGIC_NAMECOIN = 0xFEB4BEF9
MAGIC_VALUES = {
                MAGIC_MAIN : "main",
                MAGIC_REGTEST : "regtest",
                MAGIC_TESTNET3 : "testnet3",
                MAGIC_NAMECOIN : "namecoin",
}

# Port Binding Conf
MAGIC_PORT_BINDING = {  MAGIC_MAIN : 8333,
                        MAGIC_REGTEST : 18444,
                        MAGIC_TESTNET3 : 18333,
                        # MAGIC_NAMECOIN : ???? # TBD
}

SERVICES_TYPES = { 0x1 : "NODE_NETWORK" }


REJECT_CCODES = {
        0x01 : "REJECT_MALFORMED",
        0x10 : "REJECT_INVALID",
        0x11 : "REJECT_OBSOLETE",
        0x12 : "REJECT_DUPLICATE",
        0x40 : "REJECT_NONSTANDARD",
        0x41 : "REJECT_DUST",
        0x42 : "REJECT_INSUFFICIENTFEE",
        0x43 : "REJECT_CHECKPOINT",
}


# Used to display timestamp
def timestamp_to_str(ts):
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

###########################
# BiteCoin Fields
###########################

class XLEIntField(LEIntField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class XLELongField(LELongField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))


class XStrFixedLenField(StrFixedLenField):
    """
    Hexadecimal representation of a StrFixedLenField
    """
    def i2repr(self, pkt, x):
        return binascii.hexlify(x)

class LELongEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "<Q")


class HashField(XStrFixedLenField):

    def __init__(self, name, default):
        XStrFixedLenField.__init__(self, name, default, length=32)


class ChecksumField(XIntField):
    """
    First 4 bytes of sha256(sha256(payload))
    """

    def __init__(self, name, default):
        XIntField.__init__(self, name, default)

    def i2m(self, pkt, x):
        if x is None:
            pay = str(getattr(pkt,"payload",""))
            x = hashlib.sha256((hashlib.sha256(pay).digest())).digest()
            x = struct.unpack(self.fmt, x[0:4])[0]

        return x

class LTimestampField(LELongField):
    """
    Long timestamp
    """
    def __init__(self, name, default):
        LELongField.__init__(self, name, default)

    def i2m(self, pkt, x):
        if x is None:
            x = int(time.time())
        return LELongField.i2m(self, pkt, x)

    def i2h(self, pkt, x):
        if x is None:
            return None
        else:
            return timestamp_to_str(x)


class TimestampField(LEIntField):
    """
    Int timestamp
    """
    def __init__(self, name, default):
        LEIntField.__init__(self, name, default)

    def i2m(self, pkt, x):
        if x is None:
            x = int(time.time())
        return LEIntField.i2m(self, pkt, x)

    def i2h(self, pkt, x):
        if x is None:
            return None
        else:
            return timestamp_to_str(x)

class LockTimeField(LEIntField):
    """
    The block number or timestamp at which this transaction is locked:
    Value   Description
    0   Not locked
    < 500000000 Block number at which this transaction is locked
    >= 500000000    UNIX timestamp at which this transaction is locked
    """

    def i2h(self, pkt, x):
        if x == 0:
            pass
        if x < 500000000: # Block Number
            return hex(x)
        else: # Timestamp
            if x is None:
                return None
            else:
                return timestamp_to_str(x)

class VarIntField(FieldLenField):
    """
    Integer can be encoded depending on the represented value to save space. Variable length integers always
    precede an array/vector of a type of data that may vary in length.
    Longer numbers are encoded in little endian.

    Value           Storage length  Format
    < 0xFD              1            uint8_t
    <= 0xFFFF           3            0xFD followed by the length as uint16_t
    <= 0xFFFF FFFF      5            0xFE followed by the length as uint32_t
    -                   9            0xFF followed by the length as uint64_t
    """

    def __init__(self, name, default, count_of=None):
        FieldLenField.__init__(self, name, default, fmt="B", count_of=count_of)

    def i2m(self, pkt, x):
        if x is None:
            if self.count_of is not None:
                x = len(getattr(pkt, self.count_of))
            else:
                x = 0
        return x

    def getfield(self, pkt, s):
        """Extract an internal value from a string"""

        self.sz = 1
        self.fmt="B"

        offset = 0
        val = struct.unpack(self.fmt, s[:1])
        val = val[0]

        if val == 0xFD:
            self.sz=2
            self.fmt = ">H"
            offset = 1

        elif val == 0xFE:
            self.sz=4
            self.fmt = ">I"
            offset = 1

        elif val == 0xFF:
            self.sz = 8
            self.fmt = ">L"
            offset = 1

        return s[offset+self.sz:], self.m2i(pkt, struct.unpack(self.fmt, s[offset:offset+self.sz])[0])

    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""

        val = self.i2m(pkt,val)

        if val < 0xfd:
            f_s = struct.pack("B",val)
        elif val <= 0xffff:
            f_s = "\xfd" + struct.pack(">H",val)
        elif val <= 0xffffffff:
            f_s = "\xfe" + struct.pack(">I",val)
        else:
            f_s = "\xff" + struct.pack(">L",val)

        return s + f_s


class VarStrPktField(Packet):
    """
    Variable length string can be stored using a variable length integer followed by the string itself.
    """

    fields_desc = [
            VarIntField("len",None, count_of="data"),
            StrLenField("data","", length_from= lambda pkt : pkt.len),
        ]

    def extract_padding(self, s):
        return "",s


class AddrPktField(Packet):
    """
    When a network address is needed somewhere, this structure is used.
    ** Network addresses are not prefixed with a timestamp in the version message. **
    """

    fields_desc = [
        TimestampField("time",int(time.time())),
        LELongEnumField("services", 0, SERVICES_TYPES),
        IP6Field("addr", "fc00:1::1"),
        ShortField("port", 8333),
    ]

    def extract_padding(self, s):
        return "",s

class AddrWithoutTimePktField(Packet):
    """
    Like AddField but wihtout time field
    """

    fields_desc = [
        LELongEnumField("services", 0, SERVICES_TYPES),
        IP6Field("addr", "fc00:1::1"),
        ShortField("port", 8333),
    ]

    def build(self):

        if hasattr(self, "addr"):
            if getattr(self, "addr") is None:
                self.addr = "localhost"

        return Packet.build(self)

    def extract_padding(self, s):
        return "",s

class InventoryPktField(Packet):
    """
    Inventory vectors are used for notifying other nodes about objects they have or data which is being requested.
    """
    fields_desc = [
        LEIntEnumField("type",0, INVENTORY_TYPES),
        HashField("hash",None),
    ]

    def extract_padding(self, s):
        return "",s

class BlockHeaderPktField(Packet):
    """
    Block headers are sent in a headers packet in response to a getheaders message.
    """

    fields_desc = [
        LEIntField("version",0),
        StrFixedLenField("prev_block", "", length=32),
        StrFixedLenField("merkle_root", "", length=32),
        LTimestampField("timestamp",int(time.time())),
        LEIntField("bits",0), # The calculated difficulty target being used for this block
        LELongField("nonce", 0 ),
        #VarIntField("txn_count",0),
    ]

    def extract_padding(self, s):
        return "",s

class OutPointPktField(Packet):
    fields_desc = [
        HashField("hash",None),
        LEIntField("index",0),
    ]

    def extract_padding(self, s):
        return "",s

class TxInPktField(Packet):
    """
    Used in BitcoinTx packet

    Description of script here : https://en.bitcoin.it/wiki/Script
    """

    fields_desc = [
        OutPointPktField,
        VarIntField("script_len",None, count_of="sign_script"),
        StrLenField("sign_script","", length_from=lambda pkt: pkt.script_len),
        XLEIntField("sequence", 0),
    ]

    def extract_padding(self, s):
        return "",s

class TxOutPktField(Packet):
    """
    Used in BitcoinTx packet
    """

    fields_desc = [
        LELongField("value", 0),
        VarIntField("pk_script_len",None, count_of="pk_script"),
        StrLenField("pk_script","", length_from=lambda pkt: pkt.pk_script_len),
    ]

    def extract_padding(self, s):
        return "",s

#########################
# Bitcoin Packets
########################


class BitcoinHdr(Packet):
    """
    Common header
    """
    name = "Bitcoin Header"

    fields_desc = [
         LEIntEnumField("magic", MAGIC_MAIN, MAGIC_VALUES),
         StrFixedLenField("cmd","", 12),
         LEIntField("len",None),
         ChecksumField("checksum", None)
    ]

    def build(self):
        # If len is None, set it before build
        if self.len is None:
            self.len = len(self.payload)

        return Packet.build(self)

    def guess_payload_class(self, payload):
        fld, val = self.getfield_and_val("cmd")
        cmd = val.replace("\x00","")
        if cmd in BitcoinMessage.registered_message:
            return BitcoinMessage.registered_message[cmd]
        else:
            return BitcoinMessage


class BitcoinHdrs(Packet):
    """
    Because a TCP payload can contain several Bicoin packet, we create a BitcoinHdrs which is
    a list of BitcoinHdr. If the list contain less than 2 elements, the dispatch_hook return a
    simple ButcoinHdr.
    """

    fields_desc = [
        PacketListField("messages", [], BitcoinHdr),
    ]

    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        """
        Here a hack to return a BitcoinHdr class if there is only one Bitcoin packet in the TCP payload.
        """
        if pkt is not None and ("_internal" not in kargs or (kargs["_internal"]==1)):
            p = BitcoinHdrs(pkt,_internal=2) # Parse with BitcoinHdrs a first time
            if len(p.messages) <= 1:
                return BitcoinHdr
        return cls


class BitcoinMessage(Packet):
    """
    Abstract Bitcoin payload
    """
    cmd = None
    registered_message = {}

    @classmethod
    def register_variant(cls):
        cmd = cls.cmd
        if cmd:
            cls.registered_message[cmd] = cls
            if len(cmd) < 12: # Add \x00 padding
                cmd = cmd + "\x00"*(12-len(cmd))
            bind_layers(BitcoinHdr, cls, {"cmd": cmd})

    def extract_padding(self, pay):
        return "",pay


class BitcoinVersion(BitcoinMessage):
    cmd = "version"

    fields_desc = [
        LEIntField("version",0),
        LELongEnumField("services",0, SERVICES_TYPES),
        LTimestampField("timestamp",int(time.time())),
        PacketField("addr_recv", AddrWithoutTimePktField(), AddrWithoutTimePktField),

        # Fields below require version >= 106
        ConditionalField(PacketField("addr_from", AddrWithoutTimePktField(), AddrWithoutTimePktField), lambda pkt : pkt.version >= 106),
        ConditionalField(LELongField("nonce", 0 ), lambda pkt : pkt.version >= 106),
        ConditionalField(PacketField("user_agent", VarStrPktField(), VarStrPktField), lambda pkt : pkt.version >= 106),
        ConditionalField(LEIntField("start_height",0), lambda pkt : pkt.version >= 106),

        # Fields below require version >= 70001
        ConditionalField(ByteField("relay", 0), lambda pkt : pkt.version >= 70001)
    ]


class BitcoinVerack(BitcoinMessage):
    """
    The verack message is sent in reply to version. This message consists of only a message header with the cmd string "verack".
    """
    cmd = "verack"


class BitcoinAddr(BitcoinMessage):
    """
    Provide information on known nodes of the network. Non-advertised nodes should be forgotten after typically 3 hours
    """
    cmd = "addr"

    fields_desc = [
        VarIntField("count",None, count_of="addr_list"),
        PacketListField("addr_list", [], AddrPktField, count_from=lambda pkt: pkt.count),
    ]


class BitcoinInv(BitcoinMessage):
    """
    Allows a node to advertise its knowledge of one or more objects. It can be received unsolicited, or in reply to getblocks.
    """
    cmd = "inv"

    fields_desc = [
        VarIntField("count",None, count_of="inventory"),
        PacketListField("inventory", [], InventoryPktField, count_from=lambda pkt: pkt.count),
    ]


class BitcoinGetdata(BitcoinMessage):
    """
    getdata is used in response to inv
    """
    cmd = "getdata"

    fields_desc = [
        VarIntField("count",None, count_of="inventory"),
        PacketListField("inventory", [], InventoryPktField, count_from=lambda pkt: pkt.count),
    ]


class BitcoinNotfound(BitcoinMessage):
    """
    notfound is a response to a getdata, sent if any requested data items could not be relayed,
    for example, because the requested transaction was not in the memory pool or relay se
    """
    cmd = "notfound"

    fields_desc = [
        VarIntField("count",None, count_of="inventory"),
        PacketListField("inventory", [], InventoryPktField, count_from=lambda pkt: pkt.count),
    ]


class BitcoinGetblocks(BitcoinMessage):
   """
   Return an inv packet containing the list of blocks starting right after the last
   known hash in the block locator object, up to hash_stop or 500 blocks, whichever comes first.
   """
   cmd = "getblocks"

   fields_desc = [
        LEIntField("version",0),
        VarIntField("hash_count",None, count_of="hashes"),
        FieldListField("hashes", [], HashField("",0), count_from=lambda pkt : pkt.hash_count),
        HashField("hash_stop", None),
    ]


class BitcoinGetheaders(BitcoinMessage):
   """
    Return a headers packet containing the headers of blocks starting right after the last
    known hash in the block locator object, up to hash_stop or 2000 blocks, whichever comes first
   """
   cmd = "getheaders"

   fields_desc = [
        LEIntField("version",0),
        VarIntField("hash_count",None, count_of="hashes"),
        FieldListField("hashes", [], HashField("",None), count_from=lambda pkt : pkt.hash_count),
        HashField("hash_stop", None),
    ]


class BitcoinTx(BitcoinMessage):
    """
    tx describes a bitcoin transaction, in reply to getdata
    """
    cmd = "tx"

    fields_desc = [
        LEIntField("version",0),
        VarIntField("tx_in_count",None, count_of="tx_in"),
        PacketListField("tx_in", [], TxInPktField, count_from=lambda pkt : pkt.tx_in_count), # TODO
        VarIntField("tx_out_count",None, count_of="tx_out"),
        PacketListField("tx_out", [], TxOutPktField, count_from=lambda pkt : pkt.tx_out_count), # TODO
        LockTimeField("lock_time", None),
    ]


class BitcoinBlock(BitcoinMessage):
    """
    The block message is sent in response to a getdata message which requests transaction information from a block hash.
    """
    cmd = "block"

    fields_desc = [
        LEIntField("version",0),
        HashField("prev_block",0),
        HashField("merkel_block",0),
        TimestampField("timestamp", int(time.time())),
        LEIntField("bits",0), # The calculated difficulty target being used for this block
        XLEIntField("nonce",0),
        VarIntField("txn_count",None, count_of="txns"),
        PacketListField("txns", [], BitcoinTx),
    ]


class BitcoinHeader(BitcoinMessage):
    """
    The headers packet returns block headers in response to a getheaders packet.
    """
    cmd = "header"

    fields_desc = [
        VarIntField("count",None, count_of="headers"),
        PacketListField("headers", [], BlockHeaderPktField)
    ]


class BitcoinGetaddr(BitcoinMessage):
    """
    The getaddr message sends a request to a node asking for information about known active peers to
    help with finding potential nodes in the network.
    """
    cmd = "getaddr"


class BitcoinMempool(BitcoinMessage):
    """
    The mempool message sends a request to a node asking for information about transactions it has verified but which have not yet confirmed.
    """
    cmd = "mempool"


class BitcoinCheckorder(BitcoinMessage):
    """
    This message was used for IP Transactions. As IP transactions have been deprecated, it is no longer used.
    """
    cmd = "checkorder"


class BitcoinSubmitorder(BitcoinMessage):
    """
    This message was used for IP Transactions. As IP transactions have been deprecated, it is no longer used.
    """
    cmd = "submitorder"


class BitcoinReply(BitcoinMessage):
    """
    This message was used for IP Transactions. As IP transactions have been deprecated, it is no longer used.
    """
    cmd = "reply"


class BitcoinPing(BitcoinMessage):
    """
    The ping message is sent primarily to confirm that the TCP/IP connection is still valid.
    """
    cmd = "ping"

    fields_desc = [
        XLELongField("nonce",0),
    ]


class BitcoinPong(BitcoinMessage):
    """
    The pong message is sent in response to a ping message.
    In modern protocol versions, a pong response is generated using a nonce included in the ping.
    """
    cmd = "pong"

    fields_desc = [
        XLELongField("nonce",0),
    ]


class BitcoinReject(BitcoinMessage):

    cmd = "reject"

    fields_desc = [
                   PacketField("message", VarStrPktField(), VarStrPktField),
                   ByteEnumField("ccode",0, REJECT_CCODES),
                   PacketField("reason", VarStrPktField(), VarStrPktField), # Text version of the reason
                   StrField("data",""),
    ]


# Flowing Bloom filter messages are describe here : https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki

class BitcoinFilterload(BitcoinMessage):
    cmd = "filterload"

    fields_desc = [
        StrLenField("filter", "", length_from=lambda pkt: pkt.underlayer.len - 9), # The maximum size is 36,000 bytes
        XLEIntField("n_hash_functs", 0), # The maximum value allowed in this field is 50
        XLEIntField("n_tweak", 0),
        XByteField("n_flags", 0),
    ]


class BitcoinFilteradd(BitcoinMessage):
    cmd = "filteradd"

    fields_desc = [
        StrLenField("filter", "")
    ]


class BitcoinFilterclear(BitcoinMessage):
    cmd = "filterclear"

    fields_desc = [
        LEIntField("version",0),
        HashField("prev_block",0),
        HashField("merkel_block",0),
        TimestampField("timestamp", int(time.time())),
        LEIntField("bits",0), # The calculated difficulty target being used for this block
        XLEIntField("nonce",0),
        LEIntField("nb_transactions",0),
        VarIntField("len_hashes",None, count_of="hashes"),
        FieldListField("hashes", [], HashField("hash", None), count_from=lambda pkt : pkt.len_hashes),
        StrLenField("flags", ""),
    ]


class BitcoinAlertPayload(Packet):

    fields_desc = [
        LEIntField("version",0),
        LTimestampField("relay_until", int(time.time())),
        LTimestampField("expiration", int(time.time())),
        XIntField("alert_id",0),
        XIntField("cancel",0),
        VarIntField("len_set_cancel",None, count_of="set_cancel"),
        FieldListField("set_cancel", [], LEIntField("",0), count_from=lambda pkt: pkt.len_set_cancel),
        IntField("min_ver",0),
        IntField("max_ver",0),
        VarIntField("len_set_sub_ver",None, count_of="set_sub_ver"),
        FieldListField("set_sub_ver", [], VarStrPktField("",0), count_from=lambda pkt: pkt.len_set_sub_ver),
        LEIntField("priority",0),
        PacketField("comment", VarStrPktField(), VarStrPktField),
        PacketField("status_bar", VarStrPktField(), VarStrPktField),
        PacketField("reserved", VarStrPktField(), VarStrPktField),
    ]

class BitcoinAlert(BitcoinMessage):
    """
    Alert messages are signed by developpers of Satoshi's client.
    Signature is an ECDSA of the BitcoinAlertPayload
    """
    cmd = "alert"

    fields_desc = [
        BitcoinAlertPayload,
        StrField("signature", "")
    ]


for port in MAGIC_PORT_BINDING.values():
    bind_layers(TCP, BitcoinHdrs, dport=port)
    bind_layers(TCP, BitcoinHdrs, sport=port)

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="Scapy Bitcoin extension")
