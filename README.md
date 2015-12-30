# Bitcoin packets for Scapy
Implementation of Bitcoin protocol messages in Scapy.

All Bitcoin messages are built as follwing :
```python
BitcoinHdr() / BitcoinMessage()
```
A binding is done between the *BitcoinHdr.cmd* and the good *BitcoinMessage* (which is an abstract class)

*BitcoinMessage* available are :

command     | class
------------|----------------------
inv         | *BitcoinInv*
header      | *BitcoinHeader*
pong        | *BitcoinPong*
checkorder  | *BitcoinCheckorder*
filterload  | *BitcoinFilterload*
addr        | *BitcoinAddr*
tx          | *BitcoinTx*
filteradd   | *BitcoinFilteradd*
ping        | *BitcoinPing*
getheaders  | *BitcoinGetheaders*
version     | *BitcoinVersion*
reject      | *BitcoinReject*
reply       | *BitcoinReply*
submitorder | *BitcoinSubmitorder*
alert       | *BitcoinAlert*
getaddr     | *BitcoinGetaddr*
mempool     | *BitcoinMempool*
getdata     | *BitcoinGetdata*
getblocks   | *BitcoinGetblocks*
notfound    | *BitcoinNotfound*
verack      | *BitcoinVerack*
filterclear | *BitcoinFilterclear*
block       | *BitcoinBlock*

**Note** : checkorder, submitorder, reply are deprecated in the current protocol version.

## Usage example

### Crafting example
```python
python bitcoin.py
>>> pkt = BitcoinHdr() / BitcoinVersion()
```
### Sniffing example
```python
python bitcoin.py
>>> pkts = rdpcap("bitcoin.pcap")
>>> pkts[2][3].show()
###[ BitcoinHdrs ]###
  \messages\
   |###[ Bitcoin Header ]###
   |  magic= main
   |  cmd= 'verack'
   |  len= 0
   |  checksum= 0x5df6e0e2
   |###[ BitcoinVerack ]###
   |###[ Bitcoin Header ]###
   |  magic= main
   |  cmd= 'ping'
   |  len= 8
   |  checksum= 0xcb205941
   |###[ BitcoinPing ]###
   |     nonce= 0x17a3599d7d079c22
   |###[ Bitcoin Header ]###
   |  magic= main
   |  cmd= 'getheaders'
   |  len= 997
   |  checksum= 0xded3249b
   |###[ BitcoinGetheaders ]###
   |     version= 60002
   |     hash_count= 30
   |     hashes= ['\t\xbd\xbdu]X \x0f\xc1\x04\x01\xe6&&C=\xd5\x98`\xcc\xaab\x9a\x02\x00\x00\x00\x00\x00\x00\x00\x00', 'sS\xe41L\xdb\x95\xb6\xf1e^\xa5\xbe\x9e\xce:Z\x14>\xc5d\\\xde\n\x00\x00\x00\x00\x00\x00\x00\x00', "\xfb\x10'~\x8c:z\x1f\xcaa\x01\x1f&>\x06_ap\x18\xa9\x1a\xf6k\x03\x00\x00\x00\x00\x00\x00\x00\x00", '}%Z3\xb5\x80)w\xf8G\x01\xcdUH\xc2\xdd\xb0K\xd51\xcb\xc1\xfe\x02\x00\x00\x00\x00\x00\x00\x00\x00', '\x9e\xfc\x00F?\xe7\xf1\xb1\xb2\xad^K\x02\xe0RZ\x1a\xab\x8c\r=\x8c\xed\x04\x00\x00\x00\x00\x00\x00\x00\x00', '6&U\xd1\xd8/\x10\x00V:\xfd\xb7\x13\x06\xa0\xd0T\xbe1\xf27|o\x06\x00\x00\x00\x00\x00\x00\x00\x00', 'Z\x17\x8e\xf0IA\x1d\xbbED\xfaD\xbb0?\xb0\x9a\x0e\xe1\xc34$u\x03\x00\x00\x00\x00\x00\x00\x00\x00', '\xb4\xc3Ys\xd9\xbe\x05\x06\x13u\x13\x1d\x172\x9d\xf4\x12I\x1f\x91\xb2\xaf\x13\x0b\x00\x00\x00\x00\x00\x00\x00\x00', '\x17\xe6H\xaf\xbe:\xbe\xb5)\x15}\xb8\xea\x1a\xc6\xcf\xc9\xc7\xf6\xc6Y\xeb\x07\x04\x00\x00\x00\x00\x00\x00\x00\x00', 'yO\x9dH\x15w\xf0\x13`\x80\xa2x\xe1\x9a\xed\x161\xd3\xdd;)k\x1e\x01\x00\x00\x00\x00\x00\x00\x00\x00', 'NL\xf8(.\xe2\xa9\x8f\xce\xbb1\x9d\xebn\xe9\xa9\x87j\xd5\xdeN9j\t\x00\x00\x00\x00\x00\x00\x00\x00', 'i\xd9\x1a5>K\x95\xc2\xb7\xce\xd0.\xaf\x19M5\xcc\x96V\xcd*i\x18\t\x00\x00\x00\x00\x00\x00\x00\x00', 'o\xbb\x90\xd3\x18\xb9W\x1dk\x8b\xc5 4\x93\x1fe[e\x16\n\xbb\xff\\\x00\x00\x00\x00\x00\x00\x00\x00\x00', '\x98\x0cZa\xf8\xc5$B\xa8\xc4fg\x19\xec\xa4\xa0`\xf3l!\xa5\x8c\xb6\x0b\x00\x00\x00\x00\x00\x00\x00\x00', '\xf1d\xd9\x02\x96\xaec\xee,2\x0c\xe0S\xda\x83s\xed2{\x9f\xf8L@\t\x00\x00\x00\x00\x00\x00\x00\x00', '=\x89\xe6p\xdb\x0bDlox\xdc\xe0\xf4:\x15\xc5\xbc\xc6\xc1\x10\xee\x00\x99\x08\x00\x00\x00\x00\x00\x00\x00\x00', '\xb8\xa6\xf3\x80\xad\x9b\xe3~\t:\xbe*\x84\x01,f\xb8\xf9\xa4\xbde\xc9\xbe\x0b\x00\x00\x00\x00\x00\x00\x00\x00', 'j1\xfb\x08\xbf\x88\x91\xb1\x1a\xa0H\xa2J\x01v\xb3,\xf7\xb0\xf9\xd2\xc8\xb3\x06\x00\x00\x00\x00\x00\x00\x00\x00', '\x19\x01\x83T]\x05\xb3\x0b\xa7\xd3\x07\x98\xf0\x1c\xfe\xdb?\x1a,\xbf$c\xb5\x08\x00\x00\x00\x00\x00\x00\x00\x00', 'o\x14\xfc\x8e-\xb29\x9e\x908\x96\xed\xc0\xc2\x8cJ=\xe0b\xae%"\r\x03\x00\x00\x00\x00\x00\x00\x00\x00', "'\xd9U\xe5\xc9\x1c\xb1\xc8\x8aj\xd3y\x07\x10\xe7}y\x02\xf5\x94uZ\xc8\t\x00\x00\x00\x00\x00\x00\x00\x00", '5\xff\xbcT\x99\xddF\xe1k\xe5\xbe\xaf\xdd\xc8\xd7\x1e\x97[\x17\x10n\xda\xae\x08\x00\x00\x00\x00\x00\x00\x00\x00', '7\x9d\xa6L\xf8\xdd\x90\x84I\x1f\xfb\xdc\xe4\xe1\xa1\xeeO\xe5\xfc+\x9ei9\x0e\x00\x00\x00\x00\x00\x00\x00\x00', 'w\xa8\x9a\x84\xd2\x05\xf50o\xccm\xf7}\x14\x07k{\xab\xfesf\x98h\n\x00\x00\x00\x00\x00\x00\x00\x00', '\xcf\x1c\xf9\xc2\x9e]\xd29cyY\xdc\xeb\xa1\x86\x98g\xea\x97\x17@>\x19\x02\x00\x00\x00\x00\x00\x00\x00\x00', 'a\xcflB\x91\xfa\xe5\xae3\xa3\x10\xa2a\xe4\xb9|\xfd\x13\xbe\xda\x11n>\x16\x00\x00\x00\x00\x00\x00\x00\x00', '\xf0]\xc9\x8c3\x89\x11\x8d\xefV\xce\xae[\x81\xdd\xb7\xb7\xa28\x0f\xd5\x19\xdc\x01\x00\x00\x00\x00\x00\x00\x00\x00', '\x97\xcdV\x04l\xf1\xef\x87\xa5r\xe29\\u=\xb4\xd2\x16\x7f\x1f\x80\x94\x8b\xf4#\x00\x00\x00\x00\x00\x00\x00', '\x99\xb3\xa9S\xa3o\x05z@\x1c\xec/}\xa2\x11\xeb"\x99\x9a\xd5\xcc\x8eV\x03\xb0\x18\x00\x00\x00\x00\x00\x00', 'o\xe2\x8c\n\xb6\xf1\xb3r\xc1\xa6\xa2F\xaec\xf7O\x93\x1e\x83e\xe1Z\x08\x9ch\xd6\x19\x00\x00\x00\x00\x00']
   |     hash_stop= 0000000000000000000000000000000000000000000000000000000000000000
>>> pkts[2][3].messages[0]
<BitcoinHdr  magic=main cmd='verack' len=0 checksum=0x5df6e0e2 |<BitcoinVerack  |>>
>>> pkts[2][3].messages[1]
<BitcoinHdr  magic=main cmd='ping' len=8 checksum=0xcb205941 |<BitcoinPing  nonce=0x17a3599d7d079c22 |>>



>>> pkts[3][3].show()
###[ Bitcoin Header ]###
  magic= main
  cmd= 'inv'
  len= 37
  checksum= 0x3ddf21bd
###[ BitcoinInv ]###
     count= 1
     \inventroy\
      |###[ InventoryPktField ]###
      |  type= MSG_TX
      |  hash= b486a473df5025845cafbd5a77d781def2f766920ec4a9bd9bb24d4012265345

```
You can notice that in the first packet shown (see pkts[2][3]), the TCP payload is a *BitcoinHdrs*.
This packet class is a packet list of *BitcoinHdr* because several Bitcoin packets can be concatenated in a same TCP payload.

When the *BitcoinHdrs.messages* list contains only one item, TCP payload is directly a *BitcoinHdr* (see pkts[3][3]).


## Documentation

https://en.bitcoin.it/wiki/Protocol_documentation

https://bitcoin.org/en/developer-reference#p2p-network
