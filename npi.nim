
import os,times, posix,nativesockets
import  threadpool,strutils


# the lib net filter interface
proc nfq_open() : pointer {.importc , header: "<libnetfilter_queue/libnetfilter_queue.h>".}

proc nfq_bind_pf(x:pointer,y:cint):cint {.importc , header: "<libnetfilter_queue/libnetfilter_queue.h>".}

proc nfq_unbind_pf(x:pointer,y:cint):cint {.importc , header: "<libnetfilter_queue/libnetfilter_queue.h>".}

proc nfq_set_mode(x:pointer,y:uint8,z:uint32):cint {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}

proc nfq_create_queue(x:pointer,y:cint,z:pointer,data:pointer):pointer {.importc , header: "<libnetfilter_queue/libnetfilter_queue.h>".}
 
proc nfq_fd(x:pointer):int  {.importc , header: "<libnetfilter_queue/libnetfilter_queue.h>".}

proc nfq_handle_packet(x:pointer,y:pointer,d:cint):cint  {.importc , header: "<libnetfilter_queue/libnetfilter_queue.h>".}
 
proc nfq_get_msg_packet_hdr(x:pointer):pointer {.importc , header: "<libnetfilter_queue/libnetfilter_queue.h>".}

proc nfq_get_packet_hw(x:pointer):pointer {.importc , header: "<libnetfilter_queue/libnetfilter_queue.h>".}

proc nfq_set_verdict (x:pointer,id:uint32,verdict:uint32,lend:uint32,buf:cstring):cint  {.importc , header: "<libnetfilter_queue/libnetfilter_queue.h>".}

proc nfq_get_payload (x:pointer,y:pointer):cint {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}

# lib checksum interface, tcp check sum takes a pointer to  pseudo header and pointer to the actual header to process both 
proc customchecksum (x:pointer,y:cint):cint {.importc, header: "<./customchecksum.h>".}

proc tcpchecksum (x:pointer,z:pointer,y:cint):cint {.importc, header: "<./customchecksum.h>".}


# object to hold extracted the meta-data information from ip/tcp headers
type
  PacketToken = object
    state:uint8
    tcpFlags:uint8
    srcPort:uint16
    dstPort:uint16
    ipHeadLen:uint16
    totalLen:uint16
    srcIp:uint32
    dstIp:uint32
    seqNum:uint32
    ackNum:uint32
    tcpoffbytes:uint32
    showUp:float                  # when the packet show up
    resend:int                    # marker for resend 
    allocatedSharedUint64:uint64  # address to the actual payload


type
  packethdr = object
    packetid:uint32
    hwpacket:uint16
    hook:uint8


type
  nfqlmsgpackethw = object
    hwaddrlen:uint16
    pad1:uint16
    srcMac:array[8,uint8]


type sockaddr_ll = object
    sll_family:   uint16 # Always AF_PACKET
    sll_protocol: uint16 # Physical-layer protocol
    sll_ifindex:  int32  # Interface number
    sll_hatype:   uint16 # ARP hardware type
    ll_pkttype:   uint8  # Packet type
    sll_halen:    uint8  # Length of address
    sll_addr:     array[8, uint8] # Physical-layer address


const
  tmpCharBufferSize = 65000



let arguments = commandLineParams()
if arguments.len != 6:
  echo "usage <queuenum> <ifindex> <out mac> <gw mac> <ipaddr> <len>"
  quit(0)

var
  thisPCMac:        array[0..5,uint8]
  gatewayMac:       array[0..5,uint8]
  ipMacMacp :       array[0..1800,tuple[srcIp:uint32,srcMac:array[0..7,uint8],expire:float]]
  filterNum        = 1
  ifindex:int32    = 1
  subnetRange      = 255
  ourMac           = split(arguments[2],":")
  gwMac            = split(arguments[3],":") 
  localNet:uint32  = 0

if ourMac.len != 6 or gwMac.len != 6:
  echo "invalid mac address"
  quit(0)

for i in 0..5:
  try:
    let 
      r = parseHexInt(ourMac[i])
      n = parseHexInt(gwMac[i])
    thisPCMac[i] = cast[uint8](r)
    gatewayMac[i] = cast[uint8](n)
  except:
    echo "not vaild out mac"
    quit(0)

try:
  filterNum   = parseInt(arguments[0])
  ifindex     = cast[int32](parseInt(arguments[1]))
  subnetRange = parseInt(arguments[5])
  localNet    = inet_addr(cstring(arguments[4]))

except:
  echo "not vaild interface index number"

# packet sent to thread based on the value of  (mod srcIp 2) <<  (mod srcPort 2)   
# that will ensure packets from the same src ip and port handled by the same thread
var
  myThreads: array[0..3,Thread[int]] # 4 workers
  myMainThread: Thread[int] # main thread
  mainChannel: Channel[PacketToken]
  workerschannels: array[0..3, Channel[PacketToken]]


mainChannel.open()
for i in 0..3:
  workerschannels[i].open()

let
  localNetEnds = localNet + cast[uint32](subnetRange)

# search the ip mac maping (ipMacMap) to find a mac address for an ip
# using hash table for look up sounds a better option however it is not gc safe
proc getMacForIp(ipAddr:uint32): int =
  result = -1
  for i in 0..1800:
    if ipMacMacp[i].srcIp == ipAddr:
      result = i
      ipMacMacp[i].expire = epochTime()
      break

proc insertMacForIp(ipAddr:uint32, mac:array[0..7,uint8]):int =
  result = getMacForIp(ipAddr)
  if result == -1:
    for i in 0..1800:
      if ipMacMacp[i].srcIp == 0 :
        ipMacMacp[i].srcIp = ipAddr
        ipMacMacp[i].srcMac = mac
        ipMacMacp[i].expire = epochTime() + 5*60*1000 # 5 minutes before expire
        result = i
        break
    # scan and remove the expired if no place to add a new mac address 
    if result < 0 :
      let now = epochTime()
      for i in 0..1800:
        if  ipMacMacp[i].expire < now:
          ipMacMacp[i].srcIp = ipAddr
          ipMacMacp[i].expire = epochTime()
          ipMacMacp[i].srcMac = mac
          result = i
          break

# for a given packet token pack the payload and send it out
proc sendFromToken(token:var PacketToken)  =
  let 
    src = token.allocatedSharedUint64
  var
    totalLen = cast [ptr uint16](src+16'u64)[] # 14 for ethernet layer and 2 to get the totallen
    tlen = nativesockets.ntohs(totalLen) + 14
    saddIn : sockaddr_ll
  # ethernet payload is ip and our mas address is as source
  cast [ptr uint16](src+12)[] = 0x0008'u16
  copyMem(cast [ptr uint8](src + 6'u64),addr(thisPCMac[0]),6)

  let sd =  newNativeSocket(17,3, 0)
  if sd != InvalidSocket:
    saddIn.sll_family     = 17'u16
    saddIn.sll_protocol   =  6'u16
    saddIn.sll_ifindex = ifindex
    saddIn.sll_hatype = 0
    saddIn.ll_pkttype = 0
    saddIn.sll_hatype = 6
    let bindr =  sd.bindAddr(cast[ptr SockAddr](addr(saddIn)),SockLen(20))
    if bindr == 0:
      let sendr =  sendTo(sd, cast [pointer](src),cast[cint](tlen),0,cast[ptr SockAddr](addr(saddIn)),SockLen(20))
      echo " bind " , $bindr , " send " , $sendr
    close(sd)
  else:
    echo "could not create socket!"

# steer traffic direction by filling the dst mac address 
# local traffic uses the previously associated mac for ip
# or in case of external traffic the gateway mac address is used
proc steerTrafficDir(token: var PacketToken) =
  let 
    src    = token.allocatedSharedUint64
    ipDst  = src + 14
    dstIp = cast [ptr uint32](ipDst + 16)[]

  if dstIp >= localNet and dstIp <= localNetEnds:
    let i = getMacForIp(dstIp)
    if i >= 0 :
      copyMem(cast [ptr uint8](src) ,addr(ipMacMacp[i].srcMac[0]),6)
    #else:
    #  echo "no mac associated with " & nativesockets.inet_ntoa(cast[InAddr](dstIp))   
  else:
    copyMem(cast [ptr uint8](src),addr(gatewayMac[0]), 6)

# preform the checksum on slot by creating pseudo header and calc the checksums 
proc checksumToken(token: var PacketToken) =
  let
    src = token.allocatedSharedUint64
    ipDst = src + 14
    ttlen = nativesockets.ntohs(cast [ptr uint16]( cast [uint64](ipDst) + 2)[])
    iphlen   = (cast [ptr uint8](ipDst)[] and 0x0f) * 4 
    tcpSrc  = ipDst + iphlen

  var
    tmpPseudo  = alloc(32)
    proto  = nativesockets.htons(6'u16)
    tcplenNum = ttlen - iphlen
    tcpLen = nativesockets.htons(tcplenNum)
    faskTcpCheckSum:uint16 =  0'u16
    ipcheck:uint16         = 0'u16 

  # create the pseudo header fill the src, dest and tcp length
  cast[ptr uint32](tmpPseudo)[]  =  cast [ptr uint32](ipDst + 12)[]
  copyMem(cast[pointer](cast[uint64](tmpPseudo) + 4), cast [ptr uint8](ipDst + 16),4)
  copyMem(cast[pointer](cast[uint64](tmpPseudo) + 8), addr(proto),2)
  copyMem(cast[pointer](cast[uint64](tmpPseudo) + 10), addr(tcpLen),2)
  
  # clear the  tcp checksum, calculate the checksum and insert the calculated one
  copyMem(cast[pointer](tcpSrc + 16), addr(faskTcpCheckSum),2)
  faskTcpCheckSum = cast[uint16](tcpchecksum(tmpPseudo,cast[pointer](tcpSrc),cast[cint](tcplenNum)))
  copyMem(cast [pointer](tcpSrc + 16),addr(faskTcpCheckSum),2)

  # clear the pervious ip checksum, calculate the checksum and insert the new one
  copyMem(cast [pointer](ipDst + 10),addr(ipcheck),2)
  ipcheck = cast[uint16](customchecksum(cast [ptr uint8](ipDst),cast[cint](20)))
  copyMem(cast [pointer](ipDst + 10),addr(ipcheck),2)
  
  # discard the pseduo header file
  dealloc(tmpPseudo)

# create an ack 
proc createAckSeq(token:var PacketToken) =
  let src = cast[uint64](token.allocatedSharedUint64)
  var
    seqNum = token.seqNum
    ackNum = token.ackNum
    ack:uint32  = 0
    calcAck = 0'u32
    ipDst = src + 14
    tcpDst = ipDst + 20   
    
  calcAck = nativesockets.ntohl(seqNum) +  token.totalLen  - token.ipHeadLen - token.tcpoffbytes
  calcAck = nativesockets.htonl(calcAck)
  
  cast [ptr uint16](ipDst)[]         = 0x45 
  cast [ptr uint16](ipDst + 1)[]     = 0x00 
  cast [ptr uint16](ipDst + 2)[]     = nativesockets.htons(40'u16) #totallen 
  cast [ptr uint16](ipDst + 4)[]     = nativesockets.htons(40'u16) #ident 
  cast [ptr uint16](ipDst + 5)[]     = 0'u16
  cast [ptr uint8](ipDst  + 8)[]     = 0x04
  cast [ptr uint8](ipDst  + 9)[]     = 0x06
  cast [ptr uint16](ipDst + 10)[]    = 0'u16

  cast [ptr uint32](ipDst + 12)[]    = token.dstIp
  cast [ptr uint32](ipDst + 16)[]    = token.srcIp
  cast [ptr uint16](tcpDst)[]        = token.dstPort
  cast [ptr uint16](tcpDst+2)[]      = token.srcPort

  # fill ack number in the dst tcp header
  cast [ptr uint32](tcpDst + 8)[]    =  calcAck
  ack = nativesockets.ntohl(ackNum)
  cast [ptr uint32](tcpDst + 4)[]   =   ack

  # overwrite the header information
  cast [ptr uint8](tcpDst + 12)[]  = 0x50                         
  cast [ptr uint8](tcpDst + 13)[]  = 0x10                        
  cast[ptr uint16](tcpDst + 14)[]  = nativesockets.htons(100'u16)

# function to create a fake ack reply something that can be used to accelerate the tcp traffic
proc createAckReply(token: var PacketToken) =
  let  src = token.allocatedSharedUint64
  var holder = alloc(14+20+20)
  token.allocatedSharedUint64  = cast[uint64](holder)
  createAckSeq(token)
  checksumToken(token)
  steerTrafficDir(token)
  sendFromToken(token)
  dealloc(holder)
  token.allocatedSharedUint64  = src


proc fillToken(token:var PacketToken) =
  let
    src    = token.allocatedSharedUint64
    ipDst  = src + 14
    tcpDst = ipDst + token.ipHeadLen

  #token.srcIp     = cast [ptr uint32](ipDst + 12)[]          # already have it
  token.dstIp     = cast [ptr uint32](ipDst + 16)[]   
  #token.ipHeadLen = (cast [ptr uint8](ipDst)[] and 0x0f) * 4 # already have it

  token.srcPort   = cast [ptr uint16](tcpDst)[]
  token.dstPort   = cast [ptr uint16](tcpDst + 2)[]

  token.seqNum    = cast [ptr uint32](tcpDst + 4)[]
  token.ackNum    = cast [ptr uint32](tcpDst + 8)[]
  
  token.showUp = epochTime()
  token.resend = 5
  token.state  = 1

  let
    tcpoffset: ptr uint8 = cast [ptr uint8](tcpDst + 12)      # tcp offset field
  token.tcpoffbytes =  (( tcpoffset[] and 0xf0 ) shr 4) * 4   # tcp offset field in bytes

 

proc theWorkerThread(a:int) {.thread.} =
  while true:
    let 
      myToken = workersChannels[a].tryRecv()

    if myToken.dataAvailable:
      var token = myToken.msg

      # just an example of creating fake ack 
      if token.tcpFlags == 0x00 or token.tcpFlags == 0x08  or token.tcpFlags == 0x18:
        echo " it is psh : " &  $toHex(token.tcpFlags)
        createAckReply(token)
        #tracker.add(token)
        deallocShared(cast[pointer](token.allocatedSharedUint64))
    # TODO: resend 
    sleep(20) # assume min sleep 


proc tokenManager(a:int) {.thread.} =
  while true:
    let 
      n = mainChannel.recv()
      oddSrcIp   = n.srcIp mod 2
      oddSrcPort = n.srcPort mod 2
      #oddDstIp   = n.dstIp mod 2       # in case high traffic load we can use destination ip and port 
      #oddDstPort   = n.dstPort mod 2   # to account for more threads up to 16
      slot = cast[int]((oddSrcIp shl 1) or (oddSrcPort))
    workersChannels[slot].send(n)


# netfliter callback function
proc ccalb(a:pointer,b:pointer,c:pointer,d:pointer):cint=
  let
    message = nfq_get_msg_packet_hdr(c)
    ptrpackethdr = cast[ref packethdr](message)
    packetId = nativesockets.ntohl(ptrpackethdr.packetid)
    ptrhardwareInfo = nfq_get_packet_hw(c)
    hardwareInfo = cast [ref nfqlmsgpackethw](ptrhardwareInfo)

  var
    allocated : ptr[uint8]

  let
    checkptrpayload = nfq_get_payload(c,addr(allocated))
    ttlen = nativesockets.ntohs(cast [ptr uint16]( cast [uint64](allocated) + 2)[])
    headlen:uint8 = (cast [ptr uint8](cast[uint64](allocated))[] and 0x0f) * 4
    iphlen   = (cast [ptr uint8](allocated)[] and 0x0f) * 4 
    tcpFlags = (cast [ptr uint8](cast[uint64](allocated) + headlen + 13))[]
    srcIp = cast [ptr uint32](cast[uint64](allocated) + 12)[]
  
  # syn and syn-ack just passing we only collect the mac address information
  if tcpFlags == 0x02 or tcpFlags == 0x12 :
    let sl = insertMacForIp(srcIp,hardwareInfo.srcMac)
    if sl < 0:
      echo "failed to insert ip, mac addr"
    discard nfq_set_verdict(a,packetId,1,0,nil)
    return

  var
    allocatedSharedSrc   = allocShared0(ttlen+14)
    tokenInfo : PacketToken

  let
    allocatedSharedUint64 = cast[uint64](allocatedSharedSrc)

  # make a copy of the packet 
  copyMem(cast [ptr uint8](allocatedSharedUint64+14),allocated,ttlen)
  tokenInfo.srcIp = srcIp
  tokenInfo.tcpFlags = tcpFlags
  tokenInfo.allocatedSharedUint64 = allocatedSharedUint64
  tokenInfo.totalLen = ttlen
  tokenInfo.ipHeadLen = iphlen

  fillToken(tokenInfo)
  discard nfq_set_verdict(a,packetId,1,0,nil)
  mainChannel.send(tokenInfo)



proc mainLoop() =
  var
    j :pointer = nil
 
  let
    nfqOpen = nfq_open()
    unbindedNfq = nfq_unbind_pf(nfqOpen,2)
    bindedNfq = nfq_bind_pf(nfqOpen,2)
    nfqueue = nfq_create_queue(nfqOpen,cast[cint](filterNum),ccalb, j)
    nfqueueMode = nfq_set_mode(nfqueue,2,65535)
    nfqueueFD = nfq_fd(nfqOpen)

  echo "main loop to serve netfliter callback ready"
  while true:
    var  tmpCharBuffer : array[ tmpCharBufferSize,uint8]
    let x = read(cast[cint](nfqueueFD),addr(tmpCharBuffer[0]),tmpCharBufferSize)
    if x >= 0:
      let y = nfq_handle_packet(nfqOpen,addr(tmpCharBuffer[0]) ,cast[cint](x))
      if y != 0 :
        echo "failed to handle packet"



createThread(myMainThread, tokenManager, (17))
for i in 0..3:
  createThread(mythreads[i], theWorkerThread, (i))
mainLoop()
