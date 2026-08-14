package icmp

import "net"

const (
	ICMPTypeEchoReply              uint8 = 0
	ICMPTypeDestinationUnreachable uint8 = 3
	ICMPTypeRedirect               uint8 = 5
	ICMPTypeEcho                   uint8 = 8
	ICMPTypeRouterAdvertisement    uint8 = 9
	ICMPTypeRouterSolicitation     uint8 = 10
	ICMPTypeTimeExceeded           uint8 = 11
	ICMPTypeParameterProblem       uint8 = 12
	ICMPTypeTimestamp              uint8 = 13
	ICMPTypeTimestampReply         uint8 = 14
	ICMPTypePhoturis               uint8 = 40
	ICMPTypeExtendedEchoRequest    uint8 = 42
	ICMPTypeExtendedEchoReply      uint8 = 43
)

var ICMPTypes = map[uint8]string{
	0:  "Echo Reply",
	3:  "Destination Unreachable",
	5:  "Redirect",
	8:  "Echo Request",
	9:  "Router Advertisement",
	10: "Router Solicitation",
	11: "Time Exceeded",
	12: "Parameter Problem",
	13: "Timestamp",
	14: "Timestamp Reply",
	40: "Photuris",
	42: "Extended Echo Request",
	43: "Extended Echo Reply",
}

const (
	MTULen           = 1500
	MinIPv4HeaderLen = 20
	MinICMPHeaderLen = 4
	MaxICMPHeaderLen = 8
	MaxSignatureLen  = 32
	MaxReqRspLen     = 1
	MaxIvLen         = 16
	MaxDataLen       = 1423

	REQ = 0
	RSP = 1
)

type Listener interface {
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	Close() error
}

type ICMPListener struct {
	IntAddr string
	TrgAddr net.Addr
	RcvAddr net.Addr
	Conn    net.PacketConn
}

type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Payload  []byte
}
