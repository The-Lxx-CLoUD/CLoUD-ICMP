package icmp

import (
	"fmt"
	"net"
)

func NewICMPListener(intAddr, trgAddr string) (*ICMPListener, error) {
	raddr, err := net.ResolveIPAddr("ip4", trgAddr)
	if err != nil {
		return nil, fmt.Errorf("Failed to resolve target address: %v", err)
	}

	conn, err := net.ListenPacket("ip4:icmp", intAddr)
	if err != nil {
		return nil, fmt.Errorf("Error on stablish socket: %v\n", err)
	}

	return &ICMPListener{
		IntAddr: intAddr,
		TrgAddr: raddr,
		RcvAddr: raddr,
		Conn:    conn,
	}, nil
}

func (l *ICMPListener) Read(b []byte) (int, error) {
	n, addr, err := l.Conn.ReadFrom(b)

	if err != nil {
		return 0, fmt.Errorf("Error on reading socket: %v", err)
	}
	l.RcvAddr = addr
	return n, nil
}

func (l *ICMPListener) Write(b []byte, useTrg bool) (int, error) {
	if useTrg {
		return l.Conn.WriteTo(b, l.TrgAddr)
	}
	return l.Conn.WriteTo(b, l.RcvAddr)

}

func (l *ICMPListener) Close() error {
	return l.Conn.Close()
}
