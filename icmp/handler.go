package icmp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

    "github.com/The-Lxx-CLoUD/CLoUD-ICMP/crypto"
)

func toASCII(data []byte) string {
	var ascii strings.Builder
	for _, b := range data {
		if b >= 32 && b <= 126 {
			ascii.WriteByte(b)
		} else {
			ascii.WriteByte('.')
		}
	}
	return ascii.String()
}

func icmpCheckSum(b []byte) uint16 {
	var sum uint32
	length := len(b)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}

	if length%2 == 1 {
		sum += uint32(b[length-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}

func ParseICMP(b []byte, offset int, totalLen int) (hdr ICMPHeader, payload []byte, err error) {
	if totalLen < offset+MinICMPHeaderLen {
		return hdr, nil, fmt.Errorf("ICMP packet too short: %d bytes", totalLen)
	}

	hdr.Type = b[offset]
	hdr.Code = b[offset+1]
	hdr.Checksum = binary.BigEndian.Uint16(b[offset+2 : offset+4])

	if hdr.Type == ICMPTypeEcho || hdr.Type == ICMPTypeEchoReply {
		if totalLen < offset+MaxICMPHeaderLen {
			return hdr, nil, fmt.Errorf("ICMP echo packet too short: %d bytes", totalLen)
		}
		hdr.ID = binary.BigEndian.Uint16(b[offset+4 : offset+6])
		hdr.Seq = binary.BigEndian.Uint16(b[offset+6 : offset+8])
		payload = b[offset+8 : totalLen]
	} else {
		payload = b[offset+4 : totalLen]
	}

	return hdr, payload, nil
}

func PrintICMP(addr net.Addr, verbose bool, icmpHdr ICMPHeader, icmpOffset int, payload []byte, length int) {
	if verbose {
		typeName, exists := ICMPTypes[icmpHdr.Type]
		if !exists {
			typeName = fmt.Sprintf("Unknown Type (%d)", icmpHdr.Type)
		}

		timestamp := time.Now().Format("2006-01-02 15:04:05.000000")

		fmt.Printf("Time: %s\n", timestamp)
		fmt.Printf("Source: %s\n", addr.String())
		fmt.Printf("Type: %s (%d)\n", typeName, icmpHdr.Type)
		fmt.Printf("Code: %d\n", icmpHdr.Code)
		fmt.Printf("CheckSum: 0x%04x\n", icmpHdr.Checksum)
		if icmpHdr.Type == ICMPTypeEcho || icmpHdr.Type == ICMPTypeEchoReply {
			fmt.Printf("ID: %d\n", icmpHdr.ID)
			fmt.Printf("Sequence: %d\n", icmpHdr.Seq)
		}
		fmt.Printf("Packet Length: %d byte\n", length)
		if icmpOffset > 0 {
			fmt.Printf("IP Header Length: %d byte\n", icmpOffset)
		}

		if len(payload) > 0 {
			fmt.Println("Payload (Hex):")
			fmt.Println(hex.Dump(payload))
			fmt.Println("Payload (ASCII):")
			fmt.Println(toASCII(payload))
		} else {
			fmt.Println("No Payload")
		}

	} else {
		fmt.Printf("Raw Packet\n")
		fmt.Println(hex.Dump(payload))
	}

	fmt.Println("--------------------------------------------------")

}

func CreateEcho(id, seq uint16, msgType uint8, secretKey, iv, data []byte, encrypt bool) []byte {
	var (
		payload    []byte
		ciphertext []byte
		sign       []byte
	)

	if encrypt {
		key, _ := crypto.DeriveKey(secretKey)
		ciphertext, iv, _ = crypto.EncryptData(key, nil, data)

		h := hmac.New(sha256.New, secretKey)
		h.Write(ciphertext)
		sign = h.Sum(nil)

	} else {
		key, _ := crypto.DeriveKey(secretKey)
		ciphertext, iv, _ = crypto.EncryptData(key, iv, data)
		h := hmac.New(sha256.New, secretKey)
		h.Write(ciphertext)
		sign = h.Sum(nil)
	}

	customHeader := append(sign, byte(msgType))
	customHeader = append(customHeader, iv...)
	payload = append(customHeader, ciphertext...)

	header := make([]byte, MaxICMPHeaderLen)
	header[0] = ICMPTypeEcho
	header[1] = 0
	binary.BigEndian.PutUint16(header[2:4], 0)
	binary.BigEndian.PutUint16(header[4:6], id)
	binary.BigEndian.PutUint16(header[6:8], seq)

	packet := append(header, payload...)

	checksum := icmpCheckSum(packet)
	binary.BigEndian.PutUint16(packet[2:4], checksum)
	return packet
}

func CreateEchoReply(id, seq uint16, msgType uint8, secretKey, iv, data []byte, encrypt bool) []byte {
	var (
		payload    []byte
		ciphertext []byte
		sign       []byte
	)

	if encrypt {
		key, _ := crypto.DeriveKey(secretKey)
		ciphertext, iv, _ = crypto.EncryptData(key, nil, data)

		h := hmac.New(sha256.New, secretKey)
		h.Write(ciphertext)
		sign = h.Sum(nil)

	} else {
		key, _ := crypto.DeriveKey(secretKey)
		ciphertext, iv, _ = crypto.EncryptData(key, iv, data)
		h := hmac.New(sha256.New, secretKey)
		h.Write(ciphertext)
		sign = h.Sum(nil)
	}

	customHeader := append(sign, byte(msgType))
	customHeader = append(customHeader, iv...)
	payload = append(customHeader, ciphertext...)

	header := make([]byte, MaxICMPHeaderLen)
	header[0] = ICMPTypeEchoReply
	header[1] = 0
	binary.BigEndian.PutUint16(header[2:4], 0)
	binary.BigEndian.PutUint16(header[4:6], id)
	binary.BigEndian.PutUint16(header[6:8], seq)

	packet := append(header, payload...)

	checksum := icmpCheckSum(packet)
	binary.BigEndian.PutUint16(packet[2:4], checksum)
	return packet
}

func CreateDstUnreachable(id, seq uint16, msgType uint8, secretKey, iv, data []byte, encrypt bool) []byte {
	var (
		payload    []byte
		ciphertext []byte
		sign       []byte
	)

	if encrypt {
		key, _ := crypto.DeriveKey(secretKey)
		ciphertext, iv, _ = crypto.EncryptData(key, nil, data)

		h := hmac.New(sha256.New, secretKey)
		h.Write(ciphertext)
		sign = h.Sum(nil)

	} else {
		key, _ := crypto.DeriveKey(secretKey)
		ciphertext, iv, _ = crypto.EncryptData(key, iv, data)
		h := hmac.New(sha256.New, secretKey)
		h.Write(data)
		sign = h.Sum(nil)
	}
	customHeader := append(sign, byte(msgType))
	customHeader = append(customHeader, iv...)
	payload = append(customHeader, ciphertext...)

	header := make([]byte, MaxICMPHeaderLen)
	header[0] = ICMPTypeDestinationUnreachable
	header[1] = 0
	binary.BigEndian.PutUint16(header[2:4], 0)
	binary.BigEndian.PutUint16(header[4:6], id)
	binary.BigEndian.PutUint16(header[6:8], seq)

	packet := append(header, payload...)

	checksum := icmpCheckSum(packet)
	binary.BigEndian.PutUint16(packet[2:4], checksum)
	return packet
}

