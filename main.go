package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

type result struct {
	privKey   []byte
	addrBytes []byte
	tries     uint64
}

// matchesPrefix returns true if addrBytes (20‑byte) has `zeros` leading hex zeros.
func matchesPrefix(addrBytes []byte, zeros int) bool {
	full := zeros / 2    // number of whole zero bytes
	half := zeros&1 == 1 // whether there’s a half‑nibble to check

	// check full bytes == 0
	for i := range full {
		if addrBytes[i] != 0 {
			return false
		}
	}
	// if odd nibble, high 4 bits of next byte must be zero
	if half && addrBytes[full]>>4 != 0 {
		return false
	}
	return true
}

var totalTries uint64

func worker(ctx context.Context, zeros int, resCh chan<- result) {
	privBuf := make([]byte, 32)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// fill 32 random bytes
		if _, err := rand.Read(privBuf); err != nil {
			continue
		}
		atomic.AddUint64(&totalTries, 1)

		// turn into an ECDSA key (panics if buf ≥ N, so skip those rare cases)
		key, err := crypto.ToECDSA(privBuf)
		if err != nil {
			continue
		}

		// derive address
		pub := key.Public().(*ecdsa.PublicKey)
		addr := crypto.PubkeyToAddress(*pub).Bytes()

		if matchesPrefix(addr, zeros) {
			tries := atomic.LoadUint64(&totalTries)
			// copy buffers (so we don’t race)
			privCopy := make([]byte, 32)
			addrCopy := make([]byte, 20)
			copy(privCopy, privBuf)
			copy(addrCopy, addr)

			resCh <- result{privKey: privCopy, addrBytes: addrCopy, tries: tries}
			return
		}
	}
}

func main() {
	zeros := flag.Int("zeros", 3, "number of leading zero hex characters (after 0x)")
	flag.Parse()

	nCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(nCPU)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resCh := make(chan result, 1)
	start := time.Now()

	log.Printf("🔎 Searching for %d leading hex zeros on %d cores…\n", *zeros, nCPU)
	for range nCPU {
		go worker(ctx, *zeros, resCh)
	}

	res := <-resCh
	cancel()

	elapsed := time.Since(start)
	addrHex := "0x" + hex.EncodeToString(res.addrBytes)
	privHex := "0x" + hex.EncodeToString(res.privKey)

	fmt.Printf("\n✅ Found in %d tries (%s):\n", res.tries, elapsed)
	fmt.Printf("   Address:    %s\n", addrHex)
	fmt.Printf("   PrivateKey: %s\n", privHex)
}
