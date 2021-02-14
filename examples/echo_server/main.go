package main

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/wire"
)

type stubAuthenticator struct {
	creds *wire.PeerCredentials
}

func (s *stubAuthenticator) IsPeerValid(peer *wire.PeerCredentials) bool {
	if subtle.ConstantTimeCompare(s.creds.PublicKey.Bytes(), peer.PublicKey.Bytes()) != 1 {
		return false
	}
	return true
}

func handleConnection(privateKey *ecdh.PrivateKey, conn net.Conn) {
	clientPublicKeyBytes, err := hex.DecodeString("c8de601616d781d8e26589cc78399541ed9a89ef1fa7013a3c930a5b4da10f06")
	if err != nil {
		panic(err)
	}
	clientPublicKey := new(ecdh.PublicKey)
	err = clientPublicKey.FromBytes(clientPublicKeyBytes)
	if err != nil {
		panic(err)
	}

	credsClient := &wire.PeerCredentials{
		AdditionalData: []byte("example_client"),
		PublicKey:      clientPublicKey,
	}
	credsServer := &wire.PeerCredentials{
		AdditionalData: []byte("example_echo_server"),
		PublicKey:      privateKey.PublicKey(),
	}
	cfg := &wire.SessionConfig{
		Authenticator:     &stubAuthenticator{creds: credsClient},
		AdditionalData:    credsServer.AdditionalData,
		AuthenticationKey: privateKey,
		RandomReader:      rand.Reader,
	}
	s, err := wire.NewSession(cfg, false)
	if err != nil {
		panic(err)
	}

	defer conn.Close()
	defer s.Close()

	err = s.Initialize(conn)
	if err != nil {
		panic(err)
	}

	for {
		cmd, err := s.RecvCommand()
		switch err {
		case io.EOF:
			fallthrough
		case io.ErrUnexpectedEOF:
			fmt.Println("connection closed")
			return
		case nil: // OK
		}

		err = s.SendCommand(cmd)
		if err != nil {
			panic(err)
		}
	}
}

func main() {
	/*
		privateKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}
		publicKeyBytes := privateKey.PublicKey().Bytes()
		privateKeyBytes := privateKey.Bytes()

		fmt.Printf("publicKey: %x\n", publicKeyBytes)
		fmt.Printf("privateKey: %x\n", privateKeyBytes)
	*/

	//publicKeyBytes, err := hex.DecodeString("48887bd92bfee3ea74d99aa0d489bea1b32f4e923ccf240ac5949d3ab3f23e12")
	privateKeyBytes, err := hex.DecodeString("7d23a89ba0779e8b4f34c09dd2c78bb284b5cb8741db58e509b3c8448175efa9")
	if err != nil {
		panic(err)
	}
	privateKey := new(ecdh.PrivateKey)
	err = privateKey.FromBytes(privateKeyBytes)
	if err != nil {
		panic(err)
	}
	fmt.Printf("public key: %x\n", privateKey.PublicKey().Bytes())

	ln, err := net.Listen("tcp", "127.0.0.1:36669")
	if err != nil {
		panic(err)
	}

	conn, err := ln.Accept()
	if err != nil {
		panic(err)
	}
	handleConnection(privateKey, conn)
}
