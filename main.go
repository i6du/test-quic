package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"

	"github.com/u6du/ex"

	quic "github.com/u6du/quic-go"
)

const addr = "localhost:4242"

const message = "foobar"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	go func() { log.Fatal(echoServer()) }()

	ex.Panic(clientMain())
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	sess, err := listener.Accept()
	if err != nil {
		return err
	}
	stream, err := sess.AcceptStream()
	if err != nil {
		panic(err)
	}
	// Echo through the loggingWriter
	_, err = io.Copy(loggingWriter{stream}, stream)
	return err
}

func clientMain() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	session, err := quic.DialAddr(addr, tlsConf, nil)
	ex.Panic(err)

	stream, err := session.OpenStreamSync()
	if err != nil {
		return err
	}

	fmt.Printf("Client: Sending '%s'\n", message)
	_, err = stream.Write([]byte(message))
	if err != nil {
		return err
	}

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	fmt.Printf("Client: Got '%s'\n", buf)

	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}

func generateTLSConfig() *tls.Config {

	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(128), nil).Sub(max, big.NewInt(1))
	salt, err := rand.Int(rand.Reader, max)
	ex.Panic(err)

	template := x509.Certificate{SerialNumber: salt}

	pubKey, private, err := ed25519.GenerateKey(rand.Reader)

	ex.Panic(err)

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, private)
	ex.Panic(err)

	privateByte, err := x509.MarshalPKCS8PrivateKey(private)
	ex.Panic(err)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateByte})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	ex.Panic(err)

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
