package utils

import (
	"io"
	"log"
	"net"
	"strings"
)

func Copy(conn net.Conn, in io.Reader, out io.Writer) {
	toStdoutChan := copyStream(conn, out)
	toRemoteChan := copyStream(in, conn)

	select {
	case <-toStdoutChan:
	case <-toRemoteChan:
	}
}

// Performs copy operation between streams: os and tcp streams
func copyStream(src io.Reader, dst io.Writer) <-chan int {
	buf := make([]byte, 1024)
	syncChannel := make(chan int)
	go func() {
		defer func() {
			if con, ok := dst.(net.Conn); ok {
				con.Close()
			}
			syncChannel <- 0 // Notify that processing is finished
		}()
		for {
			var nBytes int
			var err error
			nBytes, err = src.Read(buf)
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("Read error: %s\n", err)
				}
				break
			}
			_, err = dst.Write(buf[0:nBytes])
			if err != nil {
				log.Fatalf("Write error: %s\n", err)
			}
		}
	}()
	return syncChannel
}
