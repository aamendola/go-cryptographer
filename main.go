package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
)

// Encrypt ...
type Encrypt struct {
	key []byte
}

// MakeEncrypt The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
// 32 bytes (AES-256)
func MakeEncrypt(key string) Encrypt {
	key = "Thats my Kung Fu"
	return Encrypt{[]byte(key)}
}

func main() {
	// https://levelup.gitconnected.com/a-short-guide-to-encryption-using-go-da97c928259f
}

func buildFilenames(filename string) (string, string) {
	txtFile := fmt.Sprintf("%s%s", filename, ".txt")
	binFile := fmt.Sprintf("%s%s", filename, ".bin")
	return txtFile, binFile
}

// Encrypter ...
func (e Encrypt) Encrypter(filename string) {
	//infile, err := os.Open("plaintext.txt")
	txtFile, binFile := buildFilenames(filename)

	infile, err := os.Open(txtFile)
	if err != nil {
		log.Fatal(err)
	}
	defer infile.Close()

	block, err := aes.NewCipher(e.key)
	if err != nil {
		log.Panic(err)
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of repeat.
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
	}

	outfile, err := os.OpenFile(binFile, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()

	// The buffer size must be multiple of 16 bytes
	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, iv)
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			// Write into file
			outfile.Write(buf[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Printf("Read %d bytes: %v", n, err)
			break
		}
	}
	// Append the IV
	outfile.Write(iv)
}

// Decrypter ...
func (e Encrypt) Decrypter(filename string) {
	//infile, err := os.Open("ciphertext.bin")
	txtFile, binFile := buildFilenames(filename)

	infile, err := os.Open(binFile)
	if err != nil {
		log.Fatal(err)
	}
	defer infile.Close()

	block, err := aes.NewCipher(e.key)
	if err != nil {
		log.Panic(err)
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of repeat.
	fi, err := infile.Stat()
	if err != nil {
		log.Fatal(err)
	}

	iv := make([]byte, block.BlockSize())
	msgLen := fi.Size() - int64(len(iv))
	_, err = infile.ReadAt(iv, msgLen)
	if err != nil {
		log.Fatal(err)
	}

	outfile, err := os.OpenFile(txtFile, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()

	// The buffer size must be multiple of 16 bytes
	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, iv)
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			// The last bytes are the IV, don't belong the original message
			if n > int(msgLen) {
				n = int(msgLen)
			}
			msgLen -= int64(n)
			stream.XORKeyStream(buf, buf[:n])
			// Write into file
			outfile.Write(buf[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Printf("Read %d bytes: %v", n, err)
			break
		}
	}
}
