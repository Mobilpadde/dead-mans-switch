package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

const (
	// https://stackoverflow.com/a/42718395/754471
	OS_READ       = 04
	OS_WRITE      = 02
	OS_USER_SHIFT = 6

	OS_USER_R = OS_READ << OS_USER_SHIFT
	OS_USER_W = OS_WRITE << OS_USER_SHIFT
)

func main() {
	encryptFile := flag.Bool("e", false, "To encrypt before running?")
	file := flag.String("f", "./data.txt", "File to encrypt")

	flag.Parse()

	reader := bufio.NewReader(os.Stdin)

	var inputs []string
	for {
		input, _, err := reader.ReadLine()
		if err != nil {
			break
		}

		inputs = append(inputs, string(input))
	}

	base := filepath.Base(*file)
	dir := filepath.Dir(*file)

	var err error
	var encrypted []byte

	if *encryptFile {
		// If not encrypted, let's encrypt out file first
		fileBytes, err := ioutil.ReadFile(*file)
		e(err)

		key := inputs[0]
		encrypted = encrypt(key, fileBytes)

		err = ioutil.WriteFile(dir+"/"+base+".enc", encrypted, OS_USER_R|OS_USER_W)
		e(err)

		os.Remove(*file)
	} else {
		// Read the contents of the already encrypted file
		encrypted, err = ioutil.ReadFile(*file + ".enc")
		e(err)
	}

	mail, pass := inputs[1], inputs[2]
	for range time.Tick(2 * time.Second) {
		if succ := checker(mail, pass, *file+".enc", encrypted); succ {
			break
		}
	}
}

func checker(user, pass, file string, bytes []byte) bool {
	c, err := client.DialTLS("imap.gmail.com:993", nil)
	e(err)

	defer func() {
		err := c.Logout()
		e(err)
	}()

	err = c.Login(user, pass)
	e(err)

	mbox, err := c.Select("INBOX", true)
	e(err)

	seqset := new(imap.SeqSet)
	seqset.AddRange(mbox.Messages-5, mbox.Messages)

	section := &imap.BodySectionName{}
	items := []imap.FetchItem{section.FetchItem()}

	msgs := make(chan *imap.Message, 5)
	done := make(chan error, 1)

	go func() {
		done <- c.Fetch(seqset, items, msgs)
	}()

	for msg := range msgs {
		m, err := mail.ReadMessage(msg.GetBody(section))
		if err != nil {
			log.Println(err)
			break
		}

		subject := m.Header.Get("Subject")
		if subject == "Unlock" {
			body, err := ioutil.ReadAll(m.Body)
			if err != nil {
				log.Println(err)
				break
			}

			bodies := strings.Split(string(body), "\r\n")

			dat, err := decrypt([]byte(bodies[3]), bytes)
			e(err)

			orig := strings.Split(file, ".enc")[0]
			return ioutil.WriteFile(orig, dat, OS_USER_R|OS_USER_W) == nil
		}
	}

	return false
}

func encrypt(key string, bytes []byte) []byte {
	c, err := aes.NewCipher([]byte(key))
	e(err)

	gcm, err := cipher.NewGCM(c)
	e(err)

	nonce := make([]byte, gcm.NonceSize())

	_, err = io.ReadFull(rand.Reader, nonce)
	e(err)

	return gcm.Seal(nonce, nonce, bytes, nil)
}

func decrypt(key, bytes []byte) ([]byte, error) {
	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		return []byte(""), err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return []byte(""), err
	}

	nonceSize := gcm.NonceSize()
	if len(bytes) < nonceSize {
		return []byte(""), err
	}

	nonce, cipherText := bytes[:nonceSize], bytes[nonceSize:]
	plain, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return []byte(""), err
	}

	return plain, nil
}

func e(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
