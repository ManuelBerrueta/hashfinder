/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                               HashFinder                                  *
 *                                  by                                       *
 *                        Manny (Revx0r) Berrueta                            *
 *                                                                           *
 * Description: This script with -diff flag finds if a file in a directory   *
 *              full of the same file is different (modified) by using the   *
 *              targetfile hash. This is useful for forensics.               *
 *              This script without the -diff flag will find a file with a   *
 *              matching hash in a directory and subdirectories.             *
 *              You can also choose the crypto type by using the -m flag     *
 *              Hash as an input                                             *
 *                                                                           *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Banner prints out ascii banner :)
func Banner() {
	asciiBanner :=
		`
██░ ██  ▄▄▄        ██████  ██░ ██   █████▒██▓ ███▄    █ ▓█████▄ ▓█████  ██▀███  
▓██░ ██▒▒████▄    ▒██    ▒ ▓██░ ██▒▓██   ▒▓██▒ ██ ▀█   █ ▒██▀ ██▌▓█   ▀ ▓██ ▒ ██▒
▒██▀▀██░▒██  ▀█▄  ░ ▓██▄   ▒██▀▀██░▒████ ░▒██▒▓██  ▀█ ██▒░██   █▌▒███   ▓██ ░▄█ ▒
░▓█ ░██ ░██▄▄▄▄██   ▒   ██▒░▓█ ░██ ░▓█▒  ░░██░▓██▒  ▐▌██▒░▓█▄   ▌▒▓█  ▄ ▒██▀▀█▄  
░▓█▒░██▓ ▓█   ▓██▒▒██████▒▒░▓█▒░██▓░▒█░   ░██░▒██░   ▓██░░▒████▓ ░▒████▒░██▓ ▒██▒
 ▒ ░░▒░▒ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒ ▒ ░   ░▓  ░ ▒░   ▒ ▒  ▒▒▓  ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
 ▒ ░▒░ ░  ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░ ░      ▒ ░░ ░░   ░ ▒░ ░ ▒  ▒  ░ ░  ░  ░▒ ░ ▒░
 ░  ░░ ░  ░   ▒   ░  ░  ░   ░  ░░ ░ ░ ░    ▒ ░   ░   ░ ░  ░ ░  ░    ░     ░░   ░ 
 ░  ░  ░      ░  ░      ░   ░  ░  ░        ░           ░    ░       ░  ░   ░     
                                                          ░                      
`
	fmt.Println(asciiBanner)
}

func main() {
	dirPtr := flag.String("dir", "", "Pass in the target directory to search in")
	diffPtr := flag.Bool("diff", false, "Find a file producing a different hash")
	fileTargetPtr := flag.String("t", "", "Pass in the target file to check agaisnt")
	cryptoTypePtr := flag.String("m", "", `Select Hash crypto type: md5, sha1,
	 sha2, sha3, and sha5. Default is Sha2. To use -m crypto, i.e. -m sha1 or -m md5`)
	inputHashPtr := flag.String("i", "", `-i inputhash. Will calculate the hash
	 base ond the input string rather than a file`)
	helpFlagPtr := flag.Bool("h", false, "Help flag to print out all the help.")
	flag.Parse()

	Banner()

	if *helpFlagPtr {
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *dirPtr == "" && *fileTargetPtr == "" || *dirPtr == "" && *inputHashPtr == "" {
		fmt.Println("This script requires you to pass the -dir and -t flags!")
		os.Exit(1)
	}

	walkErr := filepath.Walk(*dirPtr, func(path string, file os.FileInfo, err error) error {
		if err != nil {
			fmt.Print("ERROR: TEMP")
		}
		if file.IsDir() != true {

			var fileTargetHash [32]byte
			var fileTargetmd5Hash [16]byte
			var fileTargetsha1Hash [20]byte
			var fileTargetsha3Hash [48]byte
			var fileTargetsha5Hash [64]byte

			if *fileTargetPtr != "" {
				targetData, err := ioutil.ReadFile(*fileTargetPtr)
				if err != nil {
					log.Fatal(err)
				}
				if *cryptoTypePtr == "" || *cryptoTypePtr == "sha2" {
					fileTargetHash = sha256.Sum256(targetData)
				} else if *cryptoTypePtr == "md5" {
					fileTargetmd5Hash = md5.Sum(targetData)
				} else if *cryptoTypePtr == "sha1" {
					fileTargetsha1Hash = sha1.Sum(targetData)
				} else if *cryptoTypePtr == "sha3" {
					fileTargetsha3Hash = sha512.Sum384(targetData)
				} else if *cryptoTypePtr == "sha5" {
					fileTargetsha5Hash = sha512.Sum512(targetData)
				}
			} else {
				tempHex, decodeErr := hex.DecodeString(strings.ToLower(*inputHashPtr))
				if decodeErr != nil {
					log.Fatal(decodeErr)
				} //! Convert []byte to array
				if *cryptoTypePtr == "" || *cryptoTypePtr == "sha2" {
					copy(fileTargetHash[:], tempHex)
				} else if *cryptoTypePtr == "md5" {
					copy(fileTargetmd5Hash[:], tempHex)
				} else if *cryptoTypePtr == "sha1" {
					copy(fileTargetsha1Hash[:], tempHex)
				} else if *cryptoTypePtr == "sha3" {
					copy(fileTargetsha3Hash[:], tempHex)
				} else if *cryptoTypePtr == "sha5" {
					copy(fileTargetsha5Hash[:], tempHex)
				}
			}

			data, err := ioutil.ReadFile(path)
			if err != nil {
				log.Fatal(err)
			}
			switch *cryptoTypePtr {
			case "":
				fallthrough
			case "sha2":
				tempSha256 := sha256.Sum256(data)

				//! To find different hash from target file in a directory
				if *diffPtr {

					if fileTargetHash != tempSha256 {
						fmt.Printf("\t\tFound diff file!\t Name:%s\n", path)
						fmt.Printf("\t\tSha256: %x\n", tempSha256)
					}
				} else { //! To find a matching hash to the target file
					if fileTargetHash == tempSha256 {
						fmt.Printf("\t\tFound Matching Hash File!\t Name:%s\n", path)
						fmt.Printf("\t\tSha256: %x\n", tempSha256)
					}
				}
			case "sha1":
				tempSha1 := sha1.Sum(data)

				//! To find different hash from target file in a directory
				if *diffPtr {

					if fileTargetsha1Hash != tempSha1 {
						fmt.Printf("\t\tFound diff file!\t Name:%s\n", path)
						fmt.Printf("\t\tSha1: %x\n", tempSha1)
					}
				} else { //! To find a matching hash to the target file
					if fileTargetsha1Hash == tempSha1 {
						fmt.Printf("\t\tFound Matching Hash File!\t Name:%s\n", path)
						fmt.Printf("\t\tSha1: %x\n", tempSha1)
					}
				}
			case "sha3":
				tempSha3 := sha512.Sum384(data)

				//! To find different hash from target file in a directory
				if *diffPtr {

					if fileTargetsha3Hash != tempSha3 {
						fmt.Printf("\t\tFound diff file!\t Name:%s\n", path)
						fmt.Printf("\t\tSha3: %x\n", tempSha3)
					}
				} else { //! To find a matching hash to the target file
					if fileTargetsha3Hash == tempSha3 {
						fmt.Printf("\t\tFound Matching Hash File!\t Name:%s\n", path)
						fmt.Printf("\t\tSha3: %x\n", tempSha3)
					}
				}
			case "sha5":
				tempSha5 := sha512.Sum512(data)

				//! To find different hash from target file in a directory
				if *diffPtr {

					if fileTargetsha5Hash != tempSha5 {
						fmt.Printf("\t\tFound diff file!\t Name:%s\n", path)
						fmt.Printf("\t\tSha5: %x\n", tempSha5)
					}
				} else { //! To find a matching hash to the target file
					if fileTargetsha5Hash == tempSha5 {
						fmt.Printf("\t\tFound Matching Hash File!\t Name:%s\n", path)
						fmt.Printf("\t\tSha5: %x\n", tempSha5)
					}
				}
			case "md5":
				tempmd5 := md5.Sum(data)

				//! To find different hash from target file in a directory
				if *diffPtr {

					if fileTargetmd5Hash != tempmd5 {
						fmt.Printf("\t\tFound diff file!\t Name:%s\n", path)
						fmt.Printf("\t\tMD5: %x\n", tempmd5)
					}
				} else { //! To find a matching hash to the target file
					if fileTargetmd5Hash == tempmd5 {
						fmt.Printf("\t\tFound Matching Hash File!\t Name:%s\n", path)
						fmt.Printf("\t\tMD5: %x\n", tempmd5)
					}
				}
			}
		}

		return err
	})

	if walkErr != nil {
		log.Fatal(walkErr)
	}
}
