/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                  Two Number Combination Finder Script                     *
 *									by										 *
 *						   Manny (Revx0r) Berrueta					         *
 *																			 *
 * Description: This script with -diff flag finds if a file in a directory   *
 *              full of the same file is different (modified) by using the   *
 *				targetfile hash. This is useful for forensics.               *
 *              This script without the -diff flag will find a file with a   *
 *               matching hash in a directory.                               *
 *				You can also choose the crypto type by using the -m flag	 *
 *				Hash as an input and recursive search is in todo list		 *
 *  																		 *
 *																			 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	//todo: input hash instead of file
	//todo: recursive search
	//todo: output finding to a file
	dirPtr := flag.String("dir", "", "Pass in the target directory to search in")
	diffPtr := flag.Bool("diff", false, "Find a file producing a different hash")
	fileTargtPtr := flag.String("t", "", "Pass in the target file to check agaisnt")
	cryptoTypePtr := flag.String("m", "", `Select Hash crypto type: md5, sha1, sha2
											sha3, sha5. Default is Sha2.`)
	flag.Parse()

	if *dirPtr == "" && *fileTargtPtr == "" {
		fmt.Println("This script requires you to pass the -dir and -t flags!")
		os.Exit(1)
	}

	targetData, err := ioutil.ReadFile(*fileTargtPtr)

	var fileTargetHash [32]byte
	var fileTargetmd5Hash [16]byte
	var fileTargetsha1Hash [20]byte
	var fileTargetsha3Hash [48]byte
	var fileTargetsha5Hash [64]byte
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

	files, err := ioutil.ReadDir(*dirPtr)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		data, err := ioutil.ReadFile(*dirPtr + f.Name())
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
					fmt.Printf("\t\tFound diff file!\t Name:%s\n", f.Name())
					fmt.Printf("\t\tSha256: %x\n", tempSha256)
				}
			} else { //! To find a matching hash to the target file
				if fileTargetHash == tempSha256 {
					fmt.Printf("\t\tFound Matching Hash File!\t Name:%s\n", f.Name())
					fmt.Printf("\t\tSha256: %x\n", tempSha256)
				}
			}
		case "sha1":
			tempSha1 := sha1.Sum(data)

			//! To find different hash from target file in a directory
			if *diffPtr {

				if fileTargetsha1Hash != tempSha1 {
					fmt.Printf("\t\tFound diff file!\t Name:%s\n", f.Name())
					fmt.Printf("\t\tSha1: %x\n", tempSha1)
				}
			} else { //! To find a matching hash to the target file
				if fileTargetsha1Hash == tempSha1 {
					fmt.Printf("\t\tFound Matching Hash File!\t Name:%s\n", f.Name())
					fmt.Printf("\t\tSha1: %x\n", tempSha1)
				}
			}
		case "sha3":
			tempSha3 := sha512.Sum384(data)

			//! To find different hash from target file in a directory
			if *diffPtr {

				if fileTargetsha3Hash != tempSha3 {
					fmt.Printf("\t\tFound diff file!\t Name:%s\n", f.Name())
					fmt.Printf("\t\tSha3: %x\n", tempSha3)
				}
			} else { //! To find a matching hash to the target file
				if fileTargetsha3Hash == tempSha3 {
					fmt.Printf("\t\tFound Matching Hash File!\t Name:%s\n", f.Name())
					fmt.Printf("\t\tSha3: %x\n", tempSha3)
				}
			}
		case "sha5":
			tempSha5 := sha512.Sum512(data)

			//! To find different hash from target file in a directory
			if *diffPtr {

				if fileTargetsha5Hash != tempSha5 {
					fmt.Printf("\t\tFound diff file!\t Name:%s\n", f.Name())
					fmt.Printf("\t\tSha5: %x\n", tempSha5)
				}
			} else { //! To find a matching hash to the target file
				if fileTargetsha5Hash == tempSha5 {
					fmt.Printf("\t\tFound Matching Hash File!\t Name:%s\n", f.Name())
					fmt.Printf("\t\tSha5: %x\n", tempSha5)
				}
			}
		case "md5":
			tempmd5 := md5.Sum(data)

			//! To find different hash from target file in a directory
			if *diffPtr {

				if fileTargetmd5Hash != tempmd5 {
					fmt.Printf("\t\tFound diff file!\t Name:%s\n", f.Name())
					fmt.Printf("\t\tMD5: %x\n", tempmd5)
				}
			} else { //! To find a matching hash to the target file
				if fileTargetmd5Hash == tempmd5 {
					fmt.Printf("\t\tFound Matching Hash File!\t Name:%s\n", f.Name())
					fmt.Printf("\t\tMD5: %x\n", tempmd5)
				}
			}
		}
	}
}
