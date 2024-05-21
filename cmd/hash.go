// Copyright © 2017 Aaron Donovan <amdonov@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// HashCmd represents the hash command
var HashCmd = &cobra.Command{
	Use:   "hash",
	Short: "hashes a password for use with example user store",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Print("Enter Password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		hashedPassword, err := hashPassword(bytePassword)
		if err != nil {
			return err
		}
		fmt.Println()
		fmt.Println(string(hashedPassword))
		return nil
	},
}

func hashPassword(src []byte) (string, error) {
	// Hashing the password with the default cost of 10
	hashedPassword, err := bcrypt.GenerateFromPassword(src, bcrypt.DefaultCost)
	return string(hashedPassword), err
}
