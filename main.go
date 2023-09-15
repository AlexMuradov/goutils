package main

import (
	"fmt"
	"os"

	ldaputil "github.com/alexmuradov/goutils/ldaputil"

	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{Use: "ldap"}

	rootCmd.AddCommand(ldaputil.Ldap())

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
