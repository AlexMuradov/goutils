package ldaputil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"
)

type Users struct {
	User     string
	Password string
	Ou       string
	Username string
}

type Tree struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
}

var requiredEnvVars = []string{"AD_HOST", "AD_PORT", "AD_DN", "AD_PWD"}

func checkLdapEnvVars([]string) error {
	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			fmt.Printf("ERROR: Environment variable %s is not set\n", envVar)
			return errors.New("Environment variable not set")
		}
	}
	return nil
}

// LDAP connection details
var ldapHost = os.Getenv("AD_HOST")
var ldapPort, _ = strconv.Atoi(os.Getenv("AD_PORT"))
var bindDN = os.Getenv("AD_DN")
var bindPassword = os.Getenv("AD_PWD")

func ldapConnectAndBind() (*ldap.Conn, error) {
	// Create a new LDAP connection
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapHost, ldapPort))
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to LDAP server: %v", err)
	}

	// Bind to the LDAP server
	err = l.Bind(bindDN, bindPassword)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("Failed to bind to LDAP server: %v", err)
	}

	return l, nil
}

func ldapCreate() *cobra.Command {
	userjsonfile := "users.json" // Default file name
	treejsonfile := "tree.json"  // Default file name
	var userDNFormat = "cn=%s,CN=Users,DC=global,DC=domain,DC=net"

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Creates an ldap tree and users",
		Run: func(cmd *cobra.Command, args []string) {
			if checkLdapEnvVars(requiredEnvVars) != nil {
				os.Exit(1)
			}
			data, err := ioutil.ReadFile(treejsonfile)
			if err != nil {
				log.Fatalf("Failed to read JSON file: %v", err)
			}

			var tree []Tree
			err = json.Unmarshal(data, &tree)
			if err != nil {
				log.Fatalf("Failed to unmarshal JSON: %v", err)
			}
			usersFile, err := ioutil.ReadFile(userjsonfile)
			if err != nil {
				log.Fatalf("Failed to read JSON file: %v", err)
			}

			var people []Users
			err = json.Unmarshal(usersFile, &people)
			if err != nil {
				log.Fatalf("Failed to unmarshal JSON: %v", err)
			}

			// Call the ldapConnectAndBind function to get the LDAP connection
			l, err := ldapConnectAndBind()
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			defer l.Close()

			var entries []*ldap.Entry
			for _, t := range tree {
				entry := ldap.NewEntry(t.DN, t.Attributes)
				entries = append(entries, entry)
			}

			// Add the entries to the LDAP server
			for _, entry := range entries {
				addRequest := ldap.NewAddRequest(entry.DN, nil) // We use nil for no controls in this example

				for _, attr := range entry.Attributes {
					addRequest.Attribute(attr.Name, attr.Values)
				}

				err = l.Add(addRequest)
				if err != nil {
					log.Fatalf("Failed to add entry to LDAP server: %v", err)
				}
			}

			log.Println("LDAP tree creation successful!")

			for _, person := range people {
				// Create a new user entry
				userDN := fmt.Sprintf(userDNFormat, person.Username)
				userEntry := ldap.NewEntry(userDN, map[string][]string{
					"objectClass":  {"top", "person"},
					"cn":           {person.User},
					"sn":           {person.User},
					"userPassword": {person.Password},
				})

				// Add the user entry to the LDAP server
				addRequest := ldap.NewAddRequest(userEntry.DN, nil)
				for _, attr := range userEntry.Attributes {
					addRequest.Attribute(attr.Name, attr.Values)
				}
				err = l.Add(addRequest)
				if err != nil {
					if ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
						log.Printf("User %s already exists, updating...", person.User)

						modifyRequest := ldap.NewModifyRequest(userEntry.DN, nil)
						for _, attr := range userEntry.Attributes {
							modifyRequest.Replace(attr.Name, attr.Values)
						}

						// Try to modify the entry
						if err := l.Modify(modifyRequest); err != nil {
							log.Printf("Failed to update user %s: %v", person.User, err)
						} else {
							log.Printf("Successfully updated user %s", person.User)
						}
					} else {
						log.Fatalf("Failed to add user: %v", err)
					}
				} else {
					log.Printf("Successfully added user %s", person.User)
				}
			}
		},
	}
	cmd.Flags().StringVarP(&userDNFormat, "dn", "d", userDNFormat, "Format for user DN, %s will be replaced with username")
	cmd.Flags().StringVarP(&treejsonfile, "tree-file", "t", treejsonfile, "file path to tree file")
	cmd.Flags().StringVarP(&userjsonfile, "user-file", "u", userjsonfile, "file path to users file")
	return cmd
}

func ldapList() *cobra.Command {
	searchBase := "DC=global,DC=domain,DC=net" // The base DN to start searching
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List ldap",
		Run: func(cmd *cobra.Command, args []string) {
			if checkLdapEnvVars(requiredEnvVars) != nil {
				os.Exit(1)
			}

			// Call the ldapConnectAndBind function to get the LDAP connection
			l, err := ldapConnectAndBind()
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			defer l.Close()

			// Specify the LDAP search filter to retrieve all entries
			searchFilter := "(objectClass=*)"
			searchRequest := ldap.NewSearchRequest(
				searchBase,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				searchFilter,
				[]string{"dn", "objectClass"}, // Retrieve DN and objectClass attributes
				nil,
			)

			// Perform the search
			sr, err := l.Search(searchRequest)
			if err != nil {
				log.Fatalf("Failed to perform LDAP search: %v", err)
			}

			// Print the directory structure
			fmt.Println("Directory Structure:")
			for _, entry := range sr.Entries {
				fmt.Printf("%s (%s)\n", entry.DN, entry.GetAttributeValue("objectClass"))
			}
		},
	}
	cmd.Flags().StringVarP(&searchBase, "base", "b", searchBase, "base DN to start searching")
	return cmd
}

func ldapCreateDefaulFiles() *cobra.Command {
	path := "."
	cmd := &cobra.Command{
		Use:   "create-default-files",
		Short: "Creates default files for ldap",
		Run: func(cmd *cobra.Command, args []string) {

			files := map[string]string{
				"users.json": `[
					{
						"user": "User 1",
						"password": "passwd",
						"ou": "Operations",
						"username": "user1"
					},
					{
						"user": "User 2",
						"password": "passwd",
						"ou": "Development",
						"username": "user2"
					}
				]`,
				"tree.json": `[
					{
						"dn": "CN=Users,DC=global,DC=domain,DC=net",
						"attributes": {
							"objectClass": ["top", "organizationalPerson"],
							"cn": ["Users"]
						}
					}
				]`,
			}

			for filename, content := range files {
				fullPath, err := filepath.Abs(filepath.Join(path, filename))
				if err != nil {
					log.Fatalf("Failed to get absolute path %s: %v", filename, err)
				}

				err = ioutil.WriteFile(fullPath, []byte(content), 0644)
				if err != nil {
					log.Fatalf("Failed to create %s file: %v", fullPath, err)
				}
			}
		},
	}
	cmd.Flags().StringVarP(&path, "files-path", "p", path, "path to create files")
	return cmd
}

func Ldap() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ldap",
		Short: "Ldap management commands",
	}
	cmd.AddCommand(ldapCreate())
	cmd.AddCommand(ldapList())
	cmd.AddCommand(ldapCreateDefaulFiles())
	return cmd
}
