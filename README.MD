# Go Utils

A collection of utility tools written in Go to help automate and configure various services.

## LDAP Utility

The first utility in this collection provides functionality to configure an LDAP server. Using the LDAP protocol, this tool allows you to:

- Set up and configure your LDAP server's initial settings.
- Create, update, and manage users.
- Define and manage Organizational Units (OU).

### Usage

1. Ensure all required environment variables are set (`AD_HOST`, `AD_PORT`, `AD_DN`, `AD_PWD`).
2. Use the `create` command to set up the initial LDAP tree and add users.
3. Use the `list` command to view the current configuration and user list in the LDAP server.

```bash
go run main.go ldap create
go run main.go ldap list