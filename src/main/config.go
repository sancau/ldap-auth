package main

const (

	// LDAP Config

	networkType        = "tcp"
	serverAddress      = "ldap.forumsys.com:389"

	bindUser           = "cn=read-only-admin,dc=example,dc=com"
	bindPassword       = "password"

	baseDN             = "dc=example,dc=com"

	groupsSearchString = "(&(objectClass=organizationalPerson)(uid=%s))"
	usersSearchString  = "((objectClass=groupOfUniqueNames))" // another common case is "groupOfNames"
	memberAttributeName = "uniqueMember" // use "member" for "groupOfNames"

)
