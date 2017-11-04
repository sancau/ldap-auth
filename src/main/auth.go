package main

import (
	"fmt"
	"strings"
	"errors"
	"gopkg.in/ldap.v2"
)

type User struct {
	username string
	groups   []string
}

func parseMemberUid(data string) string {
	if strings.HasPrefix(data, "uid=") {
		idx := strings.Index(data, ",")
		return data[4:idx]
	}
	return ""
}

func TryLogin(username, password string) (User, error) {
	conn, err := ldap.Dial(networkType, serverAddress) // TODO TLS SUPPORT
	if err != nil {
		return User{}, err
	}
	defer conn.Close()

	err = conn.Bind(bindUser, bindPassword)
	if err != nil {
		return User{}, err
	}

	authenticated, err := Authenticate(conn, username, password)
	if err != nil {
		return User{}, err
	}
	if !authenticated {
		return User{}, errors.New("authentication failed and error was not handled")
	}

	groups, err := GetUserGroups(conn, username)
	if err != nil {
		return User{username, nil}, err
	}

	return User{username, groups}, nil
}

func GetUserGroups(conn *ldap.Conn, username string) ([]string, error) {
	groups := []string{}
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		usersSearchString,
		[]string{"dn", "cn", memberAttributeName},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	for _, entry := range result.Entries {
		groupName := entry.GetAttributeValue("cn")
		members := []string{}
		for _, memberData := range entry.GetAttributeValues(memberAttributeName) {
			var memberUid = parseMemberUid(memberData)
			if memberUid != "" {
				members = append(members, memberUid)
			}
		}
		if stringInSlice(username, members) {
			groups = append(groups, groupName)
		}
	}

	return groups, nil
}

func Authenticate(conn *ldap.Conn, username, password string) (bool, error) {
	searchString := fmt.Sprintf(groupsSearchString, username)
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchString,
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return false, err
	}

	if len(sr.Entries) == 0 {
		return false, errors.New("user does not exist")
	}
	if len(sr.Entries) > 1 {
		return false, errors.New("more then one user returned")
	}

	userDN := sr.Entries[0].DN

	// bind and check credentials
	err = conn.Bind(userDN, password)
	if err != nil {
		return false, err
	}

	// rebind back as the read only user
	err = conn.Bind(bindUser, bindPassword)
	if err != nil {
		return false, err
	}

	return true, nil
}
