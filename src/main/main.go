package main

import (
	"fmt"
	"log"
)

func main() {
	user, err := TryLogin("einstein", "password")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(
		user.username,
		user.groups,
	)
}
