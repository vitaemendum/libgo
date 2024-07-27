package main

import "math/rand"

type Account struct {
	ID        int    `json:"id"`
	FirstName string `json:"name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Number    string `json:"number"`
}

func NewAccount(firstName, lastName, email, number string) *Account {
	return &Account{
		ID:        rand.Intn(100000),
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
		Number:    number,
	}
}
