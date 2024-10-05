package main

import (
	"golang.org/x/crypto/bcrypt"
	"time"
)

type UserType string

const (
	Student UserType = "student"
	Teacher UserType = "teacher"
	Admin   UserType = "admin"
)

type LoginResponse struct {
	UserID int64  `json:"userId"`
	Token  string `json:"token"`
}

type LoginRequest struct {
	Id       int64  `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterUserRequest struct {
	FirstName string   `json:"firstName"`
	LastName  string   `json:"lastName"`
	Email     string   `json:"email"`
	Password  string   `json:"password"`
	UserType  UserType `json:"userType"`
}

type User struct {
	ID                int64     `json:"id"`
	FirstName         string    `json:"firstName"`
	LastName          string    `json:"lastName"`
	Email             string    `json:"email"`
	EncryptedPassword string    `json:"-"`
	UserType          UserType  `json:"userType"`
	CreatedAt         time.Time `json:"createdAt"`
}

func (u *User) ValidPassword(pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(u.EncryptedPassword), []byte(pw)) == nil
}

func NewUser(firstName, lastName, email, password string, userType UserType) (*User, error) {
	encpw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return &User{
		FirstName:         firstName,
		LastName:          lastName,
		Email:             email,
		EncryptedPassword: string(encpw),
		UserType:          userType,
		CreatedAt:         time.Now().UTC(),
	}, nil
}
