package models

type Session struct {
	Hash      string
	User      User
	CreatedAt int64
}
