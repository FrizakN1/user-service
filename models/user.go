package models

import "database/sql"

type User struct {
	ID        int
	Role      Role
	Login     string
	Name      string
	Password  string
	IsActive  bool
	CreatedAt int64
	UpdatedAt sql.NullInt64
}
