package database

import (
	"database/sql"
	"fmt"
	"os"
)

type Database interface {
	Connect() error
	PrepareQuery() []error
	GetQuery(key string) (*sql.Stmt, bool)
}

type DefaultDatabase struct {
	db    *sql.DB
	query map[string]*sql.Stmt
}

func (d *DefaultDatabase) Connect() error {
	var err error

	d.db, err = sql.Open("postgres", fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASS"),
		os.Getenv("DB_NAME")))
	if err != nil {
		return err
	}

	return d.db.Ping()
}

func (d *DefaultDatabase) GetQuery(key string) (*sql.Stmt, bool) {
	stmt, ok := d.query[key]

	return stmt, ok
}

func (d *DefaultDatabase) PrepareQuery() []error {
	var err error
	errorsList := make([]error, 0)
	d.query = make(map[string]*sql.Stmt)

	d.query["GET_ROLES"], err = d.db.Prepare(`
		SELECT * FROM "Role" ORDER BY id
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["GET_ROLE"], err = d.db.Prepare(`
		SELECT id, key, value FROM "Role" WHERE id = $1 OR key = $2
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["GET_SESSIONS"], err = d.db.Prepare(`
		SELECT s.*, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value
		FROM "Session" AS s
		JOIN "User" AS u ON u.id = s.user_id
		JOIN "Role" AS r ON r.id = u.role_id
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["CREATE_SESSION"], err = d.db.Prepare(`
		INSERT INTO "Session" (hash, user_id, created_at) VALUES ($1, $2, $3)
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["DELETE_SESSION"], err = d.db.Prepare(`
		DELETE FROM "Session" WHERE hash = $1
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["DELETE_USER_SESSIONS"], err = d.db.Prepare(`
		DELETE FROM "Session" WHERE user_id = $1
		RETURNING hash
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["GET_USERS"], err = d.db.Prepare(`
		SELECT u.id, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value
		FROM "User" AS u
		JOIN "Role" AS r ON r.id = u.role_id
		ORDER BY u.id
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["GET_USERS_BY_IDS"], err = d.db.Prepare(`
		SELECT u.id, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value
		FROM "User" AS u
		JOIN "Role" AS r ON r.id = u.role_id
		WHERE u.id = ANY($1)
		ORDER BY u.id
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["GET_USER"], err = d.db.Prepare(`
		SELECT u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value
		FROM "User" AS u
		JOIN "Role" AS r ON r.id = u.role_id
		WHERE u.id = $1
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["CREATE_USER"], err = d.db.Prepare(`
		INSERT INTO "User"(role_id, login, name, password, created_at) 
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["EDIT_USER"], err = d.db.Prepare(`
		UPDATE "User" SET role_id = $2, login = $3, name = $4, updated_at = $5
		WHERE id = $1
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["GET_AUTHORIZED_USER"], err = d.db.Prepare(`
		SELECT u.id, u.role_id, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value
		FROM "User" AS u
		JOIN "Role" AS r ON r.id = u.role_id
		WHERE login = $1 AND password = $2
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["CHANGE_USER_PASSWORD"], err = d.db.Prepare(`
		UPDATE "User" SET password = $2 WHERE id = $1
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["GET_SUPER_ADMIN"], err = d.db.Prepare(`
		SELECT id, password FROM "User" WHERE login = 'SuperAdmin'
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	d.query["CHANGE_USER_STATUS"], err = d.db.Prepare(`
		UPDATE "User" SET is_active = NOT is_active WHERE id = $1
		RETURNING is_active
	`)
	if err != nil {
		errorsList = append(errorsList, err)
	}

	return errorsList
}
