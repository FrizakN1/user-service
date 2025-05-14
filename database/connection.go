package database

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"os"
	"user-service/utils"
)

var Link *sql.DB
var query map[string]*sql.Stmt

func Connection() error {
	var err error
	Link, err = sql.Open("postgres", fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASS"),
		os.Getenv("DB_NAME")))
	if err != nil {
		utils.Logger.Println(err)
		return err
	}

	if err = Link.Ping(); err != nil {
		utils.Logger.Println(err)
		return err
	}

	if err = goose.SetDialect("postgres"); err != nil {
		utils.Logger.Println(err)
		return err
	}

	if err = goose.Up(Link, "migrations"); err != nil {
		utils.Logger.Println(err)
		return err
	}

	errorsList := make([]string, 0)

	errorsList = append(errorsList, prepareRole()...)
	errorsList = append(errorsList, prepareSession()...)
	errorsList = append(errorsList, prepareUsers()...)

	if len(errorsList) > 0 {
		for _, i := range errorsList {
			fmt.Println(i)
			utils.Logger.Println(i)
		}
	}

	SessionRepo := &DefaultSessionRepository{}

	if err = SessionRepo.LoadSession(sessionMap); err != nil {
		utils.Logger.Println(err)
		return err
	}

	return nil
}

func prepareQuery(queryName, sqlQuery string) error {
	if query == nil {
		query = make(map[string]*sql.Stmt)
	}

	stmt, err := Link.Prepare(sqlQuery)
	if err != nil {
		return err
	}

	query[queryName] = stmt
	return nil
}
