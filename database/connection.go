package database

import (
	"errors"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

func InitDatabase() (Database, error) {
	d := new(DefaultDatabase)

	if err := d.Connect(); err != nil {
		return nil, err
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return nil, err
	}

	if err := goose.Up(d.db, "migrations"); err != nil {
		return nil, err
	}

	errorsList := d.PrepareQuery()
	if len(errorsList) > 0 {
		for _, err := range errorsList {
			fmt.Println(err)
		}

		return nil, errors.New("ошибка при подготовке запросов")
	}

	return d, nil
}
