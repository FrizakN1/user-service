package database

import (
	"database/sql"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"testing"
	"user-service/utils"
)

func TestGetRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	originQuery := query
	originLogger := utils.Logger
	defer func() {
		query = originQuery
		utils.Logger = originLogger
	}()
	query = make(map[string]*sql.Stmt)
	utils.Logger = log.New(io.Discard, "", 0)

	expectePrepareQuery := mock.ExpectPrepare("SELECT .* FROM Role")

	var stmt *sql.Stmt
	stmt, err = db.Prepare("SELECT * FROM Role")
	assert.NoError(t, err)

	roleRepo := &DefaultRoleRepository{}

	t.Run("Success", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{
			"id", "key", "value",
		}).AddRow(
			1, "admin", "Админ",
		).AddRow(
			2, "user", "Пользователь",
		)

		expectePrepareQuery.ExpectQuery().WillReturnRows(rows)

		query["GET_ROLES"] = stmt

		roles, err := roleRepo.GetRoles()
		assert.NoError(t, err)
		assert.Len(t, roles, 2)
		assert.Equal(t, "admin", roles[0].Key)
		assert.Equal(t, "user", roles[1].Key)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}
