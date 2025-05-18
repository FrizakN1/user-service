package database

import (
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"testing"
	"user-service/mocks"
	"user-service/models"
)

func TestGetRoles(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		roleRepo := &DefaultRoleRepository{
			Database: mockDB,
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		rows := sqlmock.NewRows([]string{"id", "key", "value"}).
			AddRow(1, "admin", "Админ").
			AddRow(2, "user", "Пользователь")

		mock.ExpectPrepare("SELECT .* FROM Role ORDER BY id").ExpectQuery().WillReturnRows(rows)

		stmt, err := db.Prepare("SELECT * FROM Role ORDER BY id")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_ROLES").Return(stmt, true)

		roles, err := roleRepo.GetRoles()
		assert.NoError(t, err)
		assert.Len(t, roles, 2)
		assert.Equal(t, "admin", roles[0].Key)
		assert.Equal(t, "user", roles[1].Key)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		roleRepo := &DefaultRoleRepository{
			Database: mockDB,
		}

		mockDB.On("GetQuery", "GET_ROLES").Return(nil, false)

		roles, err := roleRepo.GetRoles()
		assert.Error(t, err)
		assert.Nil(t, roles)
		assert.Contains(t, err.Error(), "запрос GET_ROLES не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("QueryError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		roleRepo := &DefaultRoleRepository{
			Database: mockDB,
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("SELECT .* FROM Role ORDER BY id").ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare("SELECT * FROM Role ORDER BY id")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_ROLES").Return(stmt, true)

		roles, err := roleRepo.GetRoles()
		assert.Error(t, err)
		assert.Nil(t, roles)
		assert.Contains(t, err.Error(), "query error")

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ScanError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		roleRepo := &DefaultRoleRepository{
			Database: mockDB,
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		mock.ExpectPrepare("SELECT .* FROM Role ORDER BY id").ExpectQuery().WillReturnRows(row)

		stmt, err := db.Prepare("SELECT * FROM Role ORDER BY id")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_ROLES").Return(stmt, true)

		roles, err := roleRepo.GetRoles()
		assert.Error(t, err)
		assert.Nil(t, roles)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestGetRole(t *testing.T) {
	t.Run("SuccessQueryByID", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		roleRepo := &DefaultRoleRepository{
			Database: mockDB,
		}

		role := models.Role{ID: 1}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id", "key", "value"}).
			AddRow(1, "admin", "Админ")

		mock.ExpectPrepare("SELECT id, key, value FROM Role WHERE id = \\$1 OR key = \\$2").ExpectQuery().WithArgs(1, "").WillReturnRows(row)

		stmt, err := db.Prepare("SELECT id, key, value FROM Role WHERE id = $1 OR key = $2")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_ROLE").Return(stmt, true)

		err = roleRepo.GetRole(&role)
		assert.NoError(t, err)
		assert.Equal(t, "admin", role.Key)
		assert.Equal(t, "Админ", role.Value)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("SuccessQueryByKey", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		roleRepo := &DefaultRoleRepository{
			Database: mockDB,
		}

		role := models.Role{Key: "admin"}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id", "key", "value"}).
			AddRow(1, "admin", "Админ")

		mock.ExpectPrepare("SELECT id, key, value FROM Role WHERE id = \\$1 OR key = \\$2").ExpectQuery().WithArgs(0, "admin").WillReturnRows(row)

		stmt, err := db.Prepare("SELECT id, key, value FROM Role WHERE id = $1 OR key = $2")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_ROLE").Return(stmt, true)

		err = roleRepo.GetRole(&role)
		assert.NoError(t, err)
		assert.Equal(t, "admin", role.Key)
		assert.Equal(t, "Админ", role.Value)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		roleRepo := &DefaultRoleRepository{
			Database: mockDB,
		}

		role := models.Role{}

		mockDB.On("GetQuery", "GET_ROLE").Return(nil, false)

		err := roleRepo.GetRole(&role)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос GET_ROLE не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("QueryError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		roleRepo := &DefaultRoleRepository{
			Database: mockDB,
		}

		role := models.Role{}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("SELECT id, key, value FROM Role WHERE id = \\$1 OR key = \\$2").ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare("SELECT id, key, value FROM Role WHERE id = $1 OR key = $2")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_ROLE").Return(stmt, true)

		err = roleRepo.GetRole(&role)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query error")

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ScanError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		roleRepo := &DefaultRoleRepository{
			Database: mockDB,
		}

		role := models.Role{ID: 1}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		mock.ExpectPrepare("SELECT id, key, value FROM Role WHERE id = \\$1 OR key = \\$2").ExpectQuery().WithArgs(1, "").WillReturnRows(row)

		stmt, err := db.Prepare("SELECT id, key, value FROM Role WHERE id = $1 OR key = $2")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_ROLE").Return(stmt, true)

		err = roleRepo.GetRole(&role)
		assert.Error(t, err)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
