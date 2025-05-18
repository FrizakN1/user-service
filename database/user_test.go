package database

import (
	"database/sql"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	testifyMock "github.com/stretchr/testify/mock"
	"testing"
	"time"
	"user-service/mocks"
	"user-service/models"
)

func TestGetUsers(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		rows := mock.NewRows([]string{"id", "role_id", "login", "name", "is_active", "created_at", "updated_at", "role_key", "role_value"}).
			AddRow(1, 1, "admin", "Administrator", true, time.Now().Unix(), time.Now().Unix(), "admin", "Админ").
			AddRow(1, 1, "user", "User", false, time.Now().Unix(), time.Now().Unix(), "user", "Пользователь")

		mock.ExpectPrepare("SELECT .* FROM User").ExpectQuery().WillReturnRows(rows)

		stmt, err := db.Prepare("SELECT * FROM User")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_USERS").Return(stmt, true)

		users, err := userRepo.GetUsers()
		assert.NoError(t, err)
		assert.Len(t, users, 2)
		assert.Equal(t, "admin", users[0].Login)
		assert.Equal(t, "user", users[1].Login)
		assert.True(t, users[0].IsActive)
		assert.False(t, users[1].IsActive)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		mockDB.On("GetQuery", "GET_USERS").Return(nil, false)

		users, err := userRepo.GetUsers()
		assert.Error(t, err)
		assert.Nil(t, users)
		assert.Contains(t, err.Error(), "запрос GET_USERS не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("QueryError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("SELECT .* FROM User").ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare("SELECT * FROM User")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_USERS").Return(stmt, true)

		users, err := userRepo.GetUsers()
		assert.Error(t, err)
		assert.Nil(t, users)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		rows := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		mock.ExpectPrepare("SELECT .* FROM User").ExpectQuery().WillReturnRows(rows)

		stmt, err := db.Prepare("SELECT * FROM User")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_USERS").Return(stmt, true)

		users, err := userRepo.GetUsers()
		assert.Error(t, err)
		assert.Nil(t, users)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestGetUser(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		user := models.User{ID: 1}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"role_id", "login", "name", "baned", "created_at", "updated_at", "role_value", "role_translate_value"}).
			AddRow(1, "admin", "Administrator", false, time.Now().Unix(), time.Now().Unix(), "admin", "Админ")

		mock.ExpectPrepare("SELECT .* FROM User WHERE id = \\$1").ExpectQuery().WithArgs(1).WillReturnRows(row)

		stmt, err := db.Prepare("SELECT * FROM User WHERE id = $1")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_USER").Return(stmt, true)

		err = userRepo.GetUser(&user)
		assert.NoError(t, err)
		assert.Equal(t, "admin", user.Login)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		user := models.User{ID: 1}

		mockDB.On("GetQuery", "GET_USER").Return(nil, false)

		err := userRepo.GetUser(&user)
		assert.Error(t, err)
		assert.Empty(t, user.Login)
		assert.Contains(t, err.Error(), "запрос GET_USER не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("QueryError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		user := models.User{ID: 1}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("SELECT .* FROM User WHERE id = \\$1").ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare("SELECT * FROM User WHERE id = $1")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_USER").Return(stmt, true)

		err = userRepo.GetUser(&user)
		assert.Error(t, err)
		assert.Empty(t, user.Login)
		assert.Contains(t, err.Error(), "query error")

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ScanError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		user := models.User{ID: 1}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		rows := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		mock.ExpectPrepare("SELECT .* FROM User WHERE id = \\$1").ExpectQuery().WillReturnRows(rows)

		stmt, err := db.Prepare("SELECT * FROM User WHERE id = $1")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_USER").Return(stmt, true)

		err = userRepo.GetUser(&user)
		assert.Empty(t, user.Login)
		assert.Error(t, err)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestChangeStatus(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		user := models.User{ID: 1}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"is_active"}).AddRow(false)

		mock.ExpectPrepare("UPDATE User SET is_active = !is_active WHERE id = \\$1").ExpectQuery().WithArgs(1).WillReturnRows(row)

		stmt, err := db.Prepare("UPDATE User SET is_active = !is_active WHERE id = $1")

		mockDB.On("GetQuery", "CHANGE_USER_STATUS").Return(stmt, true)

		err = userRepo.ChangeStatus(&user)
		assert.NoError(t, err)
		assert.False(t, user.IsActive)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		user := models.User{ID: 1}

		mockDB.On("GetQuery", "CHANGE_USER_STATUS").Return(nil, false)

		err := userRepo.ChangeStatus(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос CHANGE_USER_STATUS не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("QueryError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		user := models.User{ID: 1}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("UPDATE User SET is_active = !is_active WHERE id = \\$1").
			ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare("UPDATE User SET is_active = !is_active WHERE id = $1")

		mockDB.On("GetQuery", "CHANGE_USER_STATUS").Return(stmt, true)

		err = userRepo.ChangeStatus(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query error")

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ScanError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		user := models.User{ID: 1}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"is_active"}).AddRow(nil)

		mock.ExpectPrepare("UPDATE User SET is_active = !is_active WHERE id = \\$1").ExpectQuery().WithArgs(1).WillReturnRows(row)

		stmt, err := db.Prepare("UPDATE User SET is_active = !is_active WHERE id = $1")

		mockDB.On("GetQuery", "CHANGE_USER_STATUS").Return(stmt, true)

		err = userRepo.ChangeStatus(&user)
		assert.Error(t, err)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestEditUser(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		user := models.User{
			ID:        1,
			Role:      models.Role{ID: 1},
			Login:     "user",
			Name:      "user",
			UpdatedAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("UPDATE User SET role_id = \\$2, login = \\$3, name = \\$4, updated_at = \\$5 WHERE id = \\$1").
			ExpectExec().WithArgs(1, 1, "user", "user", sql.NullInt64{Int64: time.Now().Unix(), Valid: true}).
			WillReturnResult(sqlmock.NewResult(1, 1))

		stmt, err := db.Prepare("UPDATE User SET role_id = $2, login = $3, name = $4, updated_at = $5 WHERE id = $1")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "EDIT_USER").Return(stmt, true)

		err = userRepo.EditUser(&user)
		assert.NoError(t, err)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		mockDB.On("GetQuery", "EDIT_USER").Return(nil, false)

		err := userRepo.EditUser(&models.User{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос EDIT_USER не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("ExecError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		user := models.User{
			ID:        1,
			Role:      models.Role{ID: 1},
			Login:     "user",
			Name:      "user",
			UpdatedAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("UPDATE User SET role_id = \\$2, login = \\$3, name = \\$4, updated_at = \\$5 WHERE id = \\$1").
			ExpectExec().WillReturnError(errors.New("exec error"))

		stmt, err := db.Prepare("UPDATE User SET role_id = $2, login = $3, name = $4, updated_at = $5 WHERE id = $1")

		mockDB.On("GetQuery", "EDIT_USER").Return(stmt, true)

		err = userRepo.EditUser(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exec error")

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestCreateUser(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{
			Role:      models.Role{ID: 1},
			Login:     "user",
			Name:      "user",
			Password:  "password",
			CreatedAt: time.Now().Unix(),
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id"}).AddRow(1)

		mock.ExpectPrepare("INSERT INTO User \\(role_id, login, name, password, created_at\\) VALUES \\(\\$1, \\$2, \\$3, \\$4, \\$5\\) RETURNING id").
			ExpectQuery().WithArgs(1, "user", "user", "encrypted-pass", time.Now().Unix()).WillReturnRows(row)

		stmt, err := db.Prepare("INSERT INTO User (role_id, login, name, password, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "CREATE_USER").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		err = userRepo.CreateUser(&user)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.ID)
		assert.Equal(t, "encrypted-pass", user.Password)

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		mockDB.On("GetQuery", "CREATE_USER").Return(nil, false)

		err := userRepo.CreateUser(&models.User{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос CREATE_USER не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("EncryptError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{Password: "password"}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("INSERT INTO User \\(role_id, login, name, password, created_at\\) VALUES \\(\\$1, \\$2, \\$3, \\$4, \\$5\\) RETURNING id")

		stmt, err := db.Prepare("INSERT INTO User (role_id, login, name, password, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "CREATE_USER").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("", errors.New("encrypt error"))

		err = userRepo.CreateUser(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encrypt error")

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{
			Role:      models.Role{ID: 1},
			Login:     "user",
			Name:      "user",
			Password:  "password",
			CreatedAt: time.Now().Unix(),
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("INSERT INTO User \\(role_id, login, name, password, created_at\\) VALUES \\(\\$1, \\$2, \\$3, \\$4, \\$5\\) RETURNING id").
			ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare("INSERT INTO User (role_id, login, name, password, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "CREATE_USER").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		err = userRepo.CreateUser(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query error")

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ScanError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{
			Role:      models.Role{ID: 1},
			Login:     "user",
			Name:      "user",
			Password:  "password",
			CreatedAt: time.Now().Unix(),
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		mock.ExpectPrepare("INSERT INTO User \\(role_id, login, name, password, created_at\\) VALUES \\(\\$1, \\$2, \\$3, \\$4, \\$5\\) RETURNING id").
			ExpectQuery().WithArgs(1, "user", "user", "encrypted-pass", time.Now().Unix()).WillReturnRows(row)

		stmt, err := db.Prepare("INSERT INTO User (role_id, login, name, password, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "CREATE_USER").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		err = userRepo.CreateUser(&user)
		assert.Error(t, err)

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestLogin(t *testing.T) {
	t.Run("SuccessfulLogin", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{
			Login:    "user",
			Password: "password",
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id", "role_id", "name", "is_active", "created_at", "updated_at", "role_value", "role_translate_value"}).
			AddRow(2, 2, "user", true, time.Now().Unix(), nil, "user", "Пользователь")

		mock.ExpectPrepare("SELECT .* FROM User WHERE login = \\$1 AND password = \\$2").ExpectQuery().WithArgs("user", "encrypted-pass").
			WillReturnRows(row)

		stmt, err := db.Prepare("SELECT * FROM User WHERE login = $1 AND password = $2")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_AUTHORIZED_USER").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		err = userRepo.Login(&user)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.ID)
		assert.Equal(t, "user", user.Name)

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("UnsuccessfulLogin", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{
			Login:    "user",
			Password: "password",
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id", "role_id", "name", "baned", "created_at", "updated_at", "role_value", "role_translate_value"})

		mock.ExpectPrepare("SELECT .* FROM User WHERE login = \\$1 AND password = \\$2").ExpectQuery().WithArgs("user", "encrypted-pass").
			WillReturnRows(row)

		stmt, err := db.Prepare("SELECT * FROM User WHERE login = $1 AND password = $2")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_AUTHORIZED_USER").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		err = userRepo.Login(&user)
		assert.NoError(t, err)
		assert.Zero(t, user.ID)

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		mockDB.On("GetQuery", "GET_AUTHORIZED_USER").Return(nil, false)

		err := userRepo.Login(&models.User{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос GET_AUTHORIZED_USER не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("EncryptError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{Password: "password"}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("SELECT .* FROM User WHERE login = \\$1 AND password = \\$2")

		stmt, err := db.Prepare("SELECT * FROM User WHERE login = $1 AND password = $2")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_AUTHORIZED_USER").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("", errors.New("encrypt error"))

		err = userRepo.Login(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encrypt error")

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{
			Login:    "user",
			Password: "password",
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("SELECT .* FROM User WHERE login = \\$1 AND password = \\$2").ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare("SELECT * FROM User WHERE login = $1 AND password = $2")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_AUTHORIZED_USER").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		err = userRepo.Login(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query error")

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ScanError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{
			Login:    "user",
			Password: "password",
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		mock.ExpectPrepare("SELECT .* FROM User WHERE login = \\$1 AND password = \\$2").ExpectQuery().WithArgs("user", "encrypted-pass").
			WillReturnRows(row)

		stmt, err := db.Prepare("SELECT * FROM User WHERE login = $1 AND password = $2")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_AUTHORIZED_USER").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		err = userRepo.Login(&user)
		assert.Error(t, err)

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestChangeUserPassword(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{ID: 1, Password: "new-pass"}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("UPDATE User SET password = \\$2 WHERE id = \\$1").ExpectExec().WithArgs(1, "encrypted-pass").WillReturnResult(sqlmock.NewResult(1, 1))

		stmt, err := db.Prepare("UPDATE User SET password = $2 WHERE id = $1")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "CHANGE_USER_PASSWORD").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		err = userRepo.ChangeUserPassword(&user)
		assert.NoError(t, err)
		assert.Equal(t, "encrypted-pass", user.Password)

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		user := models.User{}

		mockDB.On("GetQuery", "CHANGE_USER_PASSWORD").Return(nil, false)

		err := userRepo.ChangeUserPassword(&user)
		assert.Error(t, err)
		assert.Empty(t, user.Password)
		assert.Contains(t, err.Error(), "запрос CHANGE_USER_PASSWORD не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("EncryptError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("UPDATE User SET password = \\$2 WHERE id = \\$1")

		stmt, err := db.Prepare("UPDATE User SET password = $2 WHERE id = $1")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "CHANGE_USER_PASSWORD").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("", errors.New("encrypt error"))

		err = userRepo.ChangeUserPassword(&user)
		assert.Error(t, err)
		assert.Empty(t, user.Password)
		assert.Contains(t, err.Error(), "encrypt error")

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ExecError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{ID: 1, Password: "new-pass"}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("UPDATE User SET password = \\$2 WHERE id = \\$1").ExpectExec().WillReturnError(errors.New("exec error"))

		stmt, err := db.Prepare("UPDATE User SET password = $2 WHERE id = $1")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "CHANGE_USER_PASSWORD").Return(stmt, true)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		err = userRepo.ChangeUserPassword(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exec error")

		mockDB.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestGetSuperAdmin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		admin := models.User{}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		rows := sqlmock.NewRows([]string{"id", "password"}).
			AddRow(1, "encrypted-pass")

		mock.ExpectPrepare("SELECT id, password FROM User WHERE login = 'SuperAdmin'").ExpectQuery().WillReturnRows(rows)

		stmt, err := db.Prepare("SELECT id, password FROM User WHERE login = 'SuperAdmin'")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_SUPER_ADMIN").Return(stmt, true)

		err = userRepo.GetSuperAdmin(&admin)
		assert.NoError(t, err)
		assert.Equal(t, 1, admin.ID)
		assert.Equal(t, "encrypted-pass", admin.Password)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		admin := models.User{}

		mockDB.On("GetQuery", "GET_SUPER_ADMIN").Return(nil, false)

		err := userRepo.GetSuperAdmin(&admin)
		assert.Error(t, err)
		assert.Equal(t, 0, admin.ID)
		assert.Contains(t, err.Error(), "запрос GET_SUPER_ADMIN не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("QueryError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		admin := models.User{}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("SELECT id, password FROM User WHERE login = 'SuperAdmin'").ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare("SELECT id, password FROM User WHERE login = 'SuperAdmin'")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_SUPER_ADMIN").Return(stmt, true)

		err = userRepo.GetSuperAdmin(&admin)
		assert.Error(t, err)
		assert.Zero(t, admin.ID)
		assert.Contains(t, err.Error(), "query error")

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ScanError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		admin := models.User{}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		mock.ExpectPrepare("SELECT id, password FROM User WHERE login = 'SuperAdmin'").ExpectQuery().WillReturnRows(row)

		stmt, err := db.Prepare("SELECT id, password FROM User WHERE login = 'SuperAdmin'")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_SUPER_ADMIN").Return(stmt, true)

		err = userRepo.GetSuperAdmin(&admin)
		assert.Error(t, err)
		assert.Zero(t, admin.ID)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestGetUsersByIds(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		ids := []int32{1, 2}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		rows := sqlmock.NewRows([]string{"id", "role_id", "login", "name", "is_active", "created_at", "updated_at", "role_key", "role_value"}).
			AddRow(1, 1, "admin", "admin", true, time.Now().Unix(), time.Now().Unix(), "admin", "Админ").
			AddRow(2, 2, "user", "user", true, time.Now().Unix(), time.Now().Unix(), "user", "Пользователь")

		mock.ExpectPrepare("SELECT .* FROM User WHERE id = ANY\\(\\$1\\)").ExpectQuery().WithArgs(pq.Array([]int32{1, 2})).WillReturnRows(rows)

		stmt, err := db.Prepare("SELECT * FROM User WHERE id = ANY($1)")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_USERS_BY_IDS").Return(stmt, true)

		users, err := userRepo.GetUsersByIds(ids)
		assert.NoError(t, err)
		assert.Len(t, users, 2)
		assert.Equal(t, 1, users[0].ID)
		assert.Equal(t, 2, users[1].ID)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()
		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		mockDB.On("GetQuery", "GET_USERS_BY_IDS").Return(nil, false)

		users, err := userRepo.GetUsersByIds([]int32{})
		assert.Error(t, err)
		assert.Len(t, users, 0)
		assert.Contains(t, err.Error(), "запрос GET_USERS_BY_IDS не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("QueryError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("SELECT .* FROM User WHERE id = ANY\\(\\$1\\)").ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare("SELECT * FROM User WHERE id = ANY($1)")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_USERS_BY_IDS").Return(stmt, true)

		users, err := userRepo.GetUsersByIds([]int32{})
		assert.Error(t, err)
		assert.Len(t, users, 0)
		assert.Contains(t, err.Error(), "query error")

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ScanError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		userRepo := &DefaultUserRepository{
			Database: mockDB,
		}

		ids := []int32{1, 2}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		mock.ExpectPrepare("SELECT .* FROM User WHERE id = ANY\\(\\$1\\)").ExpectQuery().WithArgs(pq.Array([]int32{1, 2})).WillReturnRows(row)

		stmt, err := db.Prepare("SELECT * FROM User WHERE id = ANY($1)")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_USERS_BY_IDS").Return(stmt, true)

		users, err := userRepo.GetUsersByIds(ids)
		assert.Error(t, err)
		assert.Len(t, users, 0)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
