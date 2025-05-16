package database

import (
	"database/sql"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	testifyMock "github.com/stretchr/testify/mock"
	"io"
	"log"
	"testing"
	"time"
	"user-service/mocks"
	"user-service/models"
	"user-service/utils"
)

func TestGetUsers(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	originQuery := query
	origLogger := utils.Logger
	defer func() {
		query = originQuery
		utils.Logger = origLogger
	}()
	query = make(map[string]*sql.Stmt)
	utils.Logger = log.New(io.Discard, "", 0)

	expectPrepareQuery := mock.ExpectPrepare("SELECT .* FROM User")

	var stmt *sql.Stmt
	stmt, err = db.Prepare("SELECT * FROM User")
	assert.NoError(t, err)

	userRepo := &DefaultUserRepository{}

	t.Run("Success", func(t *testing.T) {
		rows := mock.NewRows([]string{
			"id", "role_id", "login", "name", "is_active", "created_at", "updated_at", "role_key", "role_value",
		}).AddRow(
			1, 1, "admin", "Administrator", true, time.Now().Unix(), time.Now().Unix(), "admin", "Админ",
		).AddRow(
			1, 1, "user", "User", false, time.Now().Unix(), time.Now().Unix(), "user", "Пользователь",
		)

		expectPrepareQuery.ExpectQuery().WillReturnRows(rows)

		query["GET_USERS"] = stmt

		users, err := userRepo.GetUsers()
		assert.NoError(t, err)
		assert.Len(t, users, 2)
		assert.Equal(t, "admin", users[0].Login)
		assert.Equal(t, "user", users[1].Login)
		assert.Equal(t, true, users[0].IsActive)
		assert.Equal(t, false, users[1].IsActive)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		query = make(map[string]*sql.Stmt)

		users, err := userRepo.GetUsers()
		assert.Error(t, err)
		assert.Nil(t, users)
		assert.Contains(t, err.Error(), "запрос GET_USERS не подготовлен")
	})

	t.Run("QueryError", func(t *testing.T) {
		expectPrepareQuery.ExpectQuery().WillReturnError(errors.New("query error"))

		query["GET_USERS"] = stmt

		users, err := userRepo.GetUsers()
		assert.Error(t, err)
		assert.Nil(t, users)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		expectPrepareQuery.ExpectQuery().WillReturnRows(rows)

		query["GET_USERS"] = stmt

		users, err := userRepo.GetUsers()
		assert.Error(t, err)
		assert.Nil(t, users)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	originQuery := query
	origLogger := utils.Logger
	defer func() {
		query = originQuery
		utils.Logger = origLogger
	}()
	query = make(map[string]*sql.Stmt)
	utils.Logger = log.New(io.Discard, "", 0)

	expectPrepareQuery := mock.ExpectPrepare("SELECT .* FROM User WHERE id = \\$1")

	var stmt *sql.Stmt
	stmt, err = db.Prepare("SELECT * FROM User WHERE id = $1")
	assert.NoError(t, err)

	userRepo := &DefaultUserRepository{}

	t.Run("Success", func(t *testing.T) {
		user := models.User{ID: 1}

		rows := sqlmock.NewRows([]string{
			"role_id", "login", "name", "baned", "created_at", "updated_at", "role_value", "role_translate_value",
		}).AddRow(
			1, "admin", "Administrator", false, time.Now().Unix(), time.Now().Unix(), "admin", "Админ",
		)

		expectPrepareQuery.ExpectQuery().WithArgs(1).WillReturnRows(rows)

		query["GET_USER"] = stmt

		err = userRepo.GetUser(&user)
		assert.NoError(t, err)
		assert.Equal(t, "admin", user.Login)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		user := models.User{ID: 1}

		query = make(map[string]*sql.Stmt)

		err = userRepo.GetUser(&user)
		assert.Error(t, err)
		assert.Equal(t, "", user.Login)
		assert.Contains(t, err.Error(), "запрос GET_USER не подготовлен")
	})

	t.Run("QueryError", func(t *testing.T) {
		user := models.User{ID: 1}

		expectPrepareQuery.ExpectQuery().WithArgs(1).WillReturnError(errors.New("query error"))

		query["GET_USER"] = stmt

		err = userRepo.GetUser(&user)
		assert.Error(t, err)
		assert.Equal(t, "", user.Login)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		user := models.User{ID: 1}

		rows := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		expectPrepareQuery.ExpectQuery().WillReturnRows(rows)

		query["GET_USER"] = stmt

		err = userRepo.GetUser(&user)
		assert.Equal(t, "", user.Login)
		assert.Error(t, err)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestChangeStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	originQuery := query
	origLogger := utils.Logger
	defer func() {
		query = originQuery
		utils.Logger = origLogger
	}()
	query = make(map[string]*sql.Stmt)
	utils.Logger = log.New(io.Discard, "", 0)

	expectPrepareQuery := mock.ExpectPrepare("UPDATE User SET is_active = !is_active WHERE id = \\$1")

	var stmt *sql.Stmt
	stmt, err = db.Prepare("UPDATE User SET is_active = !is_active WHERE id = $1")
	assert.NoError(t, err)

	userRepo := &DefaultUserRepository{}

	t.Run("Success", func(t *testing.T) {
		user := models.User{ID: 1}

		rows := sqlmock.NewRows([]string{"is_active"}).AddRow(false)

		expectPrepareQuery.ExpectQuery().WithArgs(1).WillReturnRows(rows)

		query["CHANGE_USER_STATUS"] = stmt

		err = userRepo.ChangeStatus(&user)
		assert.NoError(t, err)
		assert.Equal(t, false, user.IsActive)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		user := models.User{ID: 1}

		query = make(map[string]*sql.Stmt)

		err = userRepo.ChangeStatus(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос CHANGE_USER_STATUS не подготовлен")
	})

	t.Run("QueryError", func(t *testing.T) {
		user := models.User{ID: 1}

		expectPrepareQuery.ExpectQuery().WithArgs(1).WillReturnError(errors.New("query error"))

		query["CHANGE_USER_STATUS"] = stmt

		err = userRepo.ChangeStatus(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		user := models.User{ID: 1}

		rows := sqlmock.NewRows([]string{"is_active"}).AddRow(nil)

		expectPrepareQuery.ExpectQuery().WithArgs(1).WillReturnRows(rows)

		query["CHANGE_USER_STATUS"] = stmt

		err = userRepo.ChangeStatus(&user)
		assert.Error(t, err)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestEditUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	originQuery := query
	origLogger := utils.Logger
	defer func() {
		query = originQuery
		utils.Logger = origLogger
	}()
	query = make(map[string]*sql.Stmt)
	utils.Logger = log.New(io.Discard, "", 0)

	expectPrepareExec := mock.ExpectPrepare("UPDATE User SET role_id = \\$2, login = \\$3, name = \\$4, updated_at = \\$5 WHERE id = \\$1")

	var stmt *sql.Stmt
	stmt, err = db.Prepare("UPDATE User SET role_id = $2, login = $3, name = $4, updated_at = $5 WHERE id = $1")
	assert.NoError(t, err)

	userRepo := &DefaultUserRepository{}

	t.Run("Success", func(t *testing.T) {
		user := models.User{
			ID:        1,
			Role:      models.Role{ID: 1},
			Login:     "user",
			Name:      "user",
			UpdatedAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
		}

		expectPrepareExec.ExpectExec().WithArgs(
			1, 1, "user", "user", sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
		).WillReturnResult(sqlmock.NewResult(1, 1))

		query["EDIT_USER"] = stmt

		err = userRepo.EditUser(&user)
		assert.NoError(t, err)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		user := models.User{}

		query = make(map[string]*sql.Stmt)

		err = userRepo.EditUser(&user)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос EDIT_USER не подготовлен")
	})

	t.Run("ExecError", func(t *testing.T) {
		user := models.User{
			ID:        1,
			Role:      models.Role{ID: 1},
			Login:     "user",
			Name:      "user",
			UpdatedAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
		}

		expectPrepareExec.ExpectExec().WithArgs(
			1, 1, "user", "user", sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
		).WillReturnError(errors.New("exec error"))

		query["EDIT_USER"] = stmt

		err = userRepo.EditUser(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exec error")
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	originQuery := query
	origLogger := utils.Logger
	defer func() {
		query = originQuery
		utils.Logger = origLogger
	}()
	query = make(map[string]*sql.Stmt)
	utils.Logger = log.New(io.Discard, "", 0)

	expectPrepareQuery := mock.ExpectPrepare("INSERT INTO User \\(role_id, login, name, password, created_at\\) VALUES \\(\\$1, \\$2, \\$3, \\$4, \\$5\\) RETURNING id")

	var stmt *sql.Stmt
	stmt, err = db.Prepare("INSERT INTO User (role_id, login, name, password, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id")
	assert.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		user := models.User{
			Role:      models.Role{ID: 1},
			Login:     "user",
			Name:      "user",
			Password:  "password",
			CreatedAt: time.Now().Unix(),
		}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		rows := sqlmock.NewRows([]string{"id"}).AddRow(1)

		expectPrepareQuery.ExpectQuery().WithArgs(
			1, "user", "user", "encrypted-pass", time.Now().Unix(),
		).WillReturnRows(rows)

		query["CREATE_USER"] = stmt

		err = userRepo.CreateUser(&user)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.ID)
		assert.Equal(t, "encrypted-pass", user.Password)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		user := models.User{}

		userRepo := &DefaultUserRepository{}

		query = make(map[string]*sql.Stmt)

		err = userRepo.CreateUser(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос CREATE_USER не подготовлен")
	})

	t.Run("EncryptError", func(t *testing.T) {
		user := models.User{Password: "password"}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("", errors.New("encrypt error"))

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		query["CREATE_USER"] = stmt

		err = userRepo.CreateUser(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encrypt error")
	})

	t.Run("QueryError", func(t *testing.T) {
		user := models.User{
			Role:      models.Role{ID: 1},
			Login:     "user",
			Name:      "user",
			Password:  "password",
			CreatedAt: time.Now().Unix(),
		}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		expectPrepareQuery.ExpectQuery().WithArgs(
			1, "user", "user", "encrypted-pass", time.Now().Unix(),
		).WillReturnError(errors.New("query error"))

		query["CREATE_USER"] = stmt

		err = userRepo.CreateUser(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		user := models.User{
			Role:      models.Role{ID: 1},
			Login:     "user",
			Name:      "user",
			Password:  "password",
			CreatedAt: time.Now().Unix(),
		}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		rows := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		expectPrepareQuery.ExpectQuery().WithArgs(
			1, "user", "user", "encrypted-pass", time.Now().Unix(),
		).WillReturnRows(rows)

		query["CREATE_USER"] = stmt

		err = userRepo.CreateUser(&user)
		assert.Error(t, err)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	originQuery := query
	origLogger := utils.Logger
	defer func() {
		query = originQuery
		utils.Logger = origLogger
	}()
	query = make(map[string]*sql.Stmt)
	utils.Logger = log.New(io.Discard, "", 0)

	expectPrepareQuery := mock.ExpectPrepare("SELECT .* FROM User WHERE login = \\$1 AND password = \\$2")

	var stmt *sql.Stmt
	stmt, err = db.Prepare("SELECT * FROM User WHERE login = $1 AND password = $2")
	assert.NoError(t, err)

	t.Run("SuccessfulLogin", func(t *testing.T) {
		user := models.User{
			Login:    "user",
			Password: "password",
		}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		rows := sqlmock.NewRows([]string{
			"id", "role_id", "name", "is_active", "created_at", "updated_at", "role_value", "role_translate_value",
		}).AddRow(
			2, 2, "user", true, time.Now().Unix(), nil, "user", "Пользователь",
		)

		expectPrepareQuery.ExpectQuery().WithArgs("user", "encrypted-pass").WillReturnRows(rows)

		query["GET_AUTHORIZED_USER"] = stmt

		err = userRepo.Login(&user)
		assert.NoError(t, err)
		assert.Equal(t, 2, user.ID)
		assert.Equal(t, "user", user.Name)
	})

	t.Run("UnsuccessfulLogin", func(t *testing.T) {
		user := models.User{
			Login:    "user",
			Password: "password",
		}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		rows := sqlmock.NewRows([]string{
			"id", "role_id", "name", "baned", "created_at", "updated_at", "role_value", "role_translate_value",
		})

		expectPrepareQuery.ExpectQuery().WithArgs("user", "encrypted-pass").WillReturnRows(rows)

		query["GET_AUTHORIZED_USER"] = stmt

		err = userRepo.Login(&user)
		assert.NoError(t, err)
		assert.Equal(t, 0, user.ID)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		user := models.User{}

		userRepo := &DefaultUserRepository{}

		query = make(map[string]*sql.Stmt)

		err = userRepo.Login(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос GET_AUTHORIZED_USER не подготовлен")
	})

	t.Run("EncryptError", func(t *testing.T) {
		user := models.User{Password: "password"}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("", errors.New("encrypt error"))

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		query["GET_AUTHORIZED_USER"] = stmt

		err = userRepo.Login(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encrypt error")
	})

	t.Run("QueryError", func(t *testing.T) {
		user := models.User{
			Login:    "user",
			Password: "password",
		}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		expectPrepareQuery.ExpectQuery().WillReturnError(errors.New("query error"))

		query["GET_AUTHORIZED_USER"] = stmt

		err = userRepo.Login(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		user := models.User{
			Login:    "user",
			Password: "password",
		}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		rows := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		expectPrepareQuery.ExpectQuery().WithArgs("user", "encrypted-pass").WillReturnRows(rows)

		query["GET_AUTHORIZED_USER"] = stmt

		err = userRepo.Login(&user)
		assert.Error(t, err)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestChangeUserPassword(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	originQuery := query
	origLogger := utils.Logger
	defer func() {
		query = originQuery
		utils.Logger = origLogger
	}()
	query = make(map[string]*sql.Stmt)
	utils.Logger = log.New(io.Discard, "", 0)

	expectPrepareQuery := mock.ExpectPrepare("UPDATE User SET password = \\$2 WHERE id = \\$1")

	var stmt *sql.Stmt
	stmt, err = db.Prepare("UPDATE User SET password = $2 WHERE id = $1")
	assert.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		user := models.User{ID: 1, Password: "new-pass"}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		expectPrepareQuery.ExpectExec().WithArgs(1, "encrypted-pass").WillReturnResult(sqlmock.NewResult(1, 1))

		query["CHANGE_USER_PASSWORD"] = stmt

		err = userRepo.ChangeUserPassword(&user)
		assert.NoError(t, err)
		assert.Equal(t, "encrypted-pass", user.Password)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		user := models.User{}

		userRepo := &DefaultUserRepository{}

		query = make(map[string]*sql.Stmt)

		err = userRepo.ChangeUserPassword(&user)
		assert.Error(t, err)
		assert.Equal(t, "", user.Password)
		assert.Contains(t, err.Error(), "запрос CHANGE_USER_PASSWORD не подготовлен")
	})

	t.Run("EncryptError", func(t *testing.T) {
		user := models.User{ID: 1, Password: "new-pass"}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("", errors.New("encrypt error"))

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		query["CHANGE_USER_PASSWORD"] = stmt

		err = userRepo.ChangeUserPassword(&user)
		assert.Error(t, err)
		assert.Equal(t, "", user.Password)
		assert.Contains(t, err.Error(), "encrypt error")
	})

	t.Run("ExecError", func(t *testing.T) {
		user := models.User{ID: 1, Password: "new-pass"}

		mockHasher := new(mocks.Hasher)
		mockHasher.On("Encrypt", testifyMock.AnythingOfType("string")).Return("encrypted-pass", nil)

		userRepo := &DefaultUserRepository{
			Hasher: mockHasher,
		}

		expectPrepareQuery.ExpectExec().WithArgs(1, "encrypted-pass").WillReturnError(errors.New("exec error"))

		query["CHANGE_USER_PASSWORD"] = stmt

		err = userRepo.ChangeUserPassword(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exec error")
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetSuperAdmin(t *testing.T) {
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

	expectePrepareQuery := mock.ExpectPrepare("SELECT id, password FROM User WHERE login = 'SuperAdmin'")

	var stmt *sql.Stmt
	stmt, err = db.Prepare("SELECT id, password FROM User WHERE login = 'SuperAdmin'")
	assert.NoError(t, err)

	userRepo := &DefaultUserRepository{}

	t.Run("Success", func(t *testing.T) {
		admin := models.User{}

		rows := sqlmock.NewRows([]string{
			"id", "password",
		}).AddRow(
			1, "encrypted-pass",
		)

		expectePrepareQuery.ExpectQuery().WillReturnRows(rows)

		query["GET_SUPER_ADMIN"] = stmt

		err = userRepo.GetSuperAdmin(&admin)
		assert.NoError(t, err)
		assert.Equal(t, 1, admin.ID)
		assert.Equal(t, "encrypted-pass", admin.Password)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		admin := models.User{}

		query = make(map[string]*sql.Stmt)

		err = userRepo.GetSuperAdmin(&admin)
		assert.Error(t, err)
		assert.Equal(t, 0, admin.ID)
		assert.Contains(t, err.Error(), "запрос GET_SUPER_ADMIN не подготовлен")
	})

	t.Run("QueryError", func(t *testing.T) {
		admin := models.User{}

		expectePrepareQuery.ExpectQuery().WillReturnError(errors.New("query error"))

		query["GET_SUPER_ADMIN"] = stmt

		err = userRepo.GetSuperAdmin(&admin)
		assert.Error(t, err)
		assert.Equal(t, 0, admin.ID)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		admin := models.User{}

		rows := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		expectePrepareQuery.ExpectQuery().WillReturnRows(rows)

		query["GET_SUPER_ADMIN"] = stmt

		err = userRepo.GetSuperAdmin(&admin)
		assert.Error(t, err)
		assert.Equal(t, 0, admin.ID)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}
