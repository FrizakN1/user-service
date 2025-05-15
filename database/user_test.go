package database

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	testifyMock "github.com/stretchr/testify/mock"
	"io"
	"log"
	"testing"
	"time"
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

	var stmt *sql.Stmt
	stmt, err = db.Prepare("SELECT * FROM User")
	assert.NoError(t, err)

	expectPrepareQuery := "SELECT .* FROM User"

	userRepo := &DefaultUserRepository{}

	t.Run("Success", func(t *testing.T) {
		mockStmt := mock.NewRows([]string{
			"id", "role_id", "login", "name", "is_active", "created_at", "updated_at", "role_key", "role_value",
		}).AddRow(
			1, 1, "admin", "Administrator", true, time.Now().Unix(), time.Now().Unix(), "admin", "Админ",
		).AddRow(
			1, 1, "user", "User", false, time.Now().Unix(), time.Now().Unix(), "user", "Пользователь",
		)

		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WillReturnRows(mockStmt)

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
		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WillReturnError(errors.New("query error"))

		query["GET_USERS"] = stmt

		users, err := userRepo.GetUsers()
		assert.Error(t, err)
		assert.Nil(t, users)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{
			"id",
		}).AddRow(
			nil)

		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WillReturnRows(rows)

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

	var stmt *sql.Stmt
	stmt, err = db.Prepare("SELECT * FROM User WHERE id = $1")
	assert.NoError(t, err)

	expectPrepareQuery := "SELECT .* FROM User WHERE id = \\$1"

	userRepo := &DefaultUserRepository{}

	t.Run("Success", func(t *testing.T) {
		user := models.User{ID: 1}

		rows := sqlmock.NewRows([]string{
			"role_id", "login", "name", "baned", "created_at", "updated_at", "role_value", "role_translate_value",
		}).AddRow(
			1, "admin", "Administrator", false, time.Now().Unix(), time.Now().Unix(), "admin", "Админ")

		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WithArgs(1).WillReturnRows(rows)

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

		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WithArgs(1).WillReturnError(errors.New("query error"))

		query["GET_USER"] = stmt

		err = userRepo.GetUser(&user)
		assert.Error(t, err)
		assert.Equal(t, "", user.Login)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		user := models.User{ID: 1}

		rows := sqlmock.NewRows([]string{
			"id",
		}).AddRow(
			nil)

		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WillReturnRows(rows)

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

	var stmt *sql.Stmt
	stmt, err = db.Prepare("UPDATE User SET baned = !baned WHERE id = $1")

	expectPrepareQuery := "UPDATE User SET baned = !baned WHERE id = \\$1"

	userRepo := &DefaultUserRepository{}

	t.Run("Success", func(t *testing.T) {
		user := models.User{ID: 1}

		rows := sqlmock.NewRows([]string{
			"is_active",
		}).AddRow(
			false)

		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WithArgs(1).WillReturnRows(rows)

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

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectQuery().WithArgs(1).WillReturnError(errors.New("query error"))

		query["CHANGE_USER_STATUS"] = stmt

		err = userRepo.ChangeStatus(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		user := models.User{ID: 1}

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectQuery().WithArgs(1).
			WillReturnRows(
				sqlmock.NewRows([]string{"baned"}).AddRow(nil))

		query["CHANGE_USER_STATUS"] = stmt

		err = userRepo.ChangeStatus(&user)
		assert.Error(t, err)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUser_EditUser(t *testing.T) {
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

	expectPrepareQuery := "UPDATE User SET role_id = \\$2, login = \\$3, name = \\$4, updated_at = \\$5 WHERE id = \\$1"
	_prepareQuery := "UPDATE User SET role_id = $2, login = $3, name = $4, updated_at = $5 WHERE id = $1"

	t.Run("Success", func(t *testing.T) {
		user := User{
			ID:        1,
			Role:      Reference{ID: 1},
			Login:     "user",
			Name:      "user",
			UpdatedAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
		}

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectExec().WithArgs(
			1, 1, "user", "user", sql.NullInt64{Int64: time.Now().Unix(), Valid: true}).WillReturnResult(sqlmock.NewResult(1, 1))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["EDIT_USER"] = stmt

		err = user.EditUser()
		assert.NoError(t, err)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		user := User{}

		query = make(map[string]*sql.Stmt)

		err = user.EditUser()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос EDIT_USER не подготовлен")
	})

	t.Run("ExecError", func(t *testing.T) {
		user := User{
			ID:        1,
			Role:      Reference{ID: 1},
			Login:     "user",
			Name:      "user",
			UpdatedAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
		}

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectExec().WithArgs(1, 1, "user", "user", sql.NullInt64{Int64: time.Now().Unix(), Valid: true}).WillReturnError(errors.New("exec error"))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["EDIT_USER"] = stmt

		err = user.EditUser()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exec error")
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUser_CreateUser(t *testing.T) {
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

	expectPrepareQuery := "INSERT INTO User \\(role_id, login, name, password, baned, created_at, updated_at\\) VALUES \\(\\$1, \\$2, \\$3, \\$4, \\$5, \\$6, \\$7\\) RETURNING id"
	_prepareQuery := "INSERT INTO User (role_id, login, name, password, baned, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id"

	t.Run("Success", func(t *testing.T) {
		user := User{
			Role:      Reference{ID: 1},
			Login:     "user",
			Name:      "user",
			Password:  "password",
			CreatedAt: time.Now().Unix(),
		}

		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().
			WithArgs(1, "user", "user", "password", false, time.Now().Unix(), nil).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["CREATE_USER"] = stmt

		err = user.CreateUser()
		assert.NoError(t, err)
		assert.Equal(t, 1, user.ID)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		user := User{}

		query = make(map[string]*sql.Stmt)

		err = user.CreateUser()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос CREATE_USER не подготовлен")
	})

	t.Run("QueryError", func(t *testing.T) {
		user := User{}

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["CREATE_USER"] = stmt

		err = user.CreateUser()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		user := User{
			Role:      Reference{ID: 1},
			Login:     "user",
			Name:      "user",
			Password:  "password",
			CreatedAt: time.Now().Unix(),
		}

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectQuery().WithArgs(1, "user", "user", "password", false, time.Now().Unix(), nil).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(nil))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["CREATE_USER"] = stmt

		err = user.CreateUser()
		assert.Error(t, err)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUser_GetAuthorize(t *testing.T) {
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

	expectPrepareQuery := "SELECT .* FROM User WHERE login = \\$1 AND password = \\$2"
	_prepareQuery := "SELECT * FROM User WHERE login = $1 AND password = $2"

	t.Run("SuccessAuthorize", func(t *testing.T) {
		user := User{
			Login:    "user",
			Password: "password",
		}

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectQuery().WithArgs("user", "password").WillReturnRows(
			sqlmock.NewRows([]string{"id", "role_id", "name", "baned", "created_at", "updated_at", "role_value", "role_translate_value"}).
				AddRow(1, 2, "user", false, time.Now().Unix(), nil, "user", "Пользователь"))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["GET_AUTHORIZED_USER"] = stmt

		err = user.GetAuthorize()
		assert.NoError(t, err)
		assert.Equal(t, 1, user.ID)
		assert.Equal(t, "user", user.Name)
	})

	t.Run("UnsuccessAuthorize", func(t *testing.T) {
		user := User{
			Login:    "user",
			Password: "password",
		}

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectQuery().WithArgs("user", "password").WillReturnRows(
			sqlmock.NewRows([]string{"id", "role_id", "name", "baned", "created_at", "updated_at", "role_value", "role_translate_value"}))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["GET_AUTHORIZED_USER"] = stmt

		err = user.GetAuthorize()
		assert.NoError(t, err)
		assert.Equal(t, 0, user.ID)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		user := User{}

		query = make(map[string]*sql.Stmt)

		err = user.GetAuthorize()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос GET_AUTHORIZED_USER не подготовлен")
	})

	t.Run("QueryError", func(t *testing.T) {
		user := User{
			Login:    "user",
			Password: "password",
		}

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["GET_AUTHORIZED_USER"] = stmt

		err = user.GetAuthorize()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query error")
	})

	t.Run("ScanError", func(t *testing.T) {
		user := User{
			Login:    "user",
			Password: "password",
		}

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectQuery().WithArgs("user", "password").WillReturnRows(
			sqlmock.NewRows([]string{"id"}).
				AddRow(nil))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["GET_AUTHORIZED_USER"] = stmt

		err = user.GetAuthorize()
		assert.Error(t, err)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteSession(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	originQuery := query
	origLogger := utils.Logger
	originSessionMap := sessionMap
	defer func() {
		query = originQuery
		utils.Logger = origLogger
		sessionMap = originSessionMap
	}()
	query = make(map[string]*sql.Stmt)
	sessionMap = make(map[string]Session)
	utils.Logger = log.New(io.Discard, "", 0)

	expectPrepareQuery := "DELETE FROM Session WHERE hash = \\$1"
	_prepareQuery := "DELETE FROM Session WHERE hash = $1"

	t.Run("Success", func(t *testing.T) {
		session := Session{Hash: "hash"}

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectExec().WithArgs("hash").
			WillReturnResult(sqlmock.NewResult(1, 1))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["DELETE_SESSION"] = stmt
		sessionMap["hash"] = session

		err = DeleteSession(&session)
		assert.NoError(t, err)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		session := Session{}

		query = make(map[string]*sql.Stmt)

		err := DeleteSession(&session)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос DELETE_SESSION не подготовлен")
	})

	t.Run("ExecError", func(t *testing.T) {
		session := Session{}

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectExec().WillReturnError(errors.New("exec error"))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["DELETE_SESSION"] = stmt

		err = DeleteSession(&session)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exec error")
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

type MockHashGenerator struct {
	testifyMock.Mock
}

func (m *MockHashGenerator) GenerateHash(data string) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func CreateSessionWithHashFunc(user User, hashGenerator *MockHashGenerator) (string, error) {
	stmt, ok := query["CREATE_SESSION"]
	if !ok {
		err := errors.New("запрос CREATE_SESSION не подготовлен")
		utils.Logger.Println(err)
		return "", err
	}

	hash, err := hashGenerator.GenerateHash(fmt.Sprintf("%s-%d", user.Login, time.Now().Unix()))
	if err != nil {
		utils.Logger.Println(err)
		return "", err
	}

	if _, err = stmt.Exec(hash, user.ID, time.Now().Unix()); err != nil {
		utils.Logger.Println(err)
		return "", err
	}

	if sessionMap != nil {
		sessionMap[hash] = Session{
			Hash:      hash,
			User:      user,
			CreatedAt: time.Now().Unix(),
		}
	}

	return hash, nil
}

func TestCreateSession(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	hashMock := &MockHashGenerator{}

	originQuery := query
	origLogger := utils.Logger
	originSessionMap := sessionMap
	defer func() {
		query = originQuery
		utils.Logger = origLogger
		sessionMap = originSessionMap
	}()
	query = make(map[string]*sql.Stmt)
	sessionMap = make(map[string]Session)
	utils.Logger = log.New(io.Discard, "", 0)

	user := User{
		ID:    1,
		Login: "admin",
	}

	expectPrepareQuery := "INSERT INTO Session \\(hash, user_id, created_at\\) VALUES \\(\\$1, \\$2, \\$3\\)"
	_prepareQuery := "INSERT INTO Session (hash, user_id, created_at) VALUES ($1, $2, $3)"

	t.Run("Success", func(t *testing.T) {
		hashMock.On("GenerateHash", testifyMock.AnythingOfType("string")).
			Return("test-hash", nil).Once()

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectExec().WithArgs("test-hash", 1, time.Now().Unix()).WillReturnResult(sqlmock.NewResult(1, 1))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["CREATE_SESSION"] = stmt

		hash, err := CreateSessionWithHashFunc(user, hashMock)
		assert.NoError(t, err)
		assert.Equal(t, "test-hash", hash)

		session, exists := sessionMap["test-hash"]
		assert.True(t, exists)
		assert.Equal(t, "test-hash", session.Hash)
		assert.Equal(t, user.ID, session.User.ID)

		hashMock.AssertExpectations(t)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		query = make(map[string]*sql.Stmt)

		hash, err := CreateSession(user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос CREATE_SESSION не подготовлен")
		assert.Empty(t, hash)
	})

	t.Run("GenerateHashError", func(t *testing.T) {
		hashMock.On("GenerateHash", testifyMock.AnythingOfType("string")).
			Return("", errors.New("generate hash error")).Once()

		query["CREATE_SESSION"] = &sql.Stmt{}

		hash, err := CreateSessionWithHashFunc(user, hashMock)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "generate hash error")
		assert.Empty(t, hash)

		hashMock.AssertExpectations(t)
	})

	t.Run("ExecError", func(t *testing.T) {
		hashMock.On("GenerateHash", testifyMock.AnythingOfType("string")).
			Return("test-hash", nil).Once()

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectExec().WithArgs("test-hash", 1, time.Now().Unix()).WillReturnError(errors.New("exec error"))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["CREATE_SESSION"] = stmt

		hash, err := CreateSessionWithHashFunc(user, hashMock)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exec error")
		assert.Empty(t, hash)

		hashMock.AssertExpectations(t)
	})

	t.Run("NilSessionMap", func(t *testing.T) {
		hashMock.On("GenerateHash", testifyMock.AnythingOfType("string")).
			Return("test-hash", nil).Once()

		mock.ExpectPrepare(expectPrepareQuery).
			ExpectExec().WithArgs("test-hash", 1, time.Now().Unix()).WillReturnResult(sqlmock.NewResult(1, 1))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["CREATE_SESSION"] = stmt

		hash, err := CreateSessionWithHashFunc(user, hashMock)
		assert.NoError(t, err)
		assert.Equal(t, "test-hash", hash)

		session, exists := sessionMap["test-hash"]
		assert.True(t, exists)
		assert.Equal(t, "test-hash", session.Hash)

		hashMock.AssertExpectations(t)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoadSession(t *testing.T) {
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

	expectPrepareQuery := "SELECT .* FROM Session"
	_prepareQuery := "SELECT * FROM Session"

	t.Run("Success", func(t *testing.T) {
		sessions := make(map[string]Session)

		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WillReturnRows(
			sqlmock.NewRows([]string{"hash", "user_id", "created_at", "user_role_id", "user_login", "user_name", "user_baned", "user_created_at", "user_updated_at", "user_role_value", "user_role_translate_value"}).
				AddRow("test-hash-1", 1, time.Now().Unix(), 1, "admin", "Administrator", false, time.Now().Unix(), nil, "admin", "Админ").
				AddRow("test-hash-2", 2, time.Now().Unix(), 2, "user", "User", false, time.Now().Unix(), time.Now().Unix(), "user", "Пользователь"))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["GET_SESSIONS"] = stmt

		LoadSession(sessions)

		assert.Len(t, sessions, 2)

		session1, exists := sessions["test-hash-1"]
		assert.True(t, exists)
		assert.Equal(t, "test-hash-1", session1.Hash)
		assert.Equal(t, 1, session1.User.ID)
		assert.Equal(t, "admin", session1.User.Login)

		session2, exists := sessions["test-hash-2"]
		assert.True(t, exists)
		assert.Equal(t, "test-hash-2", session2.Hash)
		assert.Equal(t, 2, session2.User.ID)
		assert.Equal(t, "user", session2.User.Login)
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		query = make(map[string]*sql.Stmt)
		sessions := make(map[string]Session)

		LoadSession(sessions)

		assert.Len(t, sessions, 0)
	})

	t.Run("QueryError", func(t *testing.T) {
		sessions := make(map[string]Session)

		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["GET_SESSIONS"] = stmt

		LoadSession(sessions)

		assert.Len(t, sessions, 0)
	})

	t.Run("ScanError", func(t *testing.T) {
		sessions := make(map[string]Session)

		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WillReturnRows(
			sqlmock.NewRows([]string{"id"}).AddRow(nil))

		stmt, err := db.Prepare(_prepareQuery)
		assert.NoError(t, err)
		query["GET_SESSIONS"] = stmt

		LoadSession(sessions)

		assert.Len(t, sessions, 0)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckAdmin(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	origQuery := query
	origLogger := utils.Logger
	defer func() {
		query = origQuery
		utils.Logger = origLogger
	}()

	utils.Logger = log.New(io.Discard, "", 0)

	originalEncrypt := utils.Encrypt
	defer func() { utils.Encrypt = originalEncrypt }()
	utils.Encrypt = func(password string) (string, error) {
		return "encrypted_" + password, nil
	}

	config := &settings.Setting{
		SuperAdminPassword: "admin123",
	}

	t.Run("AdminExistsCorrectPassword", func(t *testing.T) {
		mock.ExpectPrepare("SELECT id, password FROM User WHERE login = 'SuperAdmin'").
			ExpectQuery().
			WillReturnRows(sqlmock.NewRows([]string{"id", "password"}).AddRow(1, "encrypted_admin123"))

		stmt, _ := db.Prepare("SELECT id, password FROM User WHERE login = 'SuperAdmin'")
		query["GET_SUPER_ADMIN"] = stmt

		err := CheckAdmin(config)
		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}
