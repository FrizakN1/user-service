package database

import (
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	testifyMock "github.com/stretchr/testify/mock"
	"testing"
	"time"
	"user-service/mocks"
	"user-service/models"
)

func TestDeleteSession(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database:   mockDB,
			sessionMap: make(map[string]models.Session),
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		hash := "session-hash"
		sessionRepo.sessionMap[hash] = models.Session{Hash: hash}

		mock.ExpectPrepare("DELETE FROM Session WHERE hash = \\$1").ExpectExec().WithArgs("session-hash").WillReturnResult(sqlmock.NewResult(1, 1))

		stmt, err := db.Prepare("DELETE FROM Session WHERE hash = $1")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "DELETE_SESSION").Return(stmt, true)

		err = sessionRepo.DeleteSession(hash)
		assert.NoError(t, err)

		session, ok := sessionRepo.sessionMap[hash]
		assert.False(t, ok)
		assert.Equal(t, models.Session{}, session)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database: mockDB,
		}

		mockDB.On("GetQuery", "DELETE_SESSION").Return(nil, false)

		err := sessionRepo.DeleteSession("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос DELETE_SESSION не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("ExecError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database:   mockDB,
			sessionMap: make(map[string]models.Session),
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("DELETE FROM Session WHERE hash = \\$1").ExpectExec().WillReturnError(errors.New("exec error"))

		stmt, err := db.Prepare("DELETE FROM Session WHERE hash = $1")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "DELETE_SESSION").Return(stmt, true)

		err = sessionRepo.DeleteSession("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exec error")

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestGetSession(t *testing.T) {
	t.Parallel()

	sessionRepo := &DefaultSessionRepository{
		sessionMap: map[string]models.Session{
			"session-hash": models.Session{Hash: "session-hash", User: models.User{ID: 1}},
		},
	}

	t.Run("SessionFound", func(t *testing.T) {
		hash := "session-hash"

		session := sessionRepo.GetSession(hash)
		assert.Equal(t, 1, session.User.ID)
	})

	t.Run("SessionNotFound", func(t *testing.T) {
		hash := "not-exist-session-hash"

		session := sessionRepo.GetSession(hash)
		assert.Nil(t, session)
	})
}

func TestCreateSession(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		sessionRepo := &DefaultSessionRepository{
			Database:   mockDB,
			sessionMap: make(map[string]models.Session),
			Hasher:     mockHasher,
		}

		user := models.User{ID: 1}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("INSERT INTO Session \\(hash, user_id, created_at\\) VALUES \\(\\$1, \\$2, \\$3\\)").ExpectExec().
			WithArgs("session-hash", 1, time.Now().Unix()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		stmt, err := db.Prepare("INSERT INTO Session (hash, user_id, created_at) VALUES ($1, $2, $3)")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "CREATE_SESSION").Return(stmt, true)
		mockHasher.On("GenerateHash", testifyMock.AnythingOfType("string")).Return("session-hash", nil)

		hash, err := sessionRepo.CreateSession(&user)
		assert.NoError(t, err)
		assert.Equal(t, "session-hash", hash)

		session, ok := sessionRepo.sessionMap["session-hash"]
		assert.True(t, ok)
		assert.Equal(t, "session-hash", session.Hash)
		assert.Equal(t, user.ID, session.User.ID)

		mockHasher.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database: mockDB,
		}

		user := models.User{}

		mockDB.On("GetQuery", "CREATE_SESSION").Return(nil, false)

		hash, err := sessionRepo.CreateSession(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос CREATE_SESSION не подготовлен")
		assert.Empty(t, hash)

		mockDB.AssertExpectations(t)
	})

	t.Run("GenerateHashError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		sessionRepo := &DefaultSessionRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("INSERT INTO Session \\(hash, user_id, created_at\\) VALUES \\(\\$1, \\$2, \\$3\\)")

		stmt, err := db.Prepare("INSERT INTO Session (hash, user_id, created_at) VALUES ($1, $2, $3)")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "CREATE_SESSION").Return(stmt, true)
		mockHasher.On("GenerateHash", testifyMock.AnythingOfType("string")).Return("", errors.New("generate hash error"))

		hash, err := sessionRepo.CreateSession(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "generate hash error")
		assert.Empty(t, hash)

		mockHasher.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ExecError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		mockHasher := new(mocks.Hasher)
		sessionRepo := &DefaultSessionRepository{
			Database: mockDB,
			Hasher:   mockHasher,
		}

		user := models.User{ID: 1}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("INSERT INTO Session \\(hash, user_id, created_at\\) VALUES \\(\\$1, \\$2, \\$3\\)").ExpectExec().WillReturnError(errors.New("exec error"))

		stmt, err := db.Prepare("INSERT INTO Session (hash, user_id, created_at) VALUES ($1, $2, $3)")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "CREATE_SESSION").Return(stmt, true)
		mockHasher.On("GenerateHash", testifyMock.AnythingOfType("string")).Return("session-hash", nil)

		hash, err := sessionRepo.CreateSession(&user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exec error")
		assert.Empty(t, hash)

		mockHasher.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestLoadSession(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database:   mockDB,
			sessionMap: make(map[string]models.Session),
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		rows := sqlmock.NewRows([]string{"hash", "user_id", "created_at", "user_role_id", "user_login", "user_name", "user_is_active", "user_created_at", "user_updated_at", "user_role_key", "user_role_value"}).
			AddRow("session-hash-1", 1, time.Now().Unix(), 1, "admin", "Administrator", true, time.Now().Unix(), nil, "admin", "Админ").
			AddRow("session-hash-2", 2, time.Now().Unix(), 2, "user", "User", true, time.Now().Unix(), time.Now().Unix(), "user", "Пользователь")

		mock.ExpectPrepare("SELECT s.*, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value FROM Session AS s JOIN User AS u ON u.id = s.user_id JOIN Role AS r ON r.id = u.role_id").
			ExpectQuery().WillReturnRows(rows)

		stmt, err := db.Prepare("SELECT s.*, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value FROM Session AS s JOIN User AS u ON u.id = s.user_id JOIN Role AS r ON r.id = u.role_id")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_SESSIONS").Return(stmt, true)

		err = sessionRepo.LoadSession()
		assert.NoError(t, err)
		assert.Len(t, sessionRepo.sessionMap, 2)

		session, ok := sessionRepo.sessionMap["session-hash-1"]
		assert.True(t, ok)
		assert.Equal(t, "session-hash-1", session.Hash)
		assert.Equal(t, 1, session.User.ID)
		assert.Equal(t, "admin", session.User.Login)

		session, ok = sessionRepo.sessionMap["session-hash-2"]
		assert.True(t, ok)
		assert.Equal(t, "session-hash-2", session.Hash)
		assert.Equal(t, 2, session.User.ID)
		assert.Equal(t, "user", session.User.Login)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database:   mockDB,
			sessionMap: make(map[string]models.Session),
		}

		mockDB.On("GetQuery", "GET_SESSIONS").Return(nil, false)

		err := sessionRepo.LoadSession()
		assert.Error(t, err)
		assert.Len(t, sessionRepo.sessionMap, 0)
		assert.Contains(t, err.Error(), "запрос GET_SESSIONS не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("QueryError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database:   mockDB,
			sessionMap: make(map[string]models.Session),
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("SELECT s.*, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value FROM Session AS s JOIN User AS u ON u.id = s.user_id JOIN Role AS r ON r.id = u.role_id").
			ExpectQuery().WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare("SELECT s.*, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value FROM Session AS s JOIN User AS u ON u.id = s.user_id JOIN Role AS r ON r.id = u.role_id")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_SESSIONS").Return(stmt, true)

		err = sessionRepo.LoadSession()
		assert.Error(t, err)
		assert.Len(t, sessionRepo.sessionMap, 0)
		assert.Contains(t, err.Error(), "query error")

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ScanError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database:   mockDB,
			sessionMap: make(map[string]models.Session),
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"id"}).AddRow(nil)

		mock.ExpectPrepare("SELECT s.*, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value FROM Session AS s JOIN User AS u ON u.id = s.user_id JOIN Role AS r ON r.id = u.role_id").ExpectQuery().WillReturnRows(row)

		stmt, err := db.Prepare("SELECT s.*, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value FROM Session AS s JOIN User AS u ON u.id = s.user_id JOIN Role AS r ON r.id = u.role_id")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "GET_SESSIONS").Return(stmt, true)

		err = sessionRepo.LoadSession()
		assert.Error(t, err)
		assert.Len(t, sessionRepo.sessionMap, 0)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestDeleteUserSessions(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database: mockDB,
			sessionMap: map[string]models.Session{
				"session-hash-1": models.Session{
					Hash: "session-hash-1",
				},
				"session-hash-2": models.Session{
					Hash: "session-hash-2",
				},
			},
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		rows := sqlmock.NewRows([]string{"hash"}).
			AddRow("session-hash-1").
			AddRow("session-hash-2")

		mock.ExpectPrepare("DELETE FROM Session WHERE user_id = \\$1 RETURNING hash").ExpectQuery().WithArgs(1).WillReturnRows(rows)

		stmt, err := db.Prepare("DELETE FROM Session WHERE user_id = $1 RETURNING hash")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "DELETE_USER_SESSIONS").Return(stmt, true)

		err = sessionRepo.DeleteUserSessions(1)
		assert.NoError(t, err)

		session, ok := sessionRepo.sessionMap["session-hash-1"]
		assert.False(t, ok)
		assert.Equal(t, models.Session{}, session)

		session, ok = sessionRepo.sessionMap["session-hash-2"]
		assert.False(t, ok)
		assert.Equal(t, models.Session{}, session)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("QueryNotPrepare", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database: mockDB,
		}

		mockDB.On("GetQuery", "DELETE_USER_SESSIONS").Return(nil, false)

		err := sessionRepo.DeleteUserSessions(1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "запрос DELETE_USER_SESSIONS не подготовлен")

		mockDB.AssertExpectations(t)
	})

	t.Run("QueryError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database: mockDB,
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		mock.ExpectPrepare("DELETE FROM Session WHERE user_id = \\$1 RETURNING hash").ExpectQuery().WithArgs(1).WillReturnError(errors.New("query error"))

		stmt, err := db.Prepare("DELETE FROM Session WHERE user_id = $1 RETURNING hash")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "DELETE_USER_SESSIONS").Return(stmt, true)

		err = sessionRepo.DeleteUserSessions(1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query error")

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ScanError", func(t *testing.T) {
		t.Parallel()

		mockDB := new(mocks.Database)
		sessionRepo := &DefaultSessionRepository{
			Database: mockDB,
		}

		db, mock, err := sqlmock.New()
		assert.NoError(t, err)
		defer db.Close()

		row := sqlmock.NewRows([]string{"hash"}).AddRow(nil)

		mock.ExpectPrepare("DELETE FROM Session WHERE user_id = \\$1 RETURNING hash").ExpectQuery().WithArgs(1).WillReturnRows(row)

		stmt, err := db.Prepare("DELETE FROM Session WHERE user_id = $1 RETURNING hash")
		assert.NoError(t, err)

		mockDB.On("GetQuery", "DELETE_USER_SESSIONS").Return(stmt, true)

		err = sessionRepo.DeleteUserSessions(1)
		assert.Error(t, err)

		mockDB.AssertExpectations(t)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
