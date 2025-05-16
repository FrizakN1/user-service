package database

//
//import (
//	"database/sql"
//	"errors"
//	"github.com/DATA-DOG/go-sqlmock"
//	"github.com/stretchr/testify/assert"
//	testifyMock "github.com/stretchr/testify/mock"
//	"io"
//	"log"
//	"testing"
//	"time"
//	"user-service/utils"
//)
//
//func TestDeleteSession(t *testing.T) {
//	db, mock, err := sqlmock.New()
//	assert.NoError(t, err)
//	defer db.Close()
//
//	originQuery := query
//	origLogger := utils.Logger
//	originSessionMap := sessionMap
//	defer func() {
//		query = originQuery
//		utils.Logger = origLogger
//		sessionMap = originSessionMap
//	}()
//	query = make(map[string]*sql.Stmt)
//	sessionMap = make(map[string]Session)
//	utils.Logger = log.New(io.Discard, "", 0)
//
//	expectPrepareQuery := "DELETE FROM Session WHERE hash = \\$1"
//	_prepareQuery := "DELETE FROM Session WHERE hash = $1"
//
//	t.Run("Success", func(t *testing.T) {
//		session := Session{Hash: "hash"}
//
//		mock.ExpectPrepare(expectPrepareQuery).
//			ExpectExec().WithArgs("hash").
//			WillReturnResult(sqlmock.NewResult(1, 1))
//
//		stmt, err := db.Prepare(_prepareQuery)
//		assert.NoError(t, err)
//		query["DELETE_SESSION"] = stmt
//		sessionMap["hash"] = session
//
//		err = DeleteSession(&session)
//		assert.NoError(t, err)
//	})
//
//	t.Run("QueryNotPrepare", func(t *testing.T) {
//		session := Session{}
//
//		query = make(map[string]*sql.Stmt)
//
//		err := DeleteSession(&session)
//		assert.Error(t, err)
//		assert.Contains(t, err.Error(), "запрос DELETE_SESSION не подготовлен")
//	})
//
//	t.Run("ExecError", func(t *testing.T) {
//		session := Session{}
//
//		mock.ExpectPrepare(expectPrepareQuery).
//			ExpectExec().WillReturnError(errors.New("exec error"))
//
//		stmt, err := db.Prepare(_prepareQuery)
//		assert.NoError(t, err)
//		query["DELETE_SESSION"] = stmt
//
//		err = DeleteSession(&session)
//		assert.Error(t, err)
//		assert.Contains(t, err.Error(), "exec error")
//	})
//
//	assert.NoError(t, mock.ExpectationsWereMet())
//}
//
//type MockHasher struct {
//	testifyMock.Mock
//}
//
//func (m *MockHasher) GenerateHash(value string) (string, error) {
//	args := m.Called(value)
//	return args.String(0), args.Error(1)
//}
//
//func TestCreateSession(t *testing.T) {
//	db, mock, err := sqlmock.New()
//	assert.NoError(t, err)
//	defer db.Close()
//
//	hashMock := &MockHashGenerator{}
//
//	originQuery := query
//	origLogger := utils.Logger
//	originSessionMap := sessionMap
//	defer func() {
//		query = originQuery
//		utils.Logger = origLogger
//		sessionMap = originSessionMap
//	}()
//	query = make(map[string]*sql.Stmt)
//	sessionMap = make(map[string]Session)
//	utils.Logger = log.New(io.Discard, "", 0)
//
//	user := User{
//		ID:    1,
//		Login: "admin",
//	}
//
//	expectPrepareQuery := "INSERT INTO Session \\(hash, user_id, created_at\\) VALUES \\(\\$1, \\$2, \\$3\\)"
//	_prepareQuery := "INSERT INTO Session (hash, user_id, created_at) VALUES ($1, $2, $3)"
//
//	t.Run("Success", func(t *testing.T) {
//		hashMock.On("GenerateHash", testifyMock.AnythingOfType("string")).
//			Return("test-hash", nil).Once()
//
//		mock.ExpectPrepare(expectPrepareQuery).
//			ExpectExec().WithArgs("test-hash", 1, time.Now().Unix()).WillReturnResult(sqlmock.NewResult(1, 1))
//
//		stmt, err := db.Prepare(_prepareQuery)
//		assert.NoError(t, err)
//		query["CREATE_SESSION"] = stmt
//
//		hash, err := CreateSessionWithHashFunc(user, hashMock)
//		assert.NoError(t, err)
//		assert.Equal(t, "test-hash", hash)
//
//		session, exists := sessionMap["test-hash"]
//		assert.True(t, exists)
//		assert.Equal(t, "test-hash", session.Hash)
//		assert.Equal(t, user.ID, session.User.ID)
//
//		hashMock.AssertExpectations(t)
//	})
//
//	t.Run("QueryNotPrepare", func(t *testing.T) {
//		query = make(map[string]*sql.Stmt)
//
//		hash, err := CreateSession(user)
//		assert.Error(t, err)
//		assert.Contains(t, err.Error(), "запрос CREATE_SESSION не подготовлен")
//		assert.Empty(t, hash)
//	})
//
//	t.Run("GenerateHashError", func(t *testing.T) {
//		hashMock.On("GenerateHash", testifyMock.AnythingOfType("string")).
//			Return("", errors.New("generate hash error")).Once()
//
//		query["CREATE_SESSION"] = &sql.Stmt{}
//
//		hash, err := CreateSessionWithHashFunc(user, hashMock)
//		assert.Error(t, err)
//		assert.Contains(t, err.Error(), "generate hash error")
//		assert.Empty(t, hash)
//
//		hashMock.AssertExpectations(t)
//	})
//
//	t.Run("ExecError", func(t *testing.T) {
//		hashMock.On("GenerateHash", testifyMock.AnythingOfType("string")).
//			Return("test-hash", nil).Once()
//
//		mock.ExpectPrepare(expectPrepareQuery).
//			ExpectExec().WithArgs("test-hash", 1, time.Now().Unix()).WillReturnError(errors.New("exec error"))
//
//		stmt, err := db.Prepare(_prepareQuery)
//		assert.NoError(t, err)
//		query["CREATE_SESSION"] = stmt
//
//		hash, err := CreateSessionWithHashFunc(user, hashMock)
//		assert.Error(t, err)
//		assert.Contains(t, err.Error(), "exec error")
//		assert.Empty(t, hash)
//
//		hashMock.AssertExpectations(t)
//	})
//
//	t.Run("NilSessionMap", func(t *testing.T) {
//		hashMock.On("GenerateHash", testifyMock.AnythingOfType("string")).
//			Return("test-hash", nil).Once()
//
//		mock.ExpectPrepare(expectPrepareQuery).
//			ExpectExec().WithArgs("test-hash", 1, time.Now().Unix()).WillReturnResult(sqlmock.NewResult(1, 1))
//
//		stmt, err := db.Prepare(_prepareQuery)
//		assert.NoError(t, err)
//		query["CREATE_SESSION"] = stmt
//
//		hash, err := CreateSessionWithHashFunc(user, hashMock)
//		assert.NoError(t, err)
//		assert.Equal(t, "test-hash", hash)
//
//		session, exists := sessionMap["test-hash"]
//		assert.True(t, exists)
//		assert.Equal(t, "test-hash", session.Hash)
//
//		hashMock.AssertExpectations(t)
//	})
//
//	assert.NoError(t, mock.ExpectationsWereMet())
//}
//
//func TestLoadSession(t *testing.T) {
//	db, mock, err := sqlmock.New()
//	assert.NoError(t, err)
//	defer db.Close()
//
//	originQuery := query
//	origLogger := utils.Logger
//	defer func() {
//		query = originQuery
//		utils.Logger = origLogger
//	}()
//	query = make(map[string]*sql.Stmt)
//	utils.Logger = log.New(io.Discard, "", 0)
//
//	expectPrepareQuery := "SELECT .* FROM Session"
//	_prepareQuery := "SELECT * FROM Session"
//
//	t.Run("Success", func(t *testing.T) {
//		sessions := make(map[string]Session)
//
//		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WillReturnRows(
//			sqlmock.NewRows([]string{"hash", "user_id", "created_at", "user_role_id", "user_login", "user_name", "user_baned", "user_created_at", "user_updated_at", "user_role_value", "user_role_translate_value"}).
//				AddRow("test-hash-1", 1, time.Now().Unix(), 1, "admin", "Administrator", false, time.Now().Unix(), nil, "admin", "Админ").
//				AddRow("test-hash-2", 2, time.Now().Unix(), 2, "user", "User", false, time.Now().Unix(), time.Now().Unix(), "user", "Пользователь"))
//
//		stmt, err := db.Prepare(_prepareQuery)
//		assert.NoError(t, err)
//		query["GET_SESSIONS"] = stmt
//
//		LoadSession(sessions)
//
//		assert.Len(t, sessions, 2)
//
//		session1, exists := sessions["test-hash-1"]
//		assert.True(t, exists)
//		assert.Equal(t, "test-hash-1", session1.Hash)
//		assert.Equal(t, 1, session1.User.ID)
//		assert.Equal(t, "admin", session1.User.Login)
//
//		session2, exists := sessions["test-hash-2"]
//		assert.True(t, exists)
//		assert.Equal(t, "test-hash-2", session2.Hash)
//		assert.Equal(t, 2, session2.User.ID)
//		assert.Equal(t, "user", session2.User.Login)
//	})
//
//	t.Run("QueryNotPrepare", func(t *testing.T) {
//		query = make(map[string]*sql.Stmt)
//		sessions := make(map[string]Session)
//
//		LoadSession(sessions)
//
//		assert.Len(t, sessions, 0)
//	})
//
//	t.Run("QueryError", func(t *testing.T) {
//		sessions := make(map[string]Session)
//
//		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WillReturnError(errors.New("query error"))
//
//		stmt, err := db.Prepare(_prepareQuery)
//		assert.NoError(t, err)
//		query["GET_SESSIONS"] = stmt
//
//		LoadSession(sessions)
//
//		assert.Len(t, sessions, 0)
//	})
//
//	t.Run("ScanError", func(t *testing.T) {
//		sessions := make(map[string]Session)
//
//		mock.ExpectPrepare(expectPrepareQuery).ExpectQuery().WillReturnRows(
//			sqlmock.NewRows([]string{"id"}).AddRow(nil))
//
//		stmt, err := db.Prepare(_prepareQuery)
//		assert.NoError(t, err)
//		query["GET_SESSIONS"] = stmt
//
//		LoadSession(sessions)
//
//		assert.Len(t, sessions, 0)
//	})
//
//	assert.NoError(t, mock.ExpectationsWereMet())
//}
