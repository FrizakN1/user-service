package database

import (
	"errors"
	"fmt"
	"time"
	"user-service/models"
	"user-service/utils"
)

type SessionRepository interface {
	DeleteSession(hash string) error
	GetSession(hash string) *models.Session
	CreateSession(user *models.User) (string, error)
	LoadSession() error
	DeleteUserSessions(userID int) error
}

type DefaultSessionRepository struct {
	Hasher     utils.Hasher
	Database   Database
	sessionMap map[string]models.Session
}

func NewSessionRepository(db Database) SessionRepository {
	return &DefaultSessionRepository{
		Hasher:   &utils.DefaultHasher{},
		Database: db,
	}
}

func (r *DefaultSessionRepository) DeleteSession(hash string) error {
	stmt, ok := r.Database.GetQuery("DELETE_SESSION")
	if !ok {
		return errors.New("запрос DELETE_SESSION не подготовлен")
	}

	_, e := stmt.Exec(hash)
	if e != nil {
		return e
	}

	delete(r.sessionMap, hash)

	return nil
}

func (r *DefaultSessionRepository) GetSession(hash string) *models.Session {
	session, ok := r.sessionMap[hash]
	if ok {
		return &session
	}

	return nil
}

func (r *DefaultSessionRepository) CreateSession(user *models.User) (string, error) {
	stmt, ok := r.Database.GetQuery("CREATE_SESSION")
	if !ok {
		return "", errors.New("запрос CREATE_SESSION не подготовлен")
	}

	hash, err := r.Hasher.GenerateHash(fmt.Sprintf("%s-%d", user.Login, time.Now().Unix()))
	if err != nil {
		return "", err
	}

	if _, err = stmt.Exec(hash, user.ID, time.Now().Unix()); err != nil {
		return "", err
	}

	r.sessionMap[hash] = models.Session{
		Hash:      hash,
		User:      *user,
		CreatedAt: time.Now().Unix(),
	}

	return hash, nil
}

func (r *DefaultSessionRepository) LoadSession() error {
	r.sessionMap = make(map[string]models.Session)

	stmt, ok := r.Database.GetQuery("GET_SESSIONS")
	if !ok {
		return errors.New("запрос GET_SESSIONS не подготовлен")
	}

	rows, err := stmt.Query()
	if err != nil {
		return err
	}

	defer rows.Close()

	for rows.Next() {
		var session models.Session

		if err = rows.Scan(
			&session.Hash,
			&session.User.ID,
			&session.CreatedAt,
			&session.User.Role.ID,
			&session.User.Login,
			&session.User.Name,
			&session.User.IsActive,
			&session.User.CreatedAt,
			&session.User.UpdatedAt,
			&session.User.Role.Key,
			&session.User.Role.Value,
		); err != nil {
			return err
		}

		r.sessionMap[session.Hash] = session
	}

	return nil
}

func (r *DefaultSessionRepository) DeleteUserSessions(userID int) error {
	stmt, ok := r.Database.GetQuery("DELETE_USER_SESSIONS")
	if !ok {
		return errors.New("запрос DELETE_USER_SESSIONS не подготовлен")
	}

	rows, err := stmt.Query(userID)
	if err != nil {
		return err
	}

	defer rows.Close()

	for rows.Next() {
		var hash string

		if err = rows.Scan(&hash); err != nil {
			return err
		}

		delete(r.sessionMap, hash)
	}

	return nil
}
