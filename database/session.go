package database

import (
	"errors"
	"fmt"
	"time"
	"user-service/models"
	"user-service/utils"
)

type SessionRepository interface {
	DeleteSession(s *models.Session) error
	GetSession(hash string) *models.Session
	CreateSession(user models.User) (string, error)
	LoadSession(m map[string]models.Session) error
	DeleteUserSessions(userID int) error
}

type DefaultSessionRepository struct {
	Hasher utils.Hasher
}

var sessionMap map[string]models.Session

func prepareSession() []string {
	errorsList := make([]string, 0)

	if err := prepareQuery("GET_SESSIONS", `
		SELECT s.*, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value
		FROM "Session" AS s
		JOIN "User" AS u ON u.id = s.user_id
		JOIN "Role" AS r ON r.id = u.role_id
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("CREATE_SESSION", `
		INSERT INTO "Session" (hash, user_id, created_at) VALUES ($1, $2, $3)
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("DELETE_SESSION", `
		DELETE FROM "Session" WHERE hash = $1
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("GET_USER_SESSIONS", `
		SELECT hash FROM "Session" WHERE user_id = $1
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	return errorsList
}

func (r *DefaultSessionRepository) DeleteSession(s *models.Session) error {
	stmt, ok := query["DELETE_SESSION"]
	if !ok {
		return errors.New("запрос DELETE_SESSION не подготовлен")
	}

	_, e := stmt.Exec(s.Hash)
	if e != nil {
		return e
	}

	delete(sessionMap, s.Hash)

	return nil
}

func (r *DefaultSessionRepository) GetSession(hash string) *models.Session {
	session, ok := sessionMap[hash]
	if ok {
		return &session
	}

	return nil
}

func (r *DefaultSessionRepository) CreateSession(user models.User) (string, error) {
	stmt, ok := query["CREATE_SESSION"]
	if !ok {
		err := errors.New("запрос CREATE_SESSION не подготовлен")
		utils.Logger.Println(err)
		return "", err
	}

	hash, err := r.Hasher.GenerateHash(fmt.Sprintf("%s-%d", user.Login, time.Now().Unix()))
	if err != nil {
		utils.Logger.Println(err)
		return "", err
	}

	if _, err = stmt.Exec(hash, user.ID, time.Now().Unix()); err != nil {
		utils.Logger.Println(err)
		return "", err
	}

	sessionMap[hash] = models.Session{
		Hash:      hash,
		User:      user,
		CreatedAt: time.Now().Unix(),
	}

	return hash, nil
}

func (r *DefaultSessionRepository) LoadSession(m map[string]models.Session) error {
	stmt, ok := query["GET_SESSIONS"]
	if !ok {
		err := errors.New("запрос GET_SESSIONS не подготовлен")
		return err
	}

	rows, err := stmt.Query()
	if err != nil {
		utils.Logger.Println(err)
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
			utils.Logger.Println(err)
			return err
		}

		m[session.Hash] = session
	}

	return nil
}

func (r *DefaultSessionRepository) DeleteUserSessions(userID int) error {
	stmt, ok := query["GET_USER_SESSIONS"]
	if !ok {
		return errors.New("запрос GET_USER_SESSIONS не подготовлен")
	}

	rows, e := stmt.Query(userID)
	if e != nil {
		return e
	}

	defer rows.Close()

	for rows.Next() {
		var session models.Session
		e = rows.Scan(&session.Hash)
		if e != nil {
			return e
		}

		if e = r.DeleteSession(&session); e != nil {
			utils.Logger.Println(e)
			return e
		}
	}

	return nil
}
