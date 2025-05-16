package database

import (
	"database/sql"
	"errors"
	"github.com/lib/pq"
	"user-service/models"
	"user-service/utils"
)

type UserRepository interface {
	ChangeStatus(user *models.User) error
	GetUser(user *models.User) error
	GetUsers() ([]models.User, error)
	EditUser(user *models.User) error
	CreateUser(user *models.User) error
	Login(user *models.User) error
	ChangeUserPassword(user *models.User) error
	GetUsersByIds(ids []int32) ([]models.User, error)
	GetSuperAdmin(admin *models.User) error
}

type DefaultUserRepository struct {
	Hasher      utils.Hasher
	SessionRepo SessionRepository
	RoleRepo    RoleRepository
}

func prepareUsers() []string {
	errorsList := make([]string, 0)

	if err := prepareQuery("GET_USERS", `
		SELECT u.id, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value
		FROM "User" AS u
		JOIN "Role" AS r ON r.id = u.role_id
		ORDER BY u.id
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("GET_USERS_BY_IDS", `
		SELECT u.id, u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value
		FROM "User" AS u
		JOIN "Role" AS r ON r.id = u.role_id
		WHERE u.id = ANY($1)
		ORDER BY u.id
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("GET_USER", `
		SELECT u.role_id, u.login, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value
		FROM "User" AS u
		JOIN "Role" AS r ON r.id = u.role_id
		WHERE u.id = $1
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("CREATE_USER", `
		INSERT INTO "User"(role_id, login, name, password, created_at) 
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("EDIT_USER", `
		UPDATE "User" SET role_id = $2, login = $3, name = $4, updated_at = $5
		WHERE id = $1
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("GET_AUTHORIZED_USER", `
		SELECT u.id, u.role_id, u.name, u.is_active, u.created_at, u.updated_at, r.key, r.value
		FROM "User" AS u
		JOIN "Role" AS r ON r.id = u.role_id
		WHERE login = $1 AND password = $2
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("CHANGE_USER_PASSWORD", `
		UPDATE "User" SET password = $2 WHERE id = $1
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("GET_SUPER_ADMIN", `
		SELECT id, password FROM "User" WHERE login = 'SuperAdmin'
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("CHANGE_USER_STATUS", `
		UPDATE "User" SET is_active = NOT is_active WHERE id = $1
		RETURNING is_active
	`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	return errorsList
}

func (r *DefaultUserRepository) GetUsersByIds(ids []int32) ([]models.User, error) {
	stmt, ok := query["GET_USERS_BY_IDS"]
	if !ok {
		err := errors.New("запрос GET_USERS_BY_IDS не подготовлен")
		utils.Logger.Println(err)
		return nil, err
	}

	rows, err := stmt.Query(pq.Array(ids))
	if err != nil {
		utils.Logger.Println(err)
		return nil, err
	}

	var users []models.User

	for rows.Next() {
		var user models.User

		if err = rows.Scan(
			&user.ID,
			&user.Role.ID,
			&user.Login,
			&user.Name,
			&user.IsActive,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.Role.Key,
			&user.Role.Value,
		); err != nil {
			utils.Logger.Println(err)
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func (r *DefaultUserRepository) ChangeStatus(user *models.User) error {
	stmt, ok := query["CHANGE_USER_STATUS"]
	if !ok {
		err := errors.New("запрос CHANGE_USER_STATUS не подготовлен")
		utils.Logger.Println(err)
		return err
	}

	if err := stmt.QueryRow(user.ID).Scan(&user.IsActive); err != nil {
		utils.Logger.Println(err)
		return err
	}

	return nil
}

func (r *DefaultUserRepository) GetUser(user *models.User) error {
	stmt, ok := query["GET_USER"]
	if !ok {
		err := errors.New("запрос GET_USER не подготовлен")
		utils.Logger.Println(err)
		return err
	}

	if err := stmt.QueryRow(user.ID).Scan(
		&user.Role.ID,
		&user.Login,
		&user.Name,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.Role.Key,
		&user.Role.Value,
	); err != nil {
		utils.Logger.Println(err)
		return err
	}

	return nil
}

func (r *DefaultUserRepository) GetUsers() ([]models.User, error) {
	stmt, ok := query["GET_USERS"]
	if !ok {
		err := errors.New("запрос GET_USERS не подготовлен")
		utils.Logger.Println(err)
		return nil, err
	}

	rows, err := stmt.Query()
	if err != nil {
		utils.Logger.Println(err)
		return nil, err
	}

	defer rows.Close()

	var users []models.User

	for rows.Next() {
		var user models.User

		if err = rows.Scan(
			&user.ID,
			&user.Role.ID,
			&user.Login,
			&user.Name,
			&user.IsActive,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.Role.Key,
			&user.Role.Value,
		); err != nil {
			utils.Logger.Println(err)
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func (r *DefaultUserRepository) EditUser(user *models.User) error {
	stmt, ok := query["EDIT_USER"]
	if !ok {
		err := errors.New("запрос EDIT_USER не подготовлен")
		utils.Logger.Println(err)
		return err
	}

	_, err := stmt.Exec(
		user.ID,
		user.Role.ID,
		user.Login,
		user.Name,
		user.UpdatedAt,
	)
	if err != nil {
		utils.Logger.Println(err)
		return err
	}

	return nil
}

func (r *DefaultUserRepository) CreateUser(user *models.User) error {
	stmt, ok := query["CREATE_USER"]
	if !ok {
		err := errors.New("запрос CREATE_USER не подготовлен")
		utils.Logger.Println(err)
		return err
	}

	var err error

	user.Password, err = r.Hasher.Encrypt(user.Password)
	if err != nil {
		utils.Logger.Println(err)
		return err
	}

	if err = stmt.QueryRow(
		user.Role.ID,
		user.Login,
		user.Name,
		user.Password,
		user.CreatedAt,
	).Scan(&user.ID); err != nil {
		utils.Logger.Println(err)
		return err
	}

	return nil
}

func (r *DefaultUserRepository) Login(user *models.User) error {
	stmt, ok := query["GET_AUTHORIZED_USER"]
	if !ok {
		err := errors.New("запрос GET_AUTHORIZED_USER не подготовлен")
		utils.Logger.Println(err)
		return err
	}

	var err error

	user.Password, err = r.Hasher.Encrypt(user.Password)
	if err != nil {
		utils.Logger.Println(err)
		return err
	}

	if err = stmt.QueryRow(user.Login, user.Password).Scan(
		&user.ID,
		&user.Role.ID,
		&user.Name,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.Role.Key,
		&user.Role.Value,
	); err != nil && !errors.Is(err, sql.ErrNoRows) {
		utils.Logger.Println(err)
		return err
	}

	return nil
}

func (r *DefaultUserRepository) ChangeUserPassword(user *models.User) error {
	stmt, ok := query["CHANGE_USER_PASSWORD"]
	if !ok {
		return errors.New("запрос CHANGE_USER_PASSWORD не подготовлен")
	}

	var err error

	user.Password, err = r.Hasher.Encrypt(user.Password)
	if err != nil {
		utils.Logger.Println(err)
		return err
	}

	_, e := stmt.Exec(user.ID, user.Password)
	if e != nil {
		return e
	}

	return nil
}

func (r *DefaultUserRepository) GetSuperAdmin(admin *models.User) error {
	stmt, ok := query["GET_SUPER_ADMIN"]
	if !ok {
		err := errors.New("запрос GET_SUPER_ADMIN не подготовлен")
		utils.Logger.Println(err)
		return err
	}

	if err := stmt.QueryRow().Scan(&admin.ID, &admin.Password); err != nil && !errors.Is(err, sql.ErrNoRows) {
		utils.Logger.Println(err)
		return err
	}

	return nil
}

func NewUserRepository() UserRepository {
	return &DefaultUserRepository{
		Hasher:      &utils.DefaultHasher{},
		RoleRepo:    &DefaultRoleRepository{},
		SessionRepo: &DefaultSessionRepository{},
	}
}
