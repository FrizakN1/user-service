package database

import (
	"database/sql"
	"errors"
	"time"
	"user-service/models"
	"user-service/settings"
	"user-service/utils"
)

type UserRepository interface {
	ChangeStatus(user *models.User) error
	GetUser(user *models.User) error
	GetUsers() ([]models.User, error)
	EditUser(user *models.User) error
	CreateUser(user *models.User) error
	GetAuthorize(user *models.User) error
	ChangeUserPassword(user *models.User) error
	CreateAdmin(config *settings.Setting) error
	ValidateUser(user models.User, action string) bool
	CheckAdmin(config *settings.Setting) error
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

func (r *DefaultUserRepository) GetAuthorize(user *models.User) error {
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

func (r *DefaultUserRepository) CheckAdmin(config *settings.Setting) error {
	stmt, ok := query["GET_SUPER_ADMIN"]
	if !ok {
		err := errors.New("запрос GET_SUPER_ADMIN не подготовлен")
		utils.Logger.Println(err)
		return err
	}

	var admin models.User

	e := stmt.QueryRow().Scan(&admin.ID, &admin.Password)
	if e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			if e = r.CreateAdmin(config); e != nil {
				utils.Logger.Println(e)
				return e
			}
		} else {
			utils.Logger.Println(e)
			return e
		}
	}

	encryptPass, e := r.Hasher.Encrypt(config.SuperAdminPassword)
	if e != nil {
		utils.Logger.Println(e)
		return e
	}

	if encryptPass != admin.Password {
		admin.Password = config.SuperAdminPassword

		if e = r.ChangeUserPassword(&admin); e != nil {
			utils.Logger.Println(e)
			return e
		}

		if e = r.SessionRepo.DeleteUserSessions(admin.ID); e != nil {
			utils.Logger.Println(e)
			return e
		}
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

func (r *DefaultUserRepository) CreateAdmin(config *settings.Setting) error {
	var admin models.User

	encryptPass, e := r.Hasher.Encrypt(config.SuperAdminPassword)
	if e != nil {
		utils.Logger.Println(e)
		return e
	}

	role := models.Role{Key: "admin"}
	if err := r.RoleRepo.GetRole(&role); err != nil {
		utils.Logger.Println(err)
		return err
	}

	admin = models.User{
		Login:     "SuperAdmin",
		Name:      "SuperAdmin",
		Role:      role,
		Password:  encryptPass,
		CreatedAt: time.Now().Unix(),
	}

	if e = r.CreateUser(&admin); e != nil {
		utils.Logger.Println(e)
		return e
	}
	return nil
}

func (r *DefaultUserRepository) ValidateUser(user models.User, action string) bool {
	if len(user.Name) == 0 || len(user.Login) == 0 {
		return false
	}

	roles, err := r.RoleRepo.GetRoles()
	if err != nil {
		utils.Logger.Println(err)
		return false
	}

	validRole := false
	for _, role := range roles {
		if role.ID == user.Role.ID {
			validRole = true
			break
		}
	}

	if !validRole {
		return false
	}

	if action == "create" {
		if len(user.Password) < 6 {
			return false
		}
	} else if len(user.Password) != 0 {
		if len(user.Password) < 6 {
			return false
		}
	}

	return true
}

func NewUserRepository() UserRepository {
	return &DefaultUserRepository{
		Hasher:      &utils.DefaultHasher{},
		RoleRepo:    &DefaultRoleRepository{},
		SessionRepo: &DefaultSessionRepository{},
	}
}
