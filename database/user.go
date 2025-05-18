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
	Hasher   utils.Hasher
	Database Database
}

func NewUserRepository(db Database) UserRepository {
	return &DefaultUserRepository{
		Hasher:   &utils.DefaultHasher{},
		Database: db,
	}
}

func (r *DefaultUserRepository) GetUsersByIds(ids []int32) ([]models.User, error) {
	stmt, ok := r.Database.GetQuery("GET_USERS_BY_IDS")
	if !ok {
		return nil, errors.New("запрос GET_USERS_BY_IDS не подготовлен")
	}

	rows, err := stmt.Query(pq.Array(ids))
	if err != nil {
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
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func (r *DefaultUserRepository) ChangeStatus(user *models.User) error {
	stmt, ok := r.Database.GetQuery("CHANGE_USER_STATUS")
	if !ok {
		return errors.New("запрос CHANGE_USER_STATUS не подготовлен")
	}

	if err := stmt.QueryRow(user.ID).Scan(&user.IsActive); err != nil {
		return err
	}

	return nil
}

func (r *DefaultUserRepository) GetUser(user *models.User) error {
	stmt, ok := r.Database.GetQuery("GET_USER")
	if !ok {
		err := errors.New("запрос GET_USER не подготовлен")
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
		return err
	}

	return nil
}

func (r *DefaultUserRepository) GetUsers() ([]models.User, error) {
	stmt, ok := r.Database.GetQuery("GET_USERS")
	if !ok {
		return nil, errors.New("запрос GET_USERS не подготовлен")
	}

	rows, err := stmt.Query()
	if err != nil {
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
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func (r *DefaultUserRepository) EditUser(user *models.User) error {
	stmt, ok := r.Database.GetQuery("EDIT_USER")
	if !ok {
		return errors.New("запрос EDIT_USER не подготовлен")
	}

	_, err := stmt.Exec(
		user.ID,
		user.Role.ID,
		user.Login,
		user.Name,
		user.UpdatedAt,
	)
	if err != nil {
		return err
	}

	return nil
}

func (r *DefaultUserRepository) CreateUser(user *models.User) error {
	stmt, ok := r.Database.GetQuery("CREATE_USER")
	if !ok {
		return errors.New("запрос CREATE_USER не подготовлен")
	}

	var err error

	user.Password, err = r.Hasher.Encrypt(user.Password)
	if err != nil {
		return err
	}

	if err = stmt.QueryRow(
		user.Role.ID,
		user.Login,
		user.Name,
		user.Password,
		user.CreatedAt,
	).Scan(&user.ID); err != nil {
		return err
	}

	return nil
}

func (r *DefaultUserRepository) Login(user *models.User) error {
	stmt, ok := r.Database.GetQuery("GET_AUTHORIZED_USER")
	if !ok {
		return errors.New("запрос GET_AUTHORIZED_USER не подготовлен")
	}

	var err error

	user.Password, err = r.Hasher.Encrypt(user.Password)
	if err != nil {
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
		return err
	}

	return nil
}

func (r *DefaultUserRepository) ChangeUserPassword(user *models.User) error {
	stmt, ok := r.Database.GetQuery("CHANGE_USER_PASSWORD")
	if !ok {
		return errors.New("запрос CHANGE_USER_PASSWORD не подготовлен")
	}

	var err error

	user.Password, err = r.Hasher.Encrypt(user.Password)
	if err != nil {
		return err
	}

	_, e := stmt.Exec(user.ID, user.Password)
	if e != nil {
		return e
	}

	return nil
}

func (r *DefaultUserRepository) GetSuperAdmin(admin *models.User) error {
	stmt, ok := r.Database.GetQuery("GET_SUPER_ADMIN")
	if !ok {
		return errors.New("запрос GET_SUPER_ADMIN не подготовлен")
	}

	if err := stmt.QueryRow().Scan(&admin.ID, &admin.Password); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	return nil
}
