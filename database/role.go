package database

import (
	"errors"
	"user-service/models"
)

type RoleRepository interface {
	GetRoles() ([]models.Role, error)
	GetRole(role *models.Role) error
}

type DefaultRoleRepository struct {
	Database Database
}

func NewRoleRepository(db Database) RoleRepository {
	return &DefaultRoleRepository{
		Database: db,
	}
}

func (r *DefaultRoleRepository) GetRole(role *models.Role) error {
	stmt, ok := r.Database.GetQuery("GET_ROLE")
	if !ok {
		return errors.New("запрос GET_ROLE не подготовлен")
	}

	if err := stmt.QueryRow(role.ID, role.Key).Scan(&role.ID, &role.Key, &role.Value); err != nil {
		return err
	}

	return nil
}

func (r *DefaultRoleRepository) GetRoles() ([]models.Role, error) {
	stmt, ok := r.Database.GetQuery("GET_ROLES")
	if !ok {
		return nil, errors.New("запрос GET_ROLES не подготовлен")
	}

	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []models.Role

	for rows.Next() {
		var role models.Role

		if err = rows.Scan(
			&role.ID,
			&role.Key,
			&role.Value,
		); err != nil {
			return nil, err
		}

		roles = append(roles, role)
	}

	return roles, nil
}
