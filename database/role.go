package database

import (
	"errors"
	"user-service/models"
	"user-service/utils"
)

type RoleRepository interface {
	GetRoles() ([]models.Role, error)
	GetRole(role *models.Role) error
}

type DefaultRoleRepository struct{}

func prepareRole() []string {
	errorsList := make([]string, 0)

	if err := prepareQuery("GET_ROLES", `SELECT * FROM "Role" ORDER BY id`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	if err := prepareQuery("GET_ROLE", `SELECT id, value FROM "Role" WHERE key = $1`); err != nil {
		errorsList = append(errorsList, err.Error())
	}

	return errorsList
}

func (r *DefaultRoleRepository) GetRole(role *models.Role) error {
	stmt, ok := query["GET_ROLE"]
	if !ok {
		err := errors.New("запрос GET_ROLE не подготовлен")
		utils.Logger.Println(err)
		return err
	}

	if err := stmt.QueryRow(role.Key).Scan(&role.ID, &role.Value); err != nil {
		utils.Logger.Println(err)
		return err
	}

	return nil
}

func (r *DefaultRoleRepository) GetRoles() ([]models.Role, error) {
	stmt, ok := query["GET_ROLES"]
	if !ok {
		err := errors.New("запрос GET_ROLES не подготовлен")
		utils.Logger.Println(err)
		return nil, err
	}

	rows, err := stmt.Query()
	if err != nil {
		utils.Logger.Println(err)
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
			utils.Logger.Println(err)
			return nil, err
		}

		roles = append(roles, role)
	}

	return roles, nil
}
