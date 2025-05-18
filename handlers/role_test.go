package handlers

import (
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"testing"
	"user-service/mocks"
	"user-service/models"
	"user-service/proto/userpb"
)

func TestGetRoles(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockRoleRepo := new(mocks.RoleRepository)

		mockRoleRepo.On("GetRoles").Return([]models.Role{
			{ID: 1, Key: "admin", Value: "Администратор"},
			{ID: 2, Key: "user", Value: "Пользователь"},
		}, nil)

		server := &UserServiceServer{
			Logic: &UserServiceLogic{
				RoleRepo: mockRoleRepo,
			},
			Logger: log.New(io.Discard, "", 0),
		}

		res, err := server.GetRoles(context.Background(), &userpb.Empty{})

		assert.NoError(t, err)
		assert.Len(t, res.Roles, 2)

		assert.Equal(t, int32(1), res.Roles[0].Id)
		assert.Equal(t, "admin", res.Roles[0].Key)
		assert.Equal(t, "Администратор", res.Roles[0].Value)

		assert.Equal(t, int32(2), res.Roles[1].Id)
		assert.Equal(t, "user", res.Roles[1].Key)
		assert.Equal(t, "Пользователь", res.Roles[1].Value)

		mockRoleRepo.AssertExpectations(t)
	})

	t.Run("Error", func(t *testing.T) {
		t.Parallel()

		mockRoleRepo := new(mocks.RoleRepository)

		mockRoleRepo.On("GetRoles").Return(nil, errors.New("db error"))

		server := &UserServiceServer{
			Logic: &UserServiceLogic{
				RoleRepo: mockRoleRepo,
			},
			Logger: log.New(io.Discard, "", 0),
		}

		res, err := server.GetRoles(context.Background(), &userpb.Empty{})
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "db error")

		mockRoleRepo.AssertExpectations(t)
	})
}
