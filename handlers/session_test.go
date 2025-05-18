package handlers

import (
	"context"
	"database/sql"
	"errors"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"testing"
	"time"
	"user-service/mocks"
	"user-service/models"
	"user-service/proto/userpb"
)

func TestLogout(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Parallel()

		mockSessionRepo := new(mocks.SessionRepository)

		mockSessionRepo.On("DeleteSession", "session-hash").Return(nil)

		server := UserServiceServer{
			Logic: &UserServiceLogic{
				SessionRepo: mockSessionRepo,
			},
			Logger: log.New(io.Discard, "", 0),
		}

		res, err := server.Logout(context.Background(), &userpb.LogoutRequest{Hash: "session-hash"})
		assert.NoError(t, err)
		assert.Equal(t, &userpb.Empty{}, res)

		mockSessionRepo.AssertExpectations(t)
	})

	t.Run("Error", func(t *testing.T) {
		t.Parallel()

		mockSessionRepo := new(mocks.SessionRepository)

		mockSessionRepo.On("DeleteSession", "session-hash").Return(errors.New("db error"))

		server := UserServiceServer{
			Logic: &UserServiceLogic{
				SessionRepo: mockSessionRepo,
			},
			Logger: log.New(io.Discard, "", 0),
		}

		res, err := server.Logout(context.Background(), &userpb.LogoutRequest{Hash: "session-hash"})
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "db error")

		mockSessionRepo.AssertExpectations(t)
	})
}

func TestGetSession(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Parallel()

		mockSessionRepo := new(mocks.SessionRepository)

		mockSessionRepo.On("GetSession", "session-hash").Return(&models.Session{
			Hash: "session-hash",
			User: models.User{
				ID: 1,
				Role: models.Role{
					ID:    1,
					Key:   "admin",
					Value: "Админ",
				},
				Login:     "admin",
				Name:      "admin",
				IsActive:  true,
				CreatedAt: time.Now().Unix(),
				UpdatedAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true},
			},
			CreatedAt: time.Now().Unix(),
		})

		server := UserServiceServer{
			Logic: &UserServiceLogic{
				SessionRepo: mockSessionRepo,
			},
		}

		res, err := server.GetSession(context.Background(), &userpb.GetSessionRequest{Hash: "session-hash"})
		assert.NoError(t, err)
		assert.Equal(t, "session-hash", res.Session.Hash)
		assert.Equal(t, int32(1), res.Session.User.Id)
		assert.True(t, res.Exist)

		mockSessionRepo.AssertExpectations(t)
	})

	t.Run("Error", func(t *testing.T) {
		t.Parallel()

		mockSessionRepo := new(mocks.SessionRepository)

		mockSessionRepo.On("GetSession", "session-hash").Return(nil)

		server := UserServiceServer{
			Logic: &UserServiceLogic{
				SessionRepo: mockSessionRepo,
			},
		}

		res, err := server.GetSession(context.Background(), &userpb.GetSessionRequest{Hash: "session-hash"})
		assert.NoError(t, err)
		assert.Equal(t, &userpb.Session{}, res.Session)
		assert.False(t, res.Exist)

		mockSessionRepo.AssertExpectations(t)
	})
}
