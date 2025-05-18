package handlers

import (
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io"
	"log"
	"os"
	"testing"
	"time"
	"user-service/mocks"
	"user-service/models"
	"user-service/proto/userpb"
)

func TestCreateSuperAdmin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		mockRoleRepo := new(mocks.RoleRepository)
		mockUserRepo := new(mocks.UserRepository)

		mockRoleRepo.On("GetRole", &models.Role{Key: "admin"}).Return(nil)
		mockUserRepo.On("CreateUser", &models.User{
			Login:     "SuperAdmin",
			Name:      "SuperAdmin",
			Role:      models.Role{Key: "admin"},
			Password:  os.Getenv("SUPER_ADMIN_PASSWORD"),
			CreatedAt: time.Now().Unix(),
		}).Return(nil)

		logic := &UserServiceLogic{
			RoleRepo: mockRoleRepo,
			UserRepo: mockUserRepo,
		}

		err := logic.CreateSuperAdmin()
		assert.NoError(t, err)

		mockRoleRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("ErrorGetRoles", func(t *testing.T) {
		t.Parallel()

		mockRoleRepo := new(mocks.RoleRepository)

		mockRoleRepo.On("GetRole", &models.Role{Key: "admin"}).Return(errors.New("db error"))

		logic := &UserServiceLogic{
			RoleRepo: mockRoleRepo,
			Logger:   log.New(io.Discard, "", 0),
		}

		err := logic.CreateSuperAdmin()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "db error")

		mockRoleRepo.AssertExpectations(t)
	})

	t.Run("ErrorCreateUser", func(t *testing.T) {
		t.Parallel()

		mockRoleRepo := new(mocks.RoleRepository)
		mockUserRepo := new(mocks.UserRepository)

		mockRoleRepo.On("GetRole", &models.Role{Key: "admin"}).Return(nil)
		mockUserRepo.On("CreateUser", &models.User{
			Login:     "SuperAdmin",
			Name:      "SuperAdmin",
			Role:      models.Role{Key: "admin"},
			Password:  os.Getenv("SUPER_ADMIN_PASSWORD"),
			CreatedAt: time.Now().Unix(),
		}).Return(errors.New("db error"))

		logic := &UserServiceLogic{
			RoleRepo: mockRoleRepo,
			UserRepo: mockUserRepo,
			Logger:   log.New(io.Discard, "", 0),
		}

		err := logic.CreateSuperAdmin()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "db error")

		mockRoleRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})
}

func TestCheckAdmin(t *testing.T) {
	t.Run("SuperAdminFoundWithChangePassword", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)
		mockSessionRepo := new(mocks.SessionRepository)
		mockHasher := new(mocks.Hasher)

		mockUserRepo.On("GetSuperAdmin", &models.User{}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.ID = 1
			user.Password = "old-encrypt-pass"
		}).Return(nil)
		mockUserRepo.On("ChangeUserPassword", &models.User{ID: 1, Password: os.Getenv("SUPER_ADMIN_PASSWORD")}).Return(nil)
		mockSessionRepo.On("DeleteUserSessions", 1).Return(nil)
		mockHasher.On("Encrypt", os.Getenv("SUPER_ADMIN_PASSWORD")).Return("encrypt-pass", nil)

		logic := &UserServiceLogic{
			UserRepo:    mockUserRepo,
			SessionRepo: mockSessionRepo,
			Hasher:      mockHasher,
		}

		err := logic.CheckAdmin()
		assert.NoError(t, err)

		mockUserRepo.AssertExpectations(t)
		mockSessionRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("SuperAdminFoundWithoutChangePassword", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)
		mockHasher := new(mocks.Hasher)

		mockUserRepo.On("GetSuperAdmin", &models.User{}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.ID = 1
			user.Password = "encrypt-pass"
		}).Return(nil)
		mockHasher.On("Encrypt", os.Getenv("SUPER_ADMIN_PASSWORD")).Return("encrypt-pass", nil)

		logic := &UserServiceLogic{
			UserRepo: mockUserRepo,
			Hasher:   mockHasher,
		}

		err := logic.CheckAdmin()
		assert.NoError(t, err)

		mockUserRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("SuperAdminNotFound", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)
		mockAdminCreator := new(mocks.SuperAdminCreator)

		mockUserRepo.On("GetSuperAdmin", &models.User{}).Return(nil)
		mockAdminCreator.On("CreateSuperAdmin").Return(nil)

		logic := &UserServiceLogic{
			UserRepo:     mockUserRepo,
			AdminCreator: mockAdminCreator,
		}

		err := logic.CheckAdmin()
		assert.NoError(t, err)

		mockUserRepo.AssertExpectations(t)
		mockAdminCreator.AssertExpectations(t)
	})

	t.Run("ErrorGetSuperAdmin", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)

		mockUserRepo.On("GetSuperAdmin", &models.User{}).Return(errors.New("get super admin error"))

		logic := &UserServiceLogic{
			UserRepo: mockUserRepo,
			Logger:   log.New(io.Discard, "", 0),
		}

		err := logic.CheckAdmin()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "get super admin error")

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("ErrorCreateSuperAdmin", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)
		mockAdminCreator := new(mocks.SuperAdminCreator)

		mockUserRepo.On("GetSuperAdmin", &models.User{}).Return(nil)
		mockAdminCreator.On("CreateSuperAdmin").Return(errors.New("create super admin error"))

		logic := &UserServiceLogic{
			UserRepo:     mockUserRepo,
			AdminCreator: mockAdminCreator,
			Logger:       log.New(io.Discard, "", 0),
		}

		err := logic.CheckAdmin()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "create super admin error")

		mockUserRepo.AssertExpectations(t)
		mockAdminCreator.AssertExpectations(t)
	})

	t.Run("ErrorEncrypt", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)
		mockHasher := new(mocks.Hasher)

		mockUserRepo.On("GetSuperAdmin", &models.User{}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.ID = 1
		}).Return(nil)
		mockHasher.On("Encrypt", os.Getenv("SUPER_ADMIN_PASSWORD")).Return("", errors.New("encrypt error"))

		logic := &UserServiceLogic{
			UserRepo: mockUserRepo,
			Hasher:   mockHasher,
			Logger:   log.New(io.Discard, "", 0),
		}

		err := logic.CheckAdmin()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encrypt error")

		mockUserRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("ErrorChangePassword", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)
		mockHasher := new(mocks.Hasher)

		mockUserRepo.On("GetSuperAdmin", &models.User{}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.ID = 1
			user.Password = "old-encrypt-pass"
		}).Return(nil)
		mockUserRepo.On("ChangeUserPassword", &models.User{ID: 1, Password: os.Getenv("SUPER_ADMIN_PASSWORD")}).Return(errors.New("change password error"))
		mockHasher.On("Encrypt", os.Getenv("SUPER_ADMIN_PASSWORD")).Return("encrypt-pass", nil)

		logic := &UserServiceLogic{
			UserRepo: mockUserRepo,
			Hasher:   mockHasher,
			Logger:   log.New(io.Discard, "", 0),
		}

		err := logic.CheckAdmin()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "change password error")

		mockUserRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})

	t.Run("ErrorDeleteUserSessions", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)
		mockSessionRepo := new(mocks.SessionRepository)
		mockHasher := new(mocks.Hasher)

		mockUserRepo.On("GetSuperAdmin", &models.User{}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.ID = 1
		}).Return(nil)
		mockUserRepo.On("ChangeUserPassword", &models.User{ID: 1, Password: os.Getenv("SUPER_ADMIN_PASSWORD")}).Return(nil)
		mockHasher.On("Encrypt", os.Getenv("SUPER_ADMIN_PASSWORD")).Return("encrypt-pass", nil)
		mockSessionRepo.On("DeleteUserSessions", 1).Return(errors.New("delete sessions error"))

		logic := &UserServiceLogic{
			UserRepo:    mockUserRepo,
			SessionRepo: mockSessionRepo,
			Hasher:      mockHasher,
			Logger:      log.New(io.Discard, "", 0),
		}

		err := logic.CheckAdmin()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "delete sessions error")

		mockUserRepo.AssertExpectations(t)
		mockSessionRepo.AssertExpectations(t)
		mockHasher.AssertExpectations(t)
	})
}

func TestChangeUserStatus(t *testing.T) {
	t.Run("SuccessBan", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)
		mockSessionRepo := new(mocks.SessionRepository)

		mockUserRepo.On("ChangeStatus", &models.User{ID: 1}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.IsActive = false
		}).Return(nil)
		mockSessionRepo.On("DeleteUserSessions", 1).Return(nil)

		server := &UserServiceServer{
			Logic: &UserServiceLogic{
				UserRepo:    mockUserRepo,
				SessionRepo: mockSessionRepo,
			},
		}

		res, err := server.ChangeUserStatus(context.Background(), &userpb.ChangeUserStatusRequest{Id: int32(1)})
		assert.NoError(t, err)
		assert.False(t, res.IsActive)

		mockUserRepo.AssertExpectations(t)
		mockSessionRepo.AssertExpectations(t)
	})

	t.Run("SuccessUnban", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)

		mockUserRepo.On("ChangeStatus", &models.User{ID: 1}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.IsActive = true
		}).Return(nil)

		server := &UserServiceServer{
			Logic: &UserServiceLogic{
				UserRepo: mockUserRepo,
			},
		}

		res, err := server.ChangeUserStatus(context.Background(), &userpb.ChangeUserStatusRequest{Id: int32(1)})
		assert.NoError(t, err)
		assert.True(t, res.IsActive)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("ErrorChangeStatus", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)

		mockUserRepo.On("ChangeStatus", &models.User{ID: 1}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.IsActive = false
		}).Return(errors.New("change status error"))

		server := &UserServiceServer{
			Logic: &UserServiceLogic{
				UserRepo: mockUserRepo,
			},
			Logger: log.New(io.Discard, "", 0),
		}

		res, err := server.ChangeUserStatus(context.Background(), &userpb.ChangeUserStatusRequest{Id: int32(1)})
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "change status error")

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("ErrorDeleteUserSessions", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)
		mockSessionRepo := new(mocks.SessionRepository)

		mockUserRepo.On("ChangeStatus", &models.User{ID: 1}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.IsActive = false
		}).Return(nil)
		mockSessionRepo.On("DeleteUserSessions", 1).Return(errors.New("delete sessions error"))

		server := &UserServiceServer{
			Logic: &UserServiceLogic{
				UserRepo:    mockUserRepo,
				SessionRepo: mockSessionRepo,
			},
			Logger: log.New(io.Discard, "", 0),
		}

		res, err := server.ChangeUserStatus(context.Background(), &userpb.ChangeUserStatusRequest{Id: int32(1)})
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "delete sessions error")

		mockUserRepo.AssertExpectations(t)
		mockSessionRepo.AssertExpectations(t)
	})
}

func TestLogin(t *testing.T) {
	t.Run("SuccessLogin", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)
		mockSessionRepo := new(mocks.SessionRepository)

		mockUserRepo.On("Login", &models.User{
			Login:    "admin",
			Password: "admin-pass",
		}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.ID = 1
			user.IsActive = true
		}).Return(nil)
		mockSessionRepo.On("CreateSession", &models.User{
			ID:       1,
			Login:    "admin",
			Password: "",
			IsActive: true,
		}).Return("session-hash", nil)

		server := &UserServiceServer{
			Logic: &UserServiceLogic{
				UserRepo:    mockUserRepo,
				SessionRepo: mockSessionRepo,
			},
		}

		res, err := server.Login(context.Background(), &userpb.LoginRequest{
			Login:    "admin",
			Password: "admin-pass",
		})
		assert.NoError(t, err)
		assert.Equal(t, "session-hash", res.Hash)

		mockUserRepo.AssertExpectations(t)
		mockSessionRepo.AssertExpectations(t)
	})

	t.Run("IncorrectLoginOrPassword", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)

		mockUserRepo.On("Login", &models.User{
			Login:    "admin",
			Password: "admin-pass",
		}).Return(nil)

		server := &UserServiceServer{
			Logic: &UserServiceLogic{
				UserRepo: mockUserRepo,
			},
		}

		res, err := server.Login(context.Background(), &userpb.LoginRequest{
			Login:    "admin",
			Password: "admin-pass",
		})
		assert.NoError(t, err)
		assert.Empty(t, res.Hash)
		assert.Equal(t, "Неверный логин/пароль", res.Failure)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("AccountBaned", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)

		mockUserRepo.On("Login", &models.User{
			Login:    "admin",
			Password: "admin-pass",
		}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.ID = 1
		}).Return(nil)

		server := &UserServiceServer{
			Logic: &UserServiceLogic{
				UserRepo: mockUserRepo,
			},
		}

		res, err := server.Login(context.Background(), &userpb.LoginRequest{
			Login:    "admin",
			Password: "admin-pass",
		})
		assert.NoError(t, err)
		assert.Empty(t, res.Hash)
		assert.Equal(t, "Этот аккаунт заблокирован", res.Failure)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("ErrorLogin", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)

		mockUserRepo.On("Login", &models.User{
			Login:    "admin",
			Password: "admin-pass",
		}).Return(errors.New("login error"))

		server := &UserServiceServer{
			Logic: &UserServiceLogic{
				UserRepo: mockUserRepo,
			},
			Logger: log.New(io.Discard, "", 0),
		}

		res, err := server.Login(context.Background(), &userpb.LoginRequest{
			Login:    "admin",
			Password: "admin-pass",
		})
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "login error")

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("ErrorCreateSession", func(t *testing.T) {
		t.Parallel()

		mockUserRepo := new(mocks.UserRepository)
		mockSessionRepo := new(mocks.SessionRepository)

		mockUserRepo.On("Login", &models.User{
			Login:    "admin",
			Password: "admin-pass",
		}).Run(func(args mock.Arguments) {
			user := args.Get(0).(*models.User)
			user.ID = 1
			user.IsActive = true
		}).Return(nil)
		mockSessionRepo.On("CreateSession", &models.User{
			ID:       1,
			Login:    "admin",
			Password: "",
			IsActive: true,
		}).Return("", errors.New("create session error"))

		server := &UserServiceServer{
			Logic: &UserServiceLogic{
				UserRepo:    mockUserRepo,
				SessionRepo: mockSessionRepo,
			},
			Logger: log.New(io.Discard, "", 0),
		}

		res, err := server.Login(context.Background(), &userpb.LoginRequest{
			Login:    "admin",
			Password: "admin-pass",
		})
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "create session error")

		mockUserRepo.AssertExpectations(t)
		mockSessionRepo.AssertExpectations(t)
	})
}
