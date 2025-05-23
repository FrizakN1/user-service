package handlers

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"time"
	"user-service/database"
	"user-service/models"
	"user-service/proto/userpb"
	"user-service/utils"
)

type UserServiceServer struct {
	userpb.UnimplementedUserServiceServer
	Logic  *UserServiceLogic
	Logger utils.Logger
}

type UserServiceLogic struct {
	UserRepo     database.UserRepository
	SessionRepo  database.SessionRepository
	RoleRepo     database.RoleRepository
	Hasher       utils.Hasher
	Logger       utils.Logger
	AdminCreator SuperAdminCreator
}

type SuperAdminCreator interface {
	CreateSuperAdmin() error
}

type DefaultSuperAdminCreator struct {
	UserRepo database.UserRepository
	RoleRepo database.RoleRepository
	Logger   utils.Logger
}

func NewUserServiceLogic(db database.Database, logger utils.Logger) *UserServiceLogic {
	userRepo := database.NewUserRepository(db)
	roleRepo := database.NewRoleRepository(db)

	return &UserServiceLogic{
		UserRepo:    userRepo,
		RoleRepo:    roleRepo,
		SessionRepo: database.NewSessionRepository(db),
		Hasher:      &utils.DefaultHasher{},
		Logger:      logger,
		AdminCreator: &DefaultSuperAdminCreator{
			UserRepo: userRepo,
			RoleRepo: roleRepo,
			Logger:   logger,
		},
	}
}

func (l *UserServiceLogic) ValidateUser(user models.User, action string) bool {
	if len(user.Name) == 0 || len(user.Login) == 0 {
		return false
	}

	roles, err := l.RoleRepo.GetRoles()
	if err != nil {
		l.Logger.Println(err)
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

func (l *DefaultSuperAdminCreator) CreateSuperAdmin() error {
	var admin models.User

	role := models.Role{Key: "admin"}
	if err := l.RoleRepo.GetRole(&role); err != nil {
		l.Logger.Println(err)
		return err
	}

	admin = models.User{
		Login:     "SuperAdmin",
		Name:      "SuperAdmin",
		Role:      role,
		Password:  os.Getenv("SUPER_ADMIN_PASSWORD"),
		CreatedAt: time.Now().Unix(),
	}

	if err := l.UserRepo.CreateUser(&admin); err != nil {
		l.Logger.Println(err)
		return err
	}
	return nil
}

func (l *UserServiceLogic) CheckAdmin() error {
	admin := &models.User{}

	if err := l.UserRepo.GetSuperAdmin(admin); err != nil {
		l.Logger.Println(err)
		return err
	}

	if admin.ID == 0 {
		if err := l.AdminCreator.CreateSuperAdmin(); err != nil {
			l.Logger.Println(err)
			return err
		}

		return nil
	}

	encryptPass, err := l.Hasher.Encrypt(os.Getenv("SUPER_ADMIN_PASSWORD"))
	if err != nil {
		l.Logger.Println(err)
		return err
	}

	if encryptPass != admin.Password {
		admin.Password = os.Getenv("SUPER_ADMIN_PASSWORD")

		if err = l.UserRepo.ChangeUserPassword(admin); err != nil {
			l.Logger.Println(err)
			return err
		}

		if err = l.SessionRepo.DeleteUserSessions(admin.ID); err != nil {
			l.Logger.Println(err)
			return err
		}

		log.Println("SuperAdmin password is changed")
	}

	return nil
}

func (s *UserServiceServer) ChangeUserStatus(ctx context.Context, req *userpb.ChangeUserStatusRequest) (*userpb.ChangeUserStatusResponse, error) {
	user := &models.User{ID: int(req.Id)}

	if err := s.Logic.UserRepo.ChangeStatus(user); err != nil {
		s.Logger.Println(err)
		return nil, err
	}

	if !user.IsActive {
		if err := s.Logic.SessionRepo.DeleteUserSessions(user.ID); err != nil {
			s.Logger.Println(err)
			return nil, err
		}
	}

	return &userpb.ChangeUserStatusResponse{IsActive: user.IsActive}, nil
}

func (s *UserServiceServer) Login(ctx context.Context, req *userpb.LoginRequest) (*userpb.LoginResponse, error) {
	user := &models.User{
		Login:    req.Login,
		Password: req.Password,
	}

	if err := s.Logic.UserRepo.Login(user); err != nil {
		s.Logger.Println(err)
		return nil, err
	}

	if user.ID <= 0 {
		return &userpb.LoginResponse{Failure: "Неверный логин/пароль"}, nil
	}

	if !user.IsActive {
		return &userpb.LoginResponse{Failure: "Этот аккаунт заблокирован"}, nil
	}

	user.Password = ""

	hash, err := s.Logic.SessionRepo.CreateSession(user)
	if err != nil {
		s.Logger.Println(err)
		return nil, err
	}

	return &userpb.LoginResponse{Hash: hash}, nil
}

func (s *UserServiceServer) EditUser(ctx context.Context, req *userpb.EditUserRequest) (*userpb.EditUserResponse, error) {
	user := &models.User{
		ID:       int(req.Id),
		Role:     models.Role{ID: int(req.RoleId)},
		Login:    req.Login,
		Name:     req.Name,
		Password: req.Password,
		UpdatedAt: sql.NullInt64{
			Int64: time.Now().Unix(),
			Valid: true,
		},
	}

	if !s.Logic.ValidateUser(*user, "edit") {
		return nil, errors.New("user is not valid")
	}

	if err := s.Logic.UserRepo.EditUser(user); err != nil {
		s.Logger.Println(err)
		return nil, err
	}

	if user.Password != "" {
		if err := s.Logic.UserRepo.ChangeUserPassword(user); err != nil {
			s.Logger.Println(err)
			return nil, err
		}

		user.Password = ""
	}

	if err := s.Logic.SessionRepo.DeleteUserSessions(user.ID); err != nil {
		s.Logger.Println(err)
		return nil, err
	}

	return &userpb.EditUserResponse{UpdatedAt: user.UpdatedAt.Int64}, nil
}

func (s *UserServiceServer) CreateUser(ctx context.Context, req *userpb.CreateUserRequest) (*userpb.CreateUserResponse, error) {
	user := &models.User{
		Role:      models.Role{ID: int(req.RoleId)},
		Login:     req.Login,
		Name:      req.Name,
		Password:  req.Password,
		CreatedAt: time.Now().Unix(),
	}

	if !s.Logic.ValidateUser(*user, "create") {
		return nil, errors.New("user is not valid")
	}

	if err := s.Logic.UserRepo.CreateUser(user); err != nil {
		s.Logger.Println(err)
		return nil, err
	}

	return &userpb.CreateUserResponse{UserId: int32(user.ID), CreatedAt: user.CreatedAt}, nil
}

func (s *UserServiceServer) GetUsers(ctx context.Context, req *userpb.Empty) (*userpb.GetUsersResponse, error) {
	users, err := s.Logic.UserRepo.GetUsers()
	if err != nil {
		s.Logger.Println(err)
		return nil, err
	}

	var grpcUsers []*userpb.User
	for _, u := range users {
		grpcUser := &userpb.User{
			Id:        int32(u.ID),
			Login:     u.Login,
			Name:      u.Name,
			IsActive:  u.IsActive,
			CreatedAt: u.CreatedAt,
			UpdatedAt: func() int64 {
				if u.UpdatedAt.Valid {
					return u.UpdatedAt.Int64
				}
				return 0
			}(),
			Role: &userpb.Role{
				Id:    int32(u.Role.ID),
				Key:   u.Role.Key,
				Value: u.Role.Value,
			},
		}
		grpcUsers = append(grpcUsers, grpcUser)
	}

	return &userpb.GetUsersResponse{Users: grpcUsers}, nil
}

func (s *UserServiceServer) GetUsersByIds(ctx context.Context, req *userpb.GetUsersByIdsRequest) (*userpb.GetUsersByIdsResponse, error) {
	users, err := s.Logic.UserRepo.GetUsersByIds(req.Ids)
	if err != nil {
		s.Logger.Println(err)
		return nil, err
	}

	var grpcUsers []*userpb.User
	for _, u := range users {
		grpcUser := &userpb.User{
			Id:        int32(u.ID),
			Login:     u.Login,
			Name:      u.Name,
			IsActive:  u.IsActive,
			CreatedAt: u.CreatedAt,
			UpdatedAt: func() int64 {
				if u.UpdatedAt.Valid {
					return u.UpdatedAt.Int64
				}
				return 0
			}(),
			Role: &userpb.Role{
				Id:    int32(u.Role.ID),
				Key:   u.Role.Key,
				Value: u.Role.Value,
			},
		}
		grpcUsers = append(grpcUsers, grpcUser)
	}

	return &userpb.GetUsersByIdsResponse{Users: grpcUsers}, nil
}
