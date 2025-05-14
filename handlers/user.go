package handlers

import (
	"context"
	"database/sql"
	"errors"
	"time"
	"user-service/database"
	"user-service/models"
	"user-service/proto/userpb"
	"user-service/utils"
)

type UserServiceServer struct {
	userpb.UnimplementedUserServiceServer
	userRepo    *database.DefaultUserRepository
	roleRepo    *database.DefaultRoleRepository
	sessionRepo *database.DefaultSessionRepository
}

func (s *UserServiceServer) Logout(ctx context.Context, req *userpb.LogoutRequest) (*userpb.Empty, error) {
	if err := s.sessionRepo.DeleteSession(req.Hash); err != nil {
		utils.Logger.Println(err)
		return nil, err
	}

	return &userpb.Empty{}, nil
}

func (s *UserServiceServer) GetSession(ctx context.Context, req *userpb.GetSessionRequest) (*userpb.Session, error) {
	session := s.sessionRepo.GetSession(req.Hash)
	if session == nil {
		return nil, errors.New("session not found")
	}

	grpcSession := &userpb.Session{
		Hash: session.Hash,
		User: &userpb.User{
			Id: int32(session.User.ID),
			Role: &userpb.Role{
				Id:    int32(session.User.Role.ID),
				Key:   session.User.Role.Key,
				Value: session.User.Role.Value,
			},
			Login:     session.User.Login,
			Name:      session.User.Name,
			IsActive:  session.User.IsActive,
			CreatedAt: session.User.CreatedAt,
			UpdatedAt: func() int64 {
				if session.User.UpdatedAt.Valid {
					return session.User.UpdatedAt.Int64
				}

				return 0
			}(),
		},
		CreatedAt: session.CreatedAt,
	}

	return grpcSession, nil
}

func (s *UserServiceServer) ChangeUserStatus(ctx context.Context, req *userpb.ChangeUserStatusRequest) (*userpb.ChangeUserStatusResponse, error) {
	user := &models.User{ID: int(req.Id)}

	if err := s.userRepo.ChangeStatus(user); err != nil {
		utils.Logger.Println(err)
		return nil, err
	}

	if !user.IsActive {
		if err := s.sessionRepo.DeleteUserSessions(user.ID); err != nil {
			utils.Logger.Println(err)
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

	if err := s.userRepo.Login(user); err != nil {
		return nil, err
	}

	if user.ID <= 0 {
		return &userpb.LoginResponse{Failure: "Неверный логин/пароль"}, errors.New("user not found")
	}

	if !user.IsActive {
		return &userpb.LoginResponse{Failure: "Этот аккаунт заблокирован"}, errors.New("user is not active")
	}

	user.Password = ""

	hash, err := s.sessionRepo.CreateSession(*user)
	if err != nil {
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

	if !s.userRepo.ValidateUser(*user, "edit") {
		return nil, errors.New("user is not valid")
	}

	if err := s.userRepo.EditUser(user); err != nil {
		utils.Logger.Println(err)
		return nil, err
	}

	if user.Password != "" {
		if err := s.userRepo.ChangeUserPassword(user); err != nil {
			utils.Logger.Println(err)
			return nil, err
		}

		user.Password = ""
	}

	if err := s.sessionRepo.DeleteUserSessions(user.ID); err != nil {
		utils.Logger.Println(err)
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

	if !s.userRepo.ValidateUser(*user, "create") {
		return nil, errors.New("user is not valid")
	}

	if err := s.userRepo.CreateUser(user); err != nil {
		return nil, err
	}

	return &userpb.CreateUserResponse{UserId: int32(user.ID), CreatedAt: user.CreatedAt}, nil
}

func (s *UserServiceServer) GetUsers(ctx context.Context, req *userpb.Empty) (*userpb.GetUsersResponse, error) {
	users, err := s.userRepo.GetUsers()
	if err != nil {
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
