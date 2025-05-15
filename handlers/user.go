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
	UserRepo    database.UserRepository
	RoleRepo    database.RoleRepository
	SessionRepo database.SessionRepository
}

func (s *UserServiceServer) ChangeUserStatus(ctx context.Context, req *userpb.ChangeUserStatusRequest) (*userpb.ChangeUserStatusResponse, error) {
	user := &models.User{ID: int(req.Id)}

	if err := s.UserRepo.ChangeStatus(user); err != nil {
		utils.Logger.Println(err)
		return nil, err
	}

	if !user.IsActive {
		if err := s.SessionRepo.DeleteUserSessions(user.ID); err != nil {
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

	if err := s.UserRepo.Login(user); err != nil {
		utils.Logger.Println(err)
		return nil, err
	}

	if user.ID <= 0 {
		return &userpb.LoginResponse{Failure: "Неверный логин/пароль"}, nil
	}

	if !user.IsActive {
		return &userpb.LoginResponse{Failure: "Этот аккаунт заблокирован"}, nil
	}

	user.Password = ""

	hash, err := s.SessionRepo.CreateSession(*user)
	if err != nil {
		utils.Logger.Println(err)
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

	if !s.UserRepo.ValidateUser(*user, "edit") {
		return nil, errors.New("user is not valid")
	}

	if err := s.UserRepo.EditUser(user); err != nil {
		utils.Logger.Println(err)
		return nil, err
	}

	if user.Password != "" {
		if err := s.UserRepo.ChangeUserPassword(user); err != nil {
			utils.Logger.Println(err)
			return nil, err
		}

		user.Password = ""
	}

	if err := s.SessionRepo.DeleteUserSessions(user.ID); err != nil {
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

	if !s.UserRepo.ValidateUser(*user, "create") {
		return nil, errors.New("user is not valid")
	}

	if err := s.UserRepo.CreateUser(user); err != nil {
		utils.Logger.Println(err)
		return nil, err
	}

	return &userpb.CreateUserResponse{UserId: int32(user.ID), CreatedAt: user.CreatedAt}, nil
}

func (s *UserServiceServer) GetUsers(ctx context.Context, req *userpb.Empty) (*userpb.GetUsersResponse, error) {
	users, err := s.UserRepo.GetUsers()
	if err != nil {
		utils.Logger.Println(err)
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
	users, err := s.UserRepo.GetUsersByIds(req.Ids)
	if err != nil {
		utils.Logger.Println(err)
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
