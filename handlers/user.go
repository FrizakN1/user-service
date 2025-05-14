package handlers

import (
	"context"
	"user-service/database"
	"user-service/proto/userpb"
)

type UserServiceServer struct {
	userpb.UnimplementedUserServiceServer
	repo *database.DefaultUserRepository
}

func (s *UserServiceServer) GetUsers(ctx context.Context, req *userpb.Empty) (*userpb.GetUsersResponse, error) {
	users, err := s.repo.GetUsers()
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
