package handlers

import (
	"context"
	"user-service/proto/userpb"
)

func (s *UserServiceServer) GetRoles(ctx context.Context, req *userpb.Empty) (*userpb.GetRolesResponse, error) {
	roles, err := s.Logic.RoleRepo.GetRoles()
	if err != nil {
		s.Logger.Println(err)
		return nil, err
	}

	var grpcRoles []*userpb.Role
	for _, r := range roles {
		grpcRole := &userpb.Role{
			Id:    int32(r.ID),
			Key:   r.Key,
			Value: r.Value,
		}
		grpcRoles = append(grpcRoles, grpcRole)
	}

	return &userpb.GetRolesResponse{Roles: grpcRoles}, nil
}
