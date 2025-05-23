package handlers

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"user-service/proto/userpb"
)

func (s *UserServiceServer) Logout(ctx context.Context, req *userpb.LogoutRequest) (*userpb.Empty, error) {
	if err := s.Logic.SessionRepo.DeleteSession(req.Hash); err != nil {
		s.Logger.Println(err)
		return nil, err
	}

	return &userpb.Empty{}, nil
}

func (s *UserServiceServer) GetSession(ctx context.Context, req *userpb.GetSessionRequest) (*userpb.GetSessionResponse, error) {
	session := s.Logic.SessionRepo.GetSession(req.Hash)
	if session == nil {
		return &userpb.GetSessionResponse{Session: &userpb.Session{}, Exist: false}, status.Error(codes.Unauthenticated, "session not found")
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

	return &userpb.GetSessionResponse{Session: grpcSession, Exist: true}, nil
}
