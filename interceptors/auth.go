package interceptors

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strings"
	"user-service/database"
	"user-service/proto/userpb"
)

const sessionContextKey = "session"

func AuthInterceptor(repo database.SessionRepository) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Пропускаем методы, не требующие авторизации (например, Login, Register)
		if info.FullMethod == "/user.UserService/Login" {
			return handler(ctx, req)
		}

		// Извлекаем metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "metadata not found")
		}

		authHeaders := md.Get("Authorization")
		if len(authHeaders) == 0 {
			return nil, status.Error(codes.Unauthenticated, "authorization token not provided")
		}

		parts := strings.Split(authHeaders[0], " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return nil, status.Error(codes.Unauthenticated, "invalid auth header format")
		}

		token := parts[1]

		// Проверяем сессию
		session := repo.GetSession(token)
		if session == nil {
			return nil, status.Error(codes.Unauthenticated, "invalid session token")
		}

		// Преобразуем в protobuf-модель
		grpcSession := &userpb.Session{
			Hash: session.Hash,
			User: &userpb.User{
				Id:       int32(session.User.ID),
				Login:    session.User.Login,
				Name:     session.User.Name,
				IsActive: session.User.IsActive,
				Role: &userpb.Role{
					Id:    int32(session.User.Role.ID),
					Key:   session.User.Role.Key,
					Value: session.User.Role.Value,
				},
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

		// Кладём сессию в context
		ctx = context.WithValue(ctx, sessionContextKey, grpcSession)

		// Передаём дальше
		return handler(ctx, req)
	}
}
