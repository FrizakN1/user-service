package interceptors

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"user-service/kafka"
)

func LoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		resp, err := handler(ctx, req)
		fmt.Println(123)
		status := "OK"
		if err != nil {
			fmt.Println(err)
			//status = status.Code(err).String()
		}

		message := fmt.Sprintf("method=%s status=%s", info.FullMethod, status)
		fmt.Println(message)
		kafka.LogToKafka(ctx, message)

		return resp, err
	}
}
