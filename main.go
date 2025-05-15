package main

import (
	"fmt"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"user-service/database"
	"user-service/handlers"
	"user-service/proto/userpb"
	"user-service/utils"
)

func main() {
	utils.InitLogger()

	if err := godotenv.Load(); err != nil {
		log.Fatalln(err)
		return
	}

	if err := database.Connection(); err != nil {
		log.Fatalln(err)
		return
	}

	userService := NewUserServiceServer()

	if err := userService.UserRepo.CheckAdmin(); err != nil {
		log.Fatalln(err)
		return
	}

	lis, err := net.Listen(os.Getenv("APP_NETWORK"), fmt.Sprintf(":%s", os.Getenv("APP_PORT")))
	if err != nil {
		log.Fatalln(err)
	}

	grpcServer := grpc.NewServer()
	userpb.RegisterUserServiceServer(grpcServer, userService)
	log.Println("User-service started on :50051")
	grpcServer.Serve(lis)
}

func NewUserServiceServer() *handlers.UserServiceServer {
	return &handlers.UserServiceServer{
		UserRepo:    database.NewUserRepository(),
		RoleRepo:    &database.DefaultRoleRepository{},
		SessionRepo: database.NewSessionRepository(),
	}
}
