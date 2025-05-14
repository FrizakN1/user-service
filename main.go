package main

import (
	"fmt"
	"google.golang.org/grpc"
	"log"
	"net"
	"user-service/database"
	"user-service/handlers"
	"user-service/proto/userpb"
	"user-service/settings"
	"user-service/utils"
)

func main() {
	utils.InitLogger()

	config := settings.Load("settings.json")

	if err := database.Connection(config); err != nil {
		log.Fatalln(err)
		return
	}

	userRepo := database.NewUserRepository()

	if err := userRepo.CheckAdmin(config); err != nil {
		log.Fatalln(err)
		return
	}

	lis, err := net.Listen(config.Network, fmt.Sprintf(":%s", config.Port))
	if err != nil {
		log.Fatalln(err)
	}

	grpcServer := grpc.NewServer()
	userpb.RegisterUserServiceServer(grpcServer, &handlers.UserServiceServer{})
	log.Println("User-service started on :50051")
	grpcServer.Serve(lis)
}
