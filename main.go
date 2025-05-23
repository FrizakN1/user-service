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
	"user-service/interceptors"
	"user-service/proto/userpb"
	"user-service/utils"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalln(err)
		return
	}

	logger := utils.InitLogger()

	db, err := database.InitDatabase()
	if err != nil {
		log.Fatalln(err)
		return
	}

	userService := &handlers.UserServiceServer{
		Logic:  handlers.NewUserServiceLogic(db, logger),
		Logger: logger,
	}

	if err = userService.Logic.CheckAdmin(); err != nil {
		log.Fatalln(err)
		return
	}

	if err = userService.Logic.SessionRepo.LoadSession(); err != nil {
		log.Fatalln(err)
		return
	}

	lis, err := net.Listen(os.Getenv("APP_NETWORK"), fmt.Sprintf(":%s", os.Getenv("APP_PORT")))
	if err != nil {
		log.Fatalln(err)
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			interceptors.LoggingInterceptor(),
			interceptors.AuthInterceptor(userService.Logic.SessionRepo),
		),
	)

	userpb.RegisterUserServiceServer(grpcServer, userService)
	log.Println("User-service started on :50051")
	grpcServer.Serve(lis)
}
