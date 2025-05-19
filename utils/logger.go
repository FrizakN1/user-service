package utils

import (
	"fmt"
	"log"
	"os"
	"time"
)

type Logger interface {
	Println(v ...any)
}

func InitLogger() Logger {
	logDir := "logs"

	_, err := os.Stat(logDir)
	if os.IsNotExist(err) {
		if err = os.Mkdir(logDir, os.ModePerm); err != nil {
			log.Fatalf("ошибка создания папки logs: %e\n", err)
			return log.Default()
		}
	}

	currentDate := time.Now().String()[0:10]

	loggerFile, e := os.OpenFile(fmt.Sprintf("%s/%s.log", logDir, currentDate), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if e != nil {
		log.Fatalln(e)
		return log.Default()
	}

	return log.New(loggerFile, "", log.Ldate|log.Ltime|log.Lshortfile)
}
