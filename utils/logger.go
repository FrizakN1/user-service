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

	if err := os.Mkdir(logDir, os.ModePerm); err != nil {
		fmt.Println("ошибка создания папки logs:", err)
		return log.Default()
	}

	currentDate := time.Now().String()[0:10]

	loggerFile, e := os.OpenFile(fmt.Sprintf("%s/%s.log", logDir, currentDate), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if e != nil {
		fmt.Println(e)
		return log.Default()
	}

	return log.New(loggerFile, "", log.Ldate|log.Ltime|log.Lshortfile)
}
