package kafka

import (
	"context"
	"github.com/segmentio/kafka-go"
	"log"
)

var kafkaWriter *kafka.Writer

func InitKafkaLogger() {
	kafkaWriter = kafka.NewWriter(kafka.WriterConfig{
		Brokers: []string{"kafka:9092"},
		Topic:   "user-logs",
	})
}

func LogToKafka(ctx context.Context, message string) {
	if err := kafkaWriter.WriteMessages(ctx, kafka.Message{
		Key:   []byte("user-service"),
		Value: []byte(message),
	}); err != nil {
		log.Println(err)
	}
}
