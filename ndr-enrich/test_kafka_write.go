package main

import (
    "context"
    "fmt"
    "time"
    "github.com/segmentio/kafka-go"
)

func main() {
    writer := &kafka.Writer{
        Addr:     kafka.TCP("localhost:9092"),
        Topic:    "zeek-normalized",
        Balancer: &kafka.LeastBytes{},
    }
    defer writer.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    msg := kafka.Message{
        Key:   []byte("test-key"),
        Value: []byte(`{"test":"direct-go-write","src_ip":"99.99.99.99","log_type":"conn"}`),
    }

    err := writer.WriteMessages(ctx, msg)
    if err != nil {
        fmt.Printf("Write FAILED: %v\n", err)
    } else {
        fmt.Printf("Write SUCCESS\n")
    }
}
