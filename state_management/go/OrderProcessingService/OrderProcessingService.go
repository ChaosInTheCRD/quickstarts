package main

import (
	"context"
	"log"
	"math/rand"
	"time"
	"strconv"
	dapr "github.com/dapr/go-sdk/client"

)

type Order struct {
	orderName string
	orderNum  string
}

func main() {
	for i := 0; i < 10; i++ {
		time.Sleep(5000)
		orderId := rand.Intn(1000-1) + 1
		client, err := dapr.NewClient()
		store := "statestore"
		if err != nil {
			panic(err)
		}
		defer client.Close()
		ctx := context.Background()

		if err := client.SaveState(ctx, store, "order_1", []byte(strconv.Itoa(orderId))); err != nil {
			panic(err)
		}

		if err := client.SaveState(ctx, store, "order_2", []byte(strconv.Itoa(orderId))); err != nil {
			panic(err)
		}
		
		result, err := client.GetState(ctx, store, "order_2")
		if err != nil {
			panic(err)
		}

		log.Println("Result after get: ")
		log.Println(result)

		if err := client.DeleteState(ctx, store, "order_1"); err != nil {
			panic(err)
		}

		log.Println("Order requested: " + strconv.Itoa(orderId))
		log.Println("Result: ")
		log.Println(result)
	}
}

