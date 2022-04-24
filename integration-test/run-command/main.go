package main

// RunCommand with a file in extended canonical JSON.

import (
	"context"
	"fmt"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func readJSONFile(path string) bson.Raw {
	dat, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Error reading file: %v: %v", path, err)
	}

	var asBSON bson.Raw
	err = bson.UnmarshalExtJSON(dat, true /* canonical */, &asBSON)
	if err != nil {
		log.Fatalf("Error in UnmarshalExtJSON: %v", err)
	}
	return asBSON
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %v <command-file.json>", os.Args[0])
	}

	client, err := mongo.Connect(context.TODO())
	defer func() {
		client.Disconnect(context.TODO())
	}()
	if err != nil {
		log.Fatalf("Error on Connect: %v", err)
	}

	path := os.Args[1]
	cmd := readJSONFile(path)
	res := client.Database("db").RunCommand(context.TODO(), cmd)
	resBSON, err := res.DecodeBytes()
	if err != nil {
		log.Fatalf("Error on DecodeBytes: %v", err)
	}
	resJSON, err := bson.MarshalExtJSON(resBSON, true /* canonical */, false /* escape HTML */)
	if err != nil {
		log.Fatalf("Error on MarshalExtJSON: %v", err)
	}

	fmt.Println(string(resJSON))
}
