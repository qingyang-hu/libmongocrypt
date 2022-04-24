package main

// Insert key documents.
// Create collection.

import (
	"context"
	"fmt"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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
	client, err := mongo.Connect(context.TODO())
	defer func() {
		client.Disconnect(context.TODO())
	}()
	if err != nil {
		log.Fatalf("Error on Connect: %v", err)
	}

	fmt.Println("Drop and insert key vault collection: keyvault.datakeys ... begin")
	err = client.Database("keyvault").Collection("datakeys").Drop(context.TODO())
	if err != nil {
		log.Fatalf("Error on Drop: %v", err)
	}
	key := readJSONFile("../test/data/keys/12345678123498761234123456789012-local-document.json")
	_, err = client.Database("keyvault").Collection("datakeys").InsertOne(context.TODO(), key)
	if err != nil {
		log.Fatalf("Error on Insert: %v", err)
	}
	fmt.Println("Drop and insert key vault collection: keyvault.datakeys ... end")

	// Get the EncryptedFieldConfig.
	ef := readJSONFile("./encrypted-fields.json")

	fmt.Println("Drop encrypted collection: db.test ... begin")
	err = client.Database("db").Collection("test").Drop(context.TODO(), options.DropCollection().SetEncryptedFields(ef))
	if err != nil {
		log.Fatalf("Error in Drop: %v", err)
	}
	fmt.Println("Drop encrypted collection: db.test ... end")

	fmt.Println("Create encrypted collection: db.test ... begin")
	err = client.Database("db").CreateCollection(context.TODO(), "test", options.CreateCollection().SetEncryptedFields(ef))
	if err != nil {
		log.Fatalf("Error in CreateCollection: %v", err)
	}
	fmt.Println("Create encrypted collection: db.test ... end")
}
