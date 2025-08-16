package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"

	"github.com/oskoi/monotone-go"
)

func main() {
	db := monotone.New()
	err := db.Open("./data")
	handleErr(err, "open")
	defer db.Close()

	// write one million events using batches
	batch := make([]*monotone.Event, 200)
	for j := range batch {
		batch[j] = &monotone.Event{Id: math.MaxUint64}
	}
	for range 5000 {
		err = db.Write(batch)
		handleErr(err, "write")
	}

	// read all events, starting from zero
	cur, err := db.Cursor(nil, false)
	handleErr(err, "cursor")

	total := 0
	for {
		events, err := cur.Read(200)
		total += len(events)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
		}
	}

	fmt.Println("total:", total)

	// show statistics
	bs, err := db.Execute("show storages")
	handleErr(err, "execute")

	fmt.Println(string(bs))
}

func handleErr(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}
