# Monotone Client for Go

Monotone Client is wrapper native [Monotone API](https://monotone.studio/docs/api/) using the awesome [purego](https://github.com/ebitengine/purego) library to call C.

## Installing

Clone [Monotone](https://github.com/pmwkaa/monotone), install build dependencies (only linux environments) and build release.

```
git clone https://github.com/pmwkaa/monotone && cd monotone && make release
```

Next, copy `build/libmonotone.so` to your project and add monotone-go

```
go get -u github.com/oskoi/monotone-go
```

## Example

```
LIBMONOTONE_PATH=<path to libmonotone.so> go run main.go
```

```go
// main.go
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
	err := db.Open("./example_repo")
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
	key := monotone.Event{}
	cur, err := db.Cursor(key)
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
```
