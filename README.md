# Monotone Client for Go

Monotone Client is wrapper native [Monotone API](https://monotone.studio/docs/api/) using the awesome [purego](https://github.com/ebitengine/purego) library to call C.

## Installing

```
go get -u github.com/oskoi/monotone-go
```

## Run [Examples](https://github.com/oskoi/monotone-go/tree/main/examples)

- basic -- basic API usage.

clone repo and run container:

```bash
$ git clone https://github.com/oskoi/amelie-go && cd amelie-go
$ docker run --platform linux/amd64 -it -v ./:/home ubuntu:25.04
```

and run example in container:

```bash
$ apt-get update && apt-get install -y git golang libcurl4-openssl-dev
$ cd /home && go run examples/basic/main.go
```
