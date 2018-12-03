package main

import "os"

func fatal(args ...interface{}) {
	println(args)
	os.Exit(1)
}
