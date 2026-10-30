package main

import (
	"errors"
	"os"
)

func configEnv(name string) string {
	if value, ok := os.LookupEnv("EXOWODUS_" + name); ok {
		return value
	}
	return os.Getenv("EXODUS_" + name)
}

func defaultArchiveDir() string {
	if _, err := os.Stat("exowodus-archive"); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat("exodus-archive/manifest.json"); err == nil {
			return "exodus-archive"
		}
	}
	return "exowodus-archive"
}
