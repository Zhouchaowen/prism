package main

import (
	"encoding/json"
	"github.com/syndtr/goleveldb/leveldb"
	"log"
	"strings"
)

func SaveHttpData(db *leveldb.DB, save <-chan model) {
	for md := range save {
		if !strings.Contains(md.ResponseContextType, "text/plain") && !strings.Contains(md.ResponseContextType, "application/json") {
			log.Printf("package is no text/plain,application/json")
			continue
		}
		md.key()

		byt, err := json.Marshal(md)
		if err != nil {
			log.Printf("marshal error %s", err.Error())
			continue
		}
		if err := db.Put([]byte(md.Id), byt, nil); err != nil {
			log.Printf("put error %s", err.Error())
			continue
		}
	}
}
