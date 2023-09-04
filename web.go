package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/syndtr/goleveldb/leveldb"
	"net/http"
)

func runListening(db *leveldb.DB) {
	router := gin.Default()
	router.GET("/interface", func(ctx *gin.Context) {
		var ret []model
		iter := db.NewIterator(nil, nil)
		for iter.Next() {
			// Remember that the contents of the returned slice should not be modified, and only valid until the next call to Next.
			value := iter.Value()
			md := model{}
			if err := json.Unmarshal(value, &md); err != nil {
				fmt.Printf("json.unmarshal:%s\n", err.Error())
			}
			ret = append(ret, md)
		}
		iter.Release()
		if err := iter.Error(); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"msg": err.Error(),
			})
		}

		ctx.JSON(http.StatusOK, gin.H{
			"data": ret,
		})
		return
	})

	router.Run(":8080")
}
