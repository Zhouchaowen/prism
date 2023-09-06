package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/syndtr/goleveldb/leveldb"
	"net/http"
	"time"
)

func runListening(db *leveldb.DB) {
	router := gin.New()
	router.Use(gin.Recovery())

	var h = Handler{
		db: db,
	}

	go func() {
		ticker := time.Tick(60 * time.Second)
		for {
			select {
			case <-ticker:
				stat := time.Now()
				h.load()
				fmt.Printf("================load data success %fs================l\n", time.Since(stat).Seconds())
			}
		}
	}()

	router.GET("/interface", h.list)

	router.Run(":8080")
}

type Handler struct {
	db    *leveldb.DB
	cache *[]model
}

type Search struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit" binding:"required,min=10"`
}

func (h Handler) list(ctx *gin.Context) {
	var search Search
	if err := ctx.ShouldBindQuery(&search); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"msg": err.Error(),
		})
		return
	}

	if h.cache == nil {
		h.load()
	}

	left := search.Offset * search.Limit
	right := (search.Offset + 1) * search.Limit
	if left >= len(*h.cache) {
		ctx.JSON(http.StatusOK, gin.H{
			"msg": "no data",
		})
		return
	}

	if right > len(*h.cache) {
		ctx.JSON(http.StatusOK, gin.H{
			"data":  (*h.cache)[left:],
			"total": len(*h.cache),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"data":  (*h.cache)[left:right],
		"total": len(*h.cache),
	})
	return
}

func (h *Handler) load() {
	var ret []model
	iter := h.db.NewIterator(nil, nil)
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
		fmt.Printf("iter error:%s\n", err.Error())
	}
	h.cache = &ret
}
