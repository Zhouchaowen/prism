package main

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/syndtr/goleveldb/leveldb"
	"log"
	"net/http"
	"strings"
	"time"
)

func RunListening(db *leveldb.DB) {
	router := gin.New()
	router.Use(gin.Recovery())
	router.LoadHTMLGlob("/web/*.html")
	router.Static("/css", "/web/css")
	router.Static("/js", "/web/js")
	router.StaticFile("/", "/web/index.html") //前端接口

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
				log.Printf("================load data success %fs================", time.Since(stat).Seconds())
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
	Name   string `form:"name"`
	Offset int    `form:"offset" binding:"required,min=1"`
	Limit  int    `form:"limit" binding:"required,min=10"`
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

	cache := *h.cache

	// filter by name
	if len(search.Name) > 0 {
		var tmp []model
		for i, _ := range cache {
			if strings.Contains(cache[i].RequestURL, search.Name) {
				tmp = append(tmp, cache[i])
			}
		}
		cache = tmp
	}

	left := (search.Offset - 1) * search.Limit
	right := search.Offset * search.Limit
	if left >= len(cache) {
		ctx.JSON(http.StatusOK, gin.H{
			"msg": "no data",
		})
		return
	}

	if right > len(cache) {
		ctx.JSON(http.StatusOK, gin.H{
			"data":  cache[left:],
			"total": len(cache),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"data":  cache[left:right],
		"total": len(cache),
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
			log.Printf("json.unmarshal:%s\n", err.Error())
		}
		ret = append(ret, md)
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		log.Printf("iter error:%s\n", err.Error())
	}
	h.cache = &ret
}
