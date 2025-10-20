package controllers

import (
	"github.com/revel/revel/v3"
)

type App struct {
	*revel.Controller
}

func (c App) Index() revel.Result {
	return c.RenderJSON(map[string]string{
		"message": "DegenHF ECC Authentication API - Go Revel",
		"version": "1.0.0",
		"endpoints": "/api/auth/*",
	})
}