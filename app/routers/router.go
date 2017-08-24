package routers

import (
	"AES-HLS/app/controllers"
	"net/http"

	"github.com/astaxie/beego"
)

func init() {

	beego.ErrorHandler("404", func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusNotFound)
	})
	beego.Router("/", &controllers.MainController{})
	beego.AutoRouter(&controllers.MainController{})

	ns_v1 := beego.NewNamespace("v1",
		beego.NSRouter("/get", &controllers.MainController{}, "get:Get"),
		beego.NSRouter("/playlist.m3u8", &controllers.MainController{}, "get:PlayList"),
		beego.NSRouter("/key", &controllers.MainController{}, "get:Key"),
		beego.NSRouter("/play.ts", &controllers.MainController{}, "get:Encrypt"),
	)
	beego.AddNamespace(ns_v1)
}
