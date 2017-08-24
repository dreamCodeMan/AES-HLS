package main

import (
	_ "AES-HLS/app/routers"
	"github.com/astaxie/beego"
)

func main() {
	beego.Run()
}
