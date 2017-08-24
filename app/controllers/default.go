package controllers

import (
	"AES-HLS/app/common"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/astaxie/beego"
)

var (
	Host          string
	AesKey        string
	Port          string
	AesIv         string
	ConditionCode string
	exePath       string
	auth          string
)

type MainController struct {
	beego.Controller
}

func init() {
	Host, Port, AesKey, AesIv, ConditionCode = common.GetConfig()
	_, exePath = common.GetCurrPath()
	common.StartEncryptAndCache()
	url := fmt.Sprintf("%s:%s/v1/playlist.m3u8", Host, Port)
	beego.Info("HLS视频加密程序，verison 1.0,采用AES-128加密方式，并校验客户端数据", url)
}

func (c *MainController) Get() {
	c.Ctx.WriteString("<title>HLS视频加密程序，verison 1.0</title>\n<div align=\"center\"><h4>HLS视频加密程序，verison 1.0,采用AES-128加密方式，并校验客户端数据</h4></div>")
}

func (c *MainController) PlayList() {
	if !common.MatchSignature(c.Ctx.Request, ConditionCode) {
		c.Ctx.WriteString("客户端错误")
		return
	}
	var content []byte
	cache_ts := beego.AppConfig.String("cache_ts")
	m3u8FilePath := fmt.Sprintf("%s/static/dst/index.m3u8", exePath)
	_, err := os.Stat(m3u8FilePath)
	if err == nil && cache_ts == "true" {
		beego.Info("存在加密文件，直接输出")
		content, err = ioutil.ReadFile(m3u8FilePath)
		if err != nil {
			beego.Error(err)
			c.Ctx.WriteString("读取文件错误")
			return
		}
	} else {
		m3u8Url := fmt.Sprintf("%s:%s/static/src/index.m3u8", Host, Port)
		//加密视频播放串
		encryptContent, err := common.EncryptM3u8(m3u8Url, ConditionCode)
		if err != nil {
			beego.Error(err)
			c.Ctx.WriteString("加密播放串失败")
			return
		}
		//开启缓存加密TS
		if cache_ts == "true" {
			go common.CacheVideoFile(m3u8FilePath, m3u8Url, ConditionCode)
		}
		content = []byte(encryptContent)
	}
	c.Ctx.Output.Header("Content-Type", "application/x-mpegURL")
	c.Ctx.Output.Body(content)
}

func (c *MainController) Key() {
	content := strings.TrimSpace(c.GetString("str", "123456"))
	if len(content) < 16 {
		beego.Info("待解密数据非法")
		c.Ctx.WriteString("待解密数据非法")
		return
	}
	decryptContent, err := common.CFBDecryptString(content, AesKey)
	if err != nil {
		beego.Error(err)
		c.Ctx.WriteString("解密数据失败")
		return
	}
	decryptContentArr := []string{}
	if decryptContentArr = strings.Split(decryptContent, ";"); len(decryptContentArr) != 2 {
		c.Ctx.WriteString("解密数据错误")
		return
	}
	//检测特征码,确定来源是否正确
	if decryptContentArr[1] != ConditionCode {
		c.Ctx.WriteString("数据来源错误……")
		return
	}
	c.Ctx.WriteString(decryptContentArr[0])
}

func (c *MainController) Encrypt() {
	if !common.MatchSignature(c.Ctx.Request, ConditionCode) {
		c.Ctx.WriteString("客户端错误")
		return
	}
	encryptString := c.GetString("str", "123456")
	decryptContent, err := common.CFBDecryptString(encryptString, AesKey)
	if err != nil {
		beego.Error(err)
		c.Ctx.WriteString("解密数据失败")
		return
	}

	decryptContentArr := strings.Split(decryptContent, ",")
	tsUrl := decryptContentArr[1]
	resp, err := http.Get(tsUrl)
	if err != nil {
		beego.Error(err)
		c.Ctx.WriteString("无法获取ts文件")
		return
	}
	if resp.StatusCode != http.StatusOK {
		c.Ctx.WriteString("网络错误，网络状态码")
		beego.Error("网络错误，网络状态码:", resp.StatusCode)
		return
	}
	defer resp.Body.Close()

	fileContent, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		beego.Error(err)
		c.Ctx.WriteString("打开ts文件异常")
		return
	}
	//解密密钥
	keyArray := []string{}
	if keyArray = strings.Split(decryptContentArr[0], ";"); len(keyArray) != 2 {
		return
	}
	//检测特征码,确定来源是否正确
	if keyArray[1] != ConditionCode {
		c.Ctx.WriteString("数据来源错误……")
		return
	}

	body, err := common.CBCEncryptStream(fileContent, keyArray[0], []byte(AesIv))
	c.Ctx.Output.Body(body)
}
