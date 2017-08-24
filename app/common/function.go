package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	rands "math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/astaxie/beego"
	"github.com/grafov/m3u8"
)

var strListChan = make(chan string, 10000)

var (
	Host          string
	AesKey        string
	Port          string
	AesIv         string
	ConditionCode string
	authAgent     string
)

func init() {
	authAgent = beego.AppConfig.String("auth_agent")
	Host, Port, AesKey, AesIv, ConditionCode = GetConfig()
}

func GetConfig() (Host, Port, AesKey, AesIv, ConditionCode string) {
	Host = beego.AppConfig.String("host")
	Port = beego.AppConfig.String("httpport")
	AesKey = beego.AppConfig.String("aeskey")
	AesIv = beego.AppConfig.String("aesiv")
	ConditionCode = beego.AppConfig.String("condition_code")

	return
}

//获取当前文件执行的路径
func GetCurrPath() (string, string) {
	file, _ := exec.LookPath(os.Args[0])
	schedulerPath, _ := filepath.Abs(file)
	schedulerPath = strings.Replace(schedulerPath, "\\", "/", -1)
	return schedulerPath, string(schedulerPath[0:strings.LastIndex(schedulerPath, "/")])
}

func CacheVideoFile(m3u8FilePath, m3u8Url, signatures string) {
	var body string
	topUrl := strings.Replace(m3u8Url, "index.m3u8", "", -1)
	beego.Info(topUrl)

	//打开播放串地址，获得文件内容
	resp, err := http.Get(m3u8Url)
	if err != nil {
		beego.Error("读取文件失败", m3u8Url)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		beego.Error("网络错误，网络状态码", resp.StatusCode)
		return
	}
	playlist, _, err := m3u8.DecodeFrom(resp.Body, true)
	if err != nil {
		beego.Error("解析文件失败", err)
		return
	}
	mpl := playlist.(*m3u8.MediaPlaylist)
	targetDuration := mpl.TargetDuration

	//加密播放文件地址
	for _, v := range mpl.Segments {
		//生成随机key用来加密流
		key := GetRandomString(16)
		encryptKey, _ := CFBEncryptString(key+";"+signatures, AesKey)
		extXKey := fmt.Sprintf("METHOD=AES-128,URI=\"%s\",IV=0x%s", fmt.Sprintf("%s:%s/v1/key?str=%s", Host, Port, encryptKey), AesIv)
		if v != nil {
			strListChan <- fmt.Sprintf("%s/%s;%s", m3u8FilePath, v.URI, key)
			body += fmt.Sprintf("#EXT-X-KEY:%s\n#EXTINF:%0.3f,\n%s:%s/static/dst/%s\n", extXKey, v.Duration, Host, Port, v.URI)
		}
	}
	//拼接为m3u8文件
	content := fmt.Sprintf("#EXTM3U\n#EXT-X-VERSION:%d\n#EXT-X-TARGETDURATION:%0.0f\n#EXT-X-MEDIA-SEQUENCE:0\n%s#EXT-X-ENDLIST", mpl.Version(), targetDuration, body)
	WriteStringToFile(content, m3u8FilePath)
}

//加密文件
func EncryptTsFile(fileInfo string) {
	stringArr := strings.Split(fileInfo, ";")
	key := stringArr[1]
	srcUrl := strings.Replace(stringArr[0], "/dst/index.m3u8/", "/src/", -1)
	dstUrl := strings.Replace(stringArr[0], "/index.m3u8/", "/", -1)
	err := CBCEncryptFile(srcUrl, dstUrl, key, []byte(AesIv))
	if err != nil {
		beego.Error("加密文件失败")
	}
}

//多线程加密文件服务
func StartEncryptAndCache() {
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			for {
				fileInfo := <-strListChan
				EncryptTsFile(fileInfo)
			}
		}()
	}
}

func WriteStringToFile(content string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(file.Name(), []byte(content), 0644); err != nil {
		return err
	}
	return nil
}

//生成指定长度随机字符串
func GetRandomString(n int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rands.New(rands.NewSource(time.Now().UnixNano()))
	for i := 0; i < n; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

func CBCEncryptStream(content []byte, aeskey string, iv []byte) ([]byte, error) {
	key := []byte(aeskey)
	block, err := aes.NewCipher(key[0:16])
	if err != nil {
		return nil, err
	}
	content, err = PKCS7Padding(content, block.BlockSize())
	if err != nil {
		return nil, err
	}
	bm := cipher.NewCBCEncrypter(block, iv)
	bm.CryptBlocks(content, content)
	return content, nil
}

func CBCEncryptFile(source string, dist string, aeskey string, iv []byte) error {
	plaintext, err := ioutil.ReadFile(source)
	if err != nil {
		return err
	}
	key := []byte(aeskey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	plaintext, err = PKCS7Padding(plaintext, block.BlockSize())
	if err != nil {
		return err
	}
	bm := cipher.NewCBCEncrypter(block, iv)
	bm.CryptBlocks(plaintext, plaintext)
	f, err := os.Create(dist)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, bytes.NewReader(plaintext))
	if err != nil {
		return err
	}
	return nil
}

func CFBEncryptString(content, key string) (string, error) {
	plaintext := []byte(content)

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func CFBDecryptString(cryptoText, key string) (string, error) {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("密文不长度太短")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext), nil
}

//加密并生成新的m3u8
func EncryptM3u8(m3u8Url, signatures string) (string, error) {
	var body string

	topUrl := strings.Replace(m3u8Url, "index.m3u8", "", -1)
	beego.Info(topUrl)

	//打开播放串地址，获得文件内容
	resp, err := http.Get(m3u8Url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("网络错误，网络状态码:%d", resp.StatusCode)
	}
	playlist, _, err := m3u8.DecodeFrom(resp.Body, true)
	if err != nil {
		return "", err
	}
	mpl := playlist.(*m3u8.MediaPlaylist)
	targetDuration := mpl.TargetDuration

	//加密播放文件地址
	for _, v := range mpl.Segments {
		//生成随机key用来加密流
		key := GetRandomString(16)
		encryptKey, _ := CFBEncryptString(key+";"+signatures, AesKey)
		extXKey := fmt.Sprintf("METHOD=AES-128,URI=\"%s\",IV=0x%s", fmt.Sprintf("%s:%s/v1/key?str=%s", Host, Port, encryptKey), AesIv)
		if v != nil {
			tsUri, _ := CFBEncryptString(fmt.Sprintf("%s,%s/%s,%v", key+";"+signatures, topUrl, v.URI, time.Now().Unix()), AesKey)
			body += fmt.Sprintf("#EXT-X-KEY:%s\n#EXTINF:%0.3f,\n%s:%s/v1/play.ts?str=%s\n", extXKey, v.Duration, Host, Port, tsUri)
		}
	}
	//拼接为m3u8文件
	content := fmt.Sprintf("#EXTM3U\n#EXT-X-VERSION:%d\n#EXT-X-TARGETDURATION:%0.0f\n#EXT-X-MEDIA-SEQUENCE:0\n%s#EXT-X-ENDLIST", mpl.Version(), targetDuration, body)

	return content, nil
}

func MatchSignature(req *http.Request, signature string) bool {
	var isPass bool = false
	if ConditionCode != signature {
		return false
	}
	userAgent := req.UserAgent()
	authAgentArr := strings.Split(authAgent, "|")
	for k, v := range authAgentArr {
		isPass = strings.Contains(signature+userAgent, v)
		beego.Debug(k, userAgent, v, isPass)
		if isPass {
			break
		}
	}
	return isPass
}
