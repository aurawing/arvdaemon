package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
	"github.com/yottachain/YTCrypto"
)

//var cfgFile string

var keyID int
var privateKey string
var keyMgrIf string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "arvdaemon",
	Short: "配合ARV过滤服务拉起指定的子进程",
	Long:  `启动后该程序会在文件过滤服务中注册当前进程ID，然后拉起指定的子进程`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		if keyID == 0 {
			fmt.Println("密钥ID不能为空")
			return
		}
		if privateKey == "" && keyMgrIf == "" {
			fmt.Println("必须设置私钥或密钥管理系统URL")
			return
		}
		if privateKey == "" {
			resp, err := GetPublicKey(keyMgrIf, keyID)
			if err != nil {
				fmt.Printf("从密钥管理系统URL获取私钥失败：%s\n", resp.Message)
				return
			}
			privateKey = resp.Data.PubKey
		}
		//timestr := time.Now().Format("15-04-05")
		timest := time.Now().Unix()
		msg := fmt.Sprintf("\\?SursenLogin?\\%d\\%d", keyID, timest)
		sig, err := YTCrypto.Sign(privateKey, []byte(msg))
		if err != nil {
			fmt.Println("签名失败")
			return
		}
		path := fmt.Sprintf("C:\\?SursenLogin?\\%d\\%d\\%s\\", keyID, timest, sig)
		f, err := os.Create(path)
		if err != nil {
			fmt.Printf("进程注册失败：%s\n", err.Error())
			return
		} else {
			f.Close()
		}
		fmt.Printf("注册进程ID：%d\n", os.Getpid())
		fmt.Printf("注册密钥ID：%d\n", keyID)
		childCmd := exec.Command(args[0], args[1:]...)
		fmt.Print("启动进程：")
		fmt.Println(args)
		stdout, err := childCmd.StdoutPipe()
		childCmd.Stderr = childCmd.Stdout
		if err != nil {
			panic(err)
		}
		stdoutBuf := bufio.NewReader(stdout)
		err = childCmd.Start()
		if err != nil {
			panic(err)
		}
		for {
			line, _, err := stdoutBuf.ReadLine()
			if err == io.EOF {
				break
			}
			fmt.Println(string(line))

		}
		childCmd.Wait()
		//timestr = time.Now().Format("15-04-05")
		timest = time.Now().Unix()
		msg = fmt.Sprintf("\\?SursenLogot?\\%d\\%d", keyID, timest)
		sig, err = YTCrypto.Sign(privateKey, []byte(msg))
		if err != nil {
			fmt.Println("签名失败")
			return
		}
		path = fmt.Sprintf("C:\\?SursenLogot?\\%d\\%d\\%s\\", keyID, timest, sig)
		f, err = os.Create(path)
		if err != nil {
			fmt.Println("进程退出失败")
			return
		} else {
			f.Close()
			fmt.Printf("注销进程ID：%d\n", os.Getpid())
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().IntVarP(&keyID, "key-id", "u", 0, "私钥编号")
	rootCmd.Flags().StringVarP(&privateKey, "privatekey", "p", "", "Base58编码形式的私钥")
	rootCmd.Flags().StringVarP(&keyMgrIf, "key-manager-interface", "m", "", "密钥管理服务的接口地址，使用-p参数会覆盖本配置")
}

type PubKeyResp struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    *PubKeyData `json:"data"`
}

type PubKeyData struct {
	PubKey string `json:"pubKey"`
}

func GetPublicKey(url string, keyID int) (*PubKeyResp, error) {
	fullURL := fmt.Sprintf("%s/api/encryption/key/v1/getprv?id=%d", url, keyID)
	resp, err := http.Get(fullURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reader := io.Reader(resp.Body)
	response := new(PubKeyResp)
	err = json.NewDecoder(reader).Decode(&response)
	if err != nil {
		return nil, err
	}
	if response.Code != 1000 {
		return nil, errors.New(response.Message)
	}
	return response, nil
}
