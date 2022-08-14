package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/yottachain/YTCrypto"
	"golang.org/x/sys/windows/registry"
)

//var cfgFile string

var keyID int
var privateKey string
var keyMgrIf string
var listenPort int64
var keyManageAddr string
var procName string
var auth string
var inherit string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "arvdaemon",
	Short: "配合ARV过滤服务拉起指定的子进程",
	Long: `版本号：1.0.0.0
	启动后该程序会在文件过滤服务中注册当前进程ID，然后拉起指定的子进程`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		port, kma, err := ReadRegistry()
		if err != nil {
			fmt.Printf("从注册表获取配置文件失败: %s\n", err)
			return
		}
		listenPort = port
		if keyManageAddr == "" {
			keyManageAddr = kma
		}
		arr := strings.Split(os.Args[0], "\\")
		fileName := arr[len(arr)-1]
		var CommandName string
		var CommandArgs []string
		fileNameBase := strings.Split(fileName, ".")[0]
		if fileNameBase != "arvdaemon" {
			file, err := exec.LookPath(os.Args[0])
			if err != nil {
				fmt.Printf("从ARV服务获取配置文件失败: %s\n", err)
				return
			}
			fullPath, err := filepath.Abs(file)
			if err != nil {
				fmt.Printf("从ARV服务获取配置文件失败: %s\n", err)
				return
			}
			data, err := GetDaemonConf(fullPath)
			if err != nil {
				fmt.Printf("从ARV服务获取配置文件失败: %s\n", err)
				return
			}
			keyID = data.KeyID
			if data.KeyManageAddr != "" {
				keyManageAddr = data.KeyManageAddr
			}
			if keyMgrIf == "" && keyManageAddr != "" {
				keyMgrIf = keyManageAddr
			}
			CommandName = data.ExeName
			CommandArgs = args

			//privateKey = "5KfsAaJJ5aBDtwcADVooBkmAR35VdQ19GWeRqrVbqs5euy4qKqR"
		} else {
			if len(args) > 0 {
				CommandName = args[0]
			}
			if len(args) > 1 {
				CommandArgs = args[1:]
			}
		}
		if procName != "" && auth != "true" && auth != "false" {
			fmt.Println("authorise参数不正确")
			return
		}
		if privateKey == "" && keyMgrIf == "" {
			fmt.Println("必须设置私钥或密钥管理系统URL")
			return
		}
		if privateKey == "" {
			resp, err := GetPublicKey(keyMgrIf, keyID)
			if err != nil {
				fmt.Printf("从密钥管理系统URL获取私钥失败：%s\n", err)
				return
			}
			privateKey = resp.Data.PrvKey
		}
		//timestr := time.Now().Format("15-04-05")
		inheritPH := 0
		if inherit == "true" {
			inheritPH = 1
		}
		timest := time.Now().Unix()
		msg := fmt.Sprintf("\\?SursenLogin?\\%d\\%d\\%d", keyID, timest, inheritPH)
		if procName != "" {
			if auth == "false" {
				msg = fmt.Sprintf("\\?SursenRegot?\\%d\\%s\\%d\\%d", keyID, procName, timest, inheritPH)
			} else {
				msg = fmt.Sprintf("\\?SursenRegin?\\%d\\%s\\%d\\%d", keyID, procName, timest, inheritPH)
			}
		}
		sig, err := YTCrypto.Sign(privateKey, []byte(msg))
		if err != nil {
			fmt.Println("签名失败")
			return
		}
		path := fmt.Sprintf("C:\\?SursenLogin?\\%d\\%d\\%d\\%s\\", keyID, timest, inheritPH, sig)
		if procName != "" {
			if auth == "false" {
				path = fmt.Sprintf("C:\\?SursenRegot?\\%d\\%s\\%d\\%d\\%s\\", keyID, procName, timest, inheritPH, sig)
			} else {
				path = fmt.Sprintf("C:\\?SursenRegin?\\%d\\%s\\%d\\%d\\%s\\", keyID, procName, timest, inheritPH, sig)
			}
		}
		f, err := os.Create(path)
		if err != nil {
			if procName != "" {
				if auth == "false" {
					fmt.Printf("进程%s清除授权失败: %s\n", procName, err.Error())
				} else {
					fmt.Printf("进程%s授权失败：%s\n", procName, err.Error())
				}
			} else {
				fmt.Printf("进程注册失败：%s\n", err.Error())
			}
			return
		} else {
			f.Close()
		}
		if procName != "" {
			if auth == "false" {
				fmt.Printf("进程%s清除授权成功\n", procName)
			} else {
				fmt.Printf("进程%s授权成功：%d\n", procName, keyID)
			}
			return
		}
		fmt.Printf("注册进程ID：%d\n", os.Getpid())
		fmt.Printf("注册密钥ID：%d\n", keyID)
		childCmd := exec.Command(CommandName, CommandArgs...)
		fmt.Print("启动进程：")
		fmt.Println(args)
		// stdout, err := childCmd.StdoutPipe()
		// childCmd.Stderr = childCmd.Stdout
		// if err != nil {
		// 	panic(err)
		// }
		// stdoutBuf := bufio.NewReader(stdout)
		//var stdoutBuf, stderrBuf bytes.Buffer
		//childCmd.Stdout = io.MultiWriter(os.Stdout, &stdoutBuf)
		//childCmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)
		childCmd.Stdout = os.Stdout
		childCmd.Stderr = os.Stderr
		childCmd.Stdin = os.Stdin
		childCmd.Env = append(childCmd.Env, os.Environ()...)
		err = childCmd.Start()
		if err != nil {
			panic(err)
		}
		// for {
		// 	line, _, err := stdoutBuf.ReadLine()
		// 	if err == io.EOF {
		// 		break
		// 	}
		// 	fmt.Println(string(line))

		// }
		childCmd.Wait()
		//timestr = time.Now().Format("15-04-05")
		// timest = time.Now().Unix()
		// msg = fmt.Sprintf("\\?SursenLogot?\\%d\\%d", keyID, timest)
		// sig, err = YTCrypto.Sign(privateKey, []byte(msg))
		// if err != nil {
		// 	fmt.Println("签名失败")
		// 	return
		// }
		// path = fmt.Sprintf("C:\\?SursenLogot?\\%d\\%d\\%s\\", keyID, timest, sig)
		// f, err = os.Create(path)
		// if err != nil {
		// 	fmt.Println("进程退出失败")
		// 	return
		// } else {
		// 	f.Close()
		// 	fmt.Printf("注销进程ID：%d\n", os.Getpid())
		// }
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
	cobra.MousetrapHelpText = ""
	rootCmd.Flags().IntVarP(&keyID, "key-id", "u", 0, "私钥编号")
	rootCmd.Flags().StringVarP(&privateKey, "privatekey", "p", "", "Base58编码形式的私钥")
	rootCmd.Flags().StringVarP(&keyMgrIf, "key-manager-interface", "m", "", "密钥管理服务的接口地址，使用-p参数会覆盖本配置")
	rootCmd.Flags().StringVarP(&procName, "reg-proc-name", "r", "", "授权的进程名")
	rootCmd.Flags().StringVarP(&auth, "authorise", "a", "", "对指定进程授权或取消")
	rootCmd.Flags().StringVarP(&inherit, "inherit", "i", "false", "是否对子进程自动授权")
}

type PubKeyResp struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    *PrvKeyData `json:"data"`
}

type DaemonConfResp struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data *DaemonConfItem `json:"data"`
}
type DaemonConfItem struct {
	DaemonName    string `json:"daemonName"`
	ExeName       string `json:"exeName"`
	KeyID         int    `json:"keyID"`
	KeyManageAddr string `json:"url"`
}

type PrvKeyData struct {
	PrvKey string `json:"prvKey"`
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

func GetDaemonConf(daemonName string) (*DaemonConfItem, error) {
	rep := []byte{filepath.Separator, filepath.Separator}
	daemonName = strings.Replace(daemonName, string(filepath.Separator), string(rep), -1)
	post := "{\"name\":\"loaddaemonconf\",\"daemonName\":\"" + daemonName + "\"}"
	//fmt.Println(daemonName)
	var jsonStr = []byte(post)
	req, err := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d", listenPort), bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reader := io.Reader(resp.Body)
	response := new(DaemonConfResp)
	err = json.NewDecoder(reader).Decode(&response)
	if err != nil {
		return nil, err
	}
	if response.Code != 0 {
		return nil, errors.New(response.Msg)
	}
	return response.Data, nil
}

func ReadRegistry() (int64, string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\ArvCtl", registry.READ)
	if err != nil {
		return -1, "", err
	}
	defer key.Close()
	kma, _, err := key.GetStringValue("keyManageAddr")
	if err != nil {
		return -1, "", err
	}
	port, _, err := key.GetIntegerValue("listenPort")
	if err != nil {
		return -1, "", err
	}
	fmt.Printf("Port: %d\n", port)
	fmt.Printf("KeyManageAddr: %s\n", kma)
	return int64(port), kma, nil
}
