package dget

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/klauspost/compress/zstd"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// const _registry = "registry-1.docker.io"
const _authUrl = "https://auth.docker.io/token"
const _regService = "registry.docker.io"

type LayerInfo struct {
	Id      string    `json:"id"`
	Parent  string    `json:"parent"`
	Created time.Time `json:"created"`

	ContainerConfig struct {
		Hostname     string
		Domainname   string
		User         string
		AttachStdin  bool
		AttachStdout bool
		AttachStderr bool
		Tty          bool
		OpenStdin    bool
		StdinOnce    bool
		Env          []string
		CMd          []string
		Image        string
		Volumes      map[string]interface{}
		WorkingDir   string
		Entrypoint   []string
		OnBuild      []string
		Labels       map[string]interface{}
	} `json:"container_config"`
}

type Layer struct {
	MediaType string   `json:"mediaType,omitempty"`
	Digest    string   `json:"digest"`
	Size      int64    `json:"size,omitempty"`
	Urls      []string `json:"urls,omitempty"`
}

type Info struct {
	Layers []Layer `json:"layers"`
	Config struct {
		Digest digest.Digest `json:"digest,omitempty"`
	} `json:"config"`
}

type PackageConfig struct {
	Config   string
	RepoTags []string
	Layers   []string
}

type Client struct {
	c *http.Client
}

type TagList struct {
	Name string
	Tags []string
}

type SyncSignal struct{}

func (m *Client) SetClient(c *http.Client) {
	m.c = c
}

func (m *Client) Install(syncCount int, _registry, d, tag string, arch string, printInfo bool, onlyGetTag bool, username string, password string) (err error) {
	var authUrl = _authUrl
	var regService = _regService

	resp, err := m.c.Get(fmt.Sprintf("https://%s/v2/", _registry))
	if err != nil {
		return err
	}

	if !strings.Contains(d, "/") {
		d = "library/" + d
	}

	if resp.StatusCode == 401 {
		// Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
		var hAuths = strings.Split(resp.Header.Get("Www-Authenticate"), "\"")
		logrus.Debugln("Www-Authenticate", hAuths)
		if len(hAuths) > 1 {
			authUrl = hAuths[1]
		}
		if len(hAuths) > 3 {
			regService = hAuths[3]
		} else {
			regService = _registry
		}
	}
	resp.Body.Close()

	var accessToken string
	logrus.Debugln("reg_service", regService)
	logrus.Debugln("authUrl", authUrl)

	if username != "" && password != "" {
		accessToken, err = m.getTokenWithBasicAuth(authUrl, regService, d, username, password)
	} else {
		accessToken, err = m.getAuthHead(authUrl, regService, d)
	}
	if err != nil {
		return err
	}

	var req *http.Request
	if onlyGetTag {
		var tagListURL = fmt.Sprintf("https://%s/v2/%s/tags/list", _registry, d)
		logrus.Debugln("tags request", tagListURL)
		req, err = http.NewRequest("GET", tagListURL, nil)
		if err != nil {
			return err
		}
		req.Header.Add("Authorization", "Bearer "+accessToken)

		resp, err = m.c.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode == 200 {
			var bts []byte
			bts, err = io.ReadAll(resp.Body)
			logrus.Debugln("tags response", string(bts))
			if err == nil {
				var tagList TagList
				err = json.Unmarshal(bts, &tagList)
				if err == nil && len(tagList.Tags) > 0 {
					tag = tagList.Tags[0]
					fmt.Println("获取到的tag列表为:")
					fmt.Println(strings.Join(tagList.Tags, ","))
					resp.Body.Close()
					return nil
				}
			}
		}
		resp.Body.Close()
	}

	var manifestURL = fmt.Sprintf("https://%s/v2/%s/manifests/%s", _registry, d, tag)
	req, err = http.NewRequest("GET", manifestURL, nil)
	logrus.Infoln("获取manifests信息", manifestURL)
	if err != nil {
		return err
	}

	logrus.Debugln("Authorization by", accessToken)
	req.Header.Add("Authorization", "Bearer "+accessToken)
	// 请求 manifest list / index（多架构）
	req.Header.Add("Accept", "application/vnd.docker.distribution.manifest.list.v2+json")
	req.Header.Add("Accept", "application/vnd.oci.image.index.v1+json")
	var authHeader = req.Header

	resp, err = m.c.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		bts, er := io.ReadAll(resp.Body)
		resp.Body.Close()
		logrus.Debugln(string(bts), er)
		switch resp.StatusCode {
		case 401:
			logrus.Errorf("[-] Cannot fetch manifest for %s [HTTP %d] with error access_token", d, resp.StatusCode)
		case 404:
			logrus.Errorf("[-] Cannot fetch manifest for %s [HTTP %d] with url %s", d, resp.StatusCode, manifestURL)
		}
		// TODO: better error handling
		os.Exit(1)
	}

	var bts []byte
	bts, err = io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		return err
	}

	logrus.WithField("Content-Type", resp.Header.Get("Content-Type")).Debugln("Get manifest list")
	switch resp.Header.Get("Content-Type") {
	case "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.oci.image.index.v1+json":
		var info manifestlist.ManifestList
		err = json.Unmarshal(bts, &info)
		if err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()

		logrus.Infof("获得%d个架构信息:", len(info.Manifests))
		var selectedManifest *manifestlist.ManifestDescriptor
		for i := 0; i < len(info.Manifests); i++ {
			var md = info.Manifests[i]
			logrus.Infof("[%d]架构:%s,OS:%s", i+1, md.Platform.Architecture, md.Platform.OS)
			if md.Platform.OS+"/"+md.Platform.Architecture == arch {
				logrus.Infoln("找到匹配的架构,开始下载")
				selectedManifest = &md
				req.URL, _ = url.Parse(fmt.Sprintf("https://%s/v2/%s/manifests/%s", _registry, d, md.Digest.String()))
				break
			}
		}

		if printInfo {
			fmt.Println(string(bts))
			os.Exit(0)
		}

		if selectedManifest == nil {
			return errors.New("未找到匹配的架构:" + arch)
		}

		logrus.Debug("找到的架构信息为", selectedManifest)
		req.Header.Set("Accept", selectedManifest.MediaType)

	case "application/vnd.docker.distribution.manifest.v1+prettyjws":
		resp.Body.Close()
		req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	default:
		resp.Body.Close()
		// 兜底：尝试按 schema2 manifest 拉一次
		req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	}

	resp, err = m.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var info Info
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return err
	}

	logrus.Infof("获得Manifest信息，共%d层需要下载", len(info.Layers))
	err = m.download(syncCount, _registry, d, tag, info.Config.Digest, authHeader, info.Layers)
	if err != nil {
		return err
	}

	return nil
}

func (m *Client) getTokenWithBasicAuth(urlStr, service, repository, username, password string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		logrus.Fatal(err)
		return "", err
	}

	req.SetBasicAuth(username, password)
	query := req.URL.Query()
	query.Add("service", service)
	query.Add("scope", fmt.Sprintf("repository:%s:pull", repository))
	req.URL.RawQuery = query.Encode()

	resp, err := m.c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var results map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&results)
	logrus.Debug(results)
	if err == nil && results["token"] != nil {
		return results["token"].(string), nil
	}
	return "", err
}

// download 函数已修复：移除 goto，改用 if-else
func (m *Client) download(syncCount int, _registry, d, tag string, digest digest.Digest, authHeader http.Header, layers []Layer) (err error) {
	var tmpDir = fmt.Sprintf("tmp_%s_%s", d, tag)
	err = os.MkdirAll(tmpDir, 0777)
	if err != nil {
		return err
	}

	// 检查缓存
	if _, e := os.Stat(filepath.Join(tmpDir, "repositories")); e == nil {
		logrus.Info(tmpDir, " is downloaded,use dir as cache")
	} else {
		// 缓存不存在，开始下载逻辑
		var req *http.Request
		req, err = http.NewRequest("GET", fmt.Sprintf("https://%s/v2/%s/blobs/%s", _registry, d, digest), nil)
		if err != nil {
			return err
		}
		req.Header = authHeader

		var resp *http.Response
		resp, err = m.c.Do(req)
		if err != nil {
			return err
		}

		var dest *os.File
		dest, err = os.OpenFile(filepath.Join(tmpDir, digest.Encoded()+".json"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			resp.Body.Close()
			return err
		}

		var bts []byte
		bts, err = ioutil.ReadAll(resp.Body)
		var lastLayerInfo LayerInfo
		_ = json.Unmarshal(bts, &lastLayerInfo)
		resp.Body.Close()

		var config []PackageConfig
		config = append(config, PackageConfig{
			Config:   digest.Encoded() + ".json",
			RepoTags: []string{d + ":" + tag},
		})

		if err != nil {
			dest.Close()
			return err
		}

		_, err = io.Copy(dest, bytes.NewReader(bts))
		dest.Close()
		if err != nil {
			return err
		}

		parentid := ""
		var fakeLayerId string
		var downloadStatus = make(map[int]bool)
		var notifyChan = make(chan int, 1)
		var ch = make(chan SyncSignal, syncCount)

		for n, layer := range layers {
			namer := sha256.New()
			namer.Write([]byte(parentid + "\n" + layer.Digest + "\n"))
			fakeLayerId = hex.EncodeToString(namer.Sum(nil))
			logrus.Infoln("handle layer", n, fakeLayerId, layer.Urls)

			var layerInfo LayerInfo
			if n == len(layers)-1 {
				layerInfo = lastLayerInfo
			}
			layerInfo.Id = fakeLayerId
			if parentid != "" {
				layerInfo.Parent = parentid
			}

			config[0].Layers = append(config[0].Layers, fakeLayerId+"/layer.tar")

			var copyedHeader = make(http.Header)
			for k, v := range authHeader {
				copyedHeader[k] = v
			}

			go func(fakeLayerId string, layer Layer, n int, notifyChan chan int, layerInfo *LayerInfo, tmpDir string, _registry string, d string, authHeader http.Header) {
				ch <- SyncSignal{}
				er := m.downloadLayer(fakeLayerId, &layer, layerInfo, tmpDir, _registry, d, authHeader)
				if er != nil {
					logrus.Errorf("下载第%d/%d层失败:%s", n+1, len(layers), err)
					err = er
				}
				notifyChan <- n
				<-ch
			}(fakeLayerId, layer, n, notifyChan, &layerInfo, tmpDir, _registry, d, copyedHeader)

			parentid = fakeLayerId
		}

		for len(downloadStatus) < len(layers) {
			n := <-notifyChan
			downloadStatus[n] = true
			if len(downloadStatus) == len(layers) {
				close(notifyChan)
				logrus.Infof("[%d/%d]下载完成", len(downloadStatus), len(layers))
				break
			}
			logrus.Infof("[%d/%d]第%d层下载完成", len(downloadStatus), len(layers), n+1)
		}

		if err != nil {
			return err
		}

		var manifest *os.File
		logrus.Debugln("write manifest to", filepath.Join(tmpDir, "manifest.json"))
		manifest, err = os.OpenFile(filepath.Join(tmpDir, "manifest.json"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			return err
		}

		err = json.NewEncoder(manifest).Encode(&config)
		if err != nil {
			manifest.Close()
			return err
		}
		manifest.Close()

		var repositories = make(map[string]interface{})
		repositories[d] = map[string]string{
			tag: fakeLayerId,
		}

		var rFile *os.File
		rFile, err = os.OpenFile(filepath.Join(tmpDir, "repositories"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			return err
		}
		err = json.NewEncoder(rFile).Encode(&repositories)
		rFile.Close()
		if err != nil {
			return err
		}
	}

	// 最后的打包逻辑 (相当于之前的 maketar 标签)
	if err == nil {
		err = writeDirToTarGz(tmpDir, tmpDir+"-img.tar.gz")
		if err == nil {
			fmt.Println("write tar success", tmpDir+"-img.tar.gz")
		} else {
			logrus.Debugln("write tar fail", err)
		}
	}
	return err
}

func (m *Client) getAuthHead(a, r, d string) (string, error) {
	var regUrl = fmt.Sprintf("%s?service=%s&scope=repository:%s:pull", a, r, d)
	logrus.Debug("get auth head from ", regUrl)
	resp, err := m.c.Get(regUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var results map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&results)
	logrus.Debug(results)
	if err != nil {
		return "", err
	}

	var accessToken string
	if results["access_token"] != nil {
		accessToken = results["access_token"].(string)
	} else if results["token"] != nil {
		accessToken = results["token"].(string)
	}

	if accessToken != "" {
		return accessToken, nil
	}
	return "", errors.New("access_token is empty")
}

func writeDirToTarGz(sourcedir, destinationfile string) error {
	gzFile, err := os.Create(destinationfile)
	if err != nil {
		return err
	}
	gf := gzip.NewWriter(gzFile)
	tw := tar.NewWriter(gf)

	logrus.Debug("write tgz file to ", destinationfile)

	defer func() {
		tw.Close()
		gf.Close()
		gzFile.Close()
	}()

	return filepath.Walk(sourcedir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(sourcedir, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}

		logrus.Debugln("write", relPath)
		header, err := tar.FileInfoHeader(info, path)
		if err != nil {
			return err
		}

		// must provide real name (see archive/tar behavior)
		header.Name = filepath.ToSlash(relPath)

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !info.IsDir() {
			data, err := os.Open(path)
			if err != nil {
				return err
			}
			defer data.Close()

			if _, err := io.Copy(tw, data); err != nil {
				return err
			}
		}
		return nil
	})
}

func SetLogLevel(lvl logrus.Level) {
	logrus.SetLevel(lvl)
	logrus.Debugln("设置日志级别为", lvl)
}

func isGzipMagic(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

func isZstdMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x28 && b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd
}

func (m *Client) downloadLayer(fakeLayerId string, layer *Layer, layerInfo *LayerInfo, tmpDir string, _registry string, d string, authHeader http.Header) error {
	layerDirName := filepath.Join(tmpDir, fakeLayerId)
	err := os.Mkdir(layerDirName, 0777)

	if _, er := os.Stat(filepath.Join(layerDirName, "layer.tar")); er == nil {
		logrus.Infoln("layer", fakeLayerId, "is existed, continue")
		return nil
	}

	if err != nil && !os.IsExist(err) {
		return err
	}

	err = ioutil.WriteFile(filepath.Join(layerDirName, "VERSION"), []byte("1.0"), 0666)
	if err != nil {
		return err
	}

	var req *http.Request
	req, err = http.NewRequest("GET", fmt.Sprintf("https://%s/v2/%s/blobs/%s", _registry, d, layer.Digest), nil)
	if err != nil {
		return err
	}

	req.Header = authHeader
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	var resp *http.Response
	resp, err = m.c.Do(req)
	if err != nil {
		return errors.Wrap(err, "请求失败")
	}

	// 允许走 layer.Urls 兜底
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		if len(layer.Urls) > 0 {
			req, err = http.NewRequest("GET", layer.Urls[0], nil)
			if err != nil {
				return err
			}
			req.Header = authHeader
			req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

			resp, err = m.c.Do(req)
			if err != nil {
				return errors.Wrap(err, "请求失败")
			}
			if resp.StatusCode != 200 {
				resp.Body.Close()
				return fmt.Errorf("download from customized url fail")
			}
		} else {
			bts, _ := ioutil.ReadAll(resp.Body)
			logrus.Fatalln("下载失败", string(bts))
		}
	}

	defer resp.Body.Close()

	var dst *os.File
	dst, err = os.OpenFile(filepath.Join(layerDirName, "layer.tar.part"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer dst.Close()

	// 关键修改：不再强制 gzip 解压，而是根据 mediaType / 文件头判断 gzip、zstd 或未压缩 tar
	br := bufio.NewReader(resp.Body)

	mediaType := strings.ToLower(layer.MediaType)
	var reader io.Reader = br

	var gzReader *gzip.Reader
	var zstdReader *zstd.Decoder

	switch {
	case strings.Contains(mediaType, "zstd"):
		zstdReader, err = zstd.NewReader(br)
		if err != nil {
			return err
		}
		defer zstdReader.Close()
		reader = zstdReader

	case strings.Contains(mediaType, "gzip"):
		gzReader, err = gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gzReader.Close()
		reader = gzReader

	default:
		// mediaType 不可靠/为空时：魔数探测
		magic, _ := br.Peek(4)
		if isZstdMagic(magic) {
			zstdReader, err = zstd.NewReader(br)
			if err != nil {
				return err
			}
			defer zstdReader.Close()
			reader = zstdReader
		} else if isGzipMagic(magic) {
			gzReader, err = gzip.NewReader(br)
			if err != nil {
				return err
			}
			defer gzReader.Close()
			reader = gzReader
		} else {
			// 当作未压缩 tar 直接写出
			reader = br
		}
	}

	_, err = io.Copy(dst, reader)
	if err != nil {
		return errors.Wrap(err, "下载失败")
	}

	var jsonFile *os.File
	jsonFile, err = os.OpenFile(filepath.Join(layerDirName, "json"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	err = json.NewEncoder(jsonFile).Encode(layerInfo)
	jsonFile.Close()
	if err != nil {
		return err
	}

	err = os.Rename(filepath.Join(layerDirName, "layer.tar.part"), filepath.Join(layerDirName, "layer.tar"))
	if err != nil {
		return errors.Wrap(err, "下载失败")
	}

	return nil
}
