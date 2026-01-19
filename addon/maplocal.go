package addon

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/denisvmedia/go-mitmproxy/internal/helper"
	"github.com/denisvmedia/go-mitmproxy/proxy"
)

type mapLocalTo struct {
	Path string
}

type mapLocalItem struct {
	From   *mapFrom
	To     *mapLocalTo
	Enable bool
}

func (itm *mapLocalItem) match(req *proxy.Request) bool {
	if !itm.Enable {
		return false
	}
	return itm.From.match(req)
}

func (itm *mapLocalItem) response(req *proxy.Request) (string, *proxy.Response) {
	getStat := func(filepath string) (fs.FileInfo, *proxy.Response) {
		stat, err := os.Stat(filepath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, &proxy.Response{
					StatusCode: 404,
				}
			}
			slog.Error("map local os.Stat error", "path", filepath, "error", err)
			return nil, &proxy.Response{
				StatusCode: 500,
			}
		}
		return stat, nil
	}

	respFile := func(filepath string) *proxy.Response {
		file, err := os.Open(filepath)
		if err != nil {
			slog.Error("map local os.Open error", "path", filepath, "error", err)
			return &proxy.Response{
				StatusCode: 500,
			}
		}
		return &proxy.Response{
			StatusCode: 200,
			BodyReader: file,
		}
	}

	stat, resp := getStat(itm.To.Path)
	if resp != nil {
		return itm.To.Path, resp
	}

	if !stat.IsDir() {
		return itm.To.Path, respFile(itm.To.Path)
	}

	// is dir
	subPath := req.URL.Path
	if itm.From.Path != "" && strings.HasSuffix(itm.From.Path, "/*") {
		subPath = req.URL.Path[len(itm.From.Path)-2:]
	}
	filepath := path.Join(itm.To.Path, subPath)

	stat, resp = getStat(filepath)
	if resp != nil {
		return filepath, resp
	}

	if !stat.IsDir() {
		return filepath, respFile(filepath)
	}
	slog.Error("map local path should be file", "path", filepath)
	return filepath, &proxy.Response{
		StatusCode: 500,
	}
}

type MapLocal struct {
	proxy.BaseAddon
	Items  []*mapLocalItem
	Enable bool
}

func (ml *MapLocal) Requestheaders(f *proxy.Flow) {
	if !ml.Enable {
		return
	}
	for _, item := range ml.Items {
		if item.match(f.Request) {
			aurl := f.Request.URL.String()
			localfile, resp := item.response(f.Request)
			slog.Info("map local", "from", aurl, "to", localfile)
			f.Response = resp
			return
		}
	}
}

func (ml *MapLocal) validate() error {
	for i, item := range ml.Items {
		if item.From == nil {
			return fmt.Errorf("%v no item.From", i)
		}
		if item.From.Protocol != "" && item.From.Protocol != "http" && item.From.Protocol != "https" {
			return fmt.Errorf("%v invalid item.From.Protocol %v", i, item.From.Protocol)
		}
		if item.To == nil {
			return fmt.Errorf("%v no item.To", i)
		}
		if item.To.Path == "" {
			return fmt.Errorf("%v empty item.To.Path", i)
		}
	}
	return nil
}

func NewMapLocalFromFile(filename string) (*MapLocal, error) {
	var mapLocal MapLocal
	if err := helper.NewStructFromFile(filename, &mapLocal); err != nil {
		return nil, err
	}
	if err := mapLocal.validate(); err != nil {
		return nil, err
	}
	return &mapLocal, nil
}
