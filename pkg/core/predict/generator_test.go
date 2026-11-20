package predict

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRealConfigFiles(t *testing.T) {
	out := make(chan string, 64)
	done := make(chan struct{})
	go func() {
		for range out {
		}
		close(done)
	}()
	count, err := PredictDomains("test.example.com", out)
	close(out)
	<-done
	if err != nil {
		t.Fatalf("使用实际配置文件进行域名预测失败: %v", err)
	}
	t.Log(count)
	assert.Greater(t, count, 0)
}
