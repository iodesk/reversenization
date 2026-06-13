package service

import "github.com/vibeswaf/waf/internal/pipeline"

type pipelineContextAdapter struct {
	ctx *pipeline.Context
}

func (a *pipelineContextAdapter) GetClientIP() string {
	return a.ctx.ClientIP
}

func (a *pipelineContextAdapter) GetHost() string {
	return a.ctx.Normalized.Host
}

func (a *pipelineContextAdapter) GetPath() string {
	return a.ctx.Normalized.Path
}

func (a *pipelineContextAdapter) GetQuery() string {
	return a.ctx.Normalized.Query
}

func (a *pipelineContextAdapter) GetMethod() string {
	return a.ctx.Normalized.Method
}

func (a *pipelineContextAdapter) GetUserAgent() string {
	return a.ctx.Normalized.UA
}

func (a *pipelineContextAdapter) GetHeader(key string) string {
	return a.ctx.Request.Header.Get(key)
}

func (a *pipelineContextAdapter) GetScheme() string {
	if a.ctx.Request.TLS != nil {
		return "https"
	}
	return "http"
}

func (a *pipelineContextAdapter) GetProto() string {
	return a.ctx.Request.Proto
}

func (a *pipelineContextAdapter) IsTLS() bool {
	return a.ctx.Request.TLS != nil
}

func (a *pipelineContextAdapter) GetMetadata() map[string]interface{} {
	return a.ctx.GetMetadata()
}
