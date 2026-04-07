package handler

import (
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/labstack/echo/v4"
)

func signerContextFromEcho(ctx echo.Context) *evidencesvc.SignerContext {
	if claims, ok := ctx.Get("user").(*authn.UserClaims); ok && claims != nil {
		return evidencesvc.NewUserSignerContextFromClaims(claims)
	}
	if agentAuth, ok := ctx.Get("agent_auth").(*middleware.AgentAuthContext); ok && agentAuth != nil {
		return evidencesvc.NewAgentSignerContext(agentAuth.Claims, agentAuth.Agent, agentAuth.Key)
	}
	return nil
}
