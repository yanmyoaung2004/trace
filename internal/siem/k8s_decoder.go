package siem

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type k8sAuditEvent struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Level      string `json:"level"`
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`
	RequestURI string `json:"requestURI"`
	Verb       string `json:"verb"`
	User       struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
		UID      string   `json:"uid"`
	} `json:"user"`
	ImpersonatedUser *struct {
		Username string `json:"username"`
	} `json:"impersonatedUser,omitempty"`
	SourceIPs []string `json:"sourceIPs"`
	UserAgent string   `json:"userAgent"`
	ObjectRef *struct {
		Resource     string `json:"resource"`
		Namespace    string `json:"namespace"`
		Name         string `json:"name"`
		APIGroup     string `json:"apiGroup"`
		APIVersion   string `json:"apiVersion"`
		Subresource  string `json:"subresource"`
	} `json:"objectRef,omitempty"`
	ResponseStatus *struct {
		Code    int    `json:"code"`
		Reason  string `json:"reason"`
		Status  string `json:"status"`
	} `json:"responseStatus,omitempty"`
	RequestObject  any `json:"requestObject,omitempty"`
	ResponseObject any `json:"responseObject,omitempty"`
}

type K8sAuditDecoder struct{}

func (d *K8sAuditDecoder) Name() string { return "k8s_audit" }

func (d *K8sAuditDecoder) Decode(raw []byte) (*Event, error) {
	line := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(line, "{") {
		return nil, fmt.Errorf("not JSON")
	}
	if !strings.Contains(line, `"kind":"Event"`) && !strings.Contains(line, `"kind": "Event"`) {
		return nil, fmt.Errorf("not K8s audit event")
	}

	var evt k8sAuditEvent
	if err := json.Unmarshal(raw, &evt); err != nil {
		return nil, fmt.Errorf("k8s parse: %w", err)
	}

	if evt.Kind != "Event" || evt.AuditID == "" {
		return nil, fmt.Errorf("not K8s audit event")
	}

	fields := make(map[string]any)
	fields["audit_id"] = evt.AuditID
	fields["user"] = evt.User.Username
	fields["verb"] = evt.Verb
	fields["request_uri"] = evt.RequestURI
	fields["stage"] = evt.Stage
	fields["level"] = evt.Level
	fields["source_ips"] = evt.SourceIPs

	if evt.ImpersonatedUser != nil {
		fields["impersonated_user"] = evt.ImpersonatedUser.Username
	}

	if evt.ObjectRef != nil {
		fields["resource"] = evt.ObjectRef.Resource
		fields["namespace"] = evt.ObjectRef.Namespace
		fields["name"] = evt.ObjectRef.Name
		fields["api_group"] = evt.ObjectRef.APIGroup
		fields["api_version"] = evt.ObjectRef.APIVersion
		if evt.ObjectRef.Subresource != "" {
			fields["subresource"] = evt.ObjectRef.Subresource
		}
	}

	if evt.ResponseStatus != nil {
		fields["response_code"] = evt.ResponseStatus.Code
		fields["response_reason"] = evt.ResponseStatus.Reason
	}

	sev := levelToK8sSeverity(evt.Level)
	tags := []string{"k8s", "kubernetes"}

	resource := ""
	verb := evt.Verb
	if evt.ObjectRef != nil {
		resource = evt.ObjectRef.Resource
		if evt.ObjectRef.Subresource != "" {
			resource = resource + "/" + evt.ObjectRef.Subresource
		}
	}

	fields["k8s_resource"] = resource

	switch {
	case resource == "pods/exec" && verb == "create":
		tags = append(tags, "k8s:exec")
		if sev < 3 { sev = 3 }
	case resource == "secrets" && verb == "get":
		tags = append(tags, "k8s:secret-access")
		if sev < 4 { sev = 4 }
	case resource == "secrets" && verb == "list":
		tags = append(tags, "k8s:secret-access")
		if sev < 3 { sev = 3 }
	case strings.Contains(resource, "clusterrole"):
		tags = append(tags, "k8s:rbac-change")
		if sev < 4 { sev = 4 }
	case strings.Contains(resource, "rolebinding") || strings.Contains(resource, "clusterrolebinding"):
		tags = append(tags, "k8s:rbac-change")
		if sev < 4 { sev = 4 }
	case verb == "impersonate":
		tags = append(tags, "k8s:impersonation")
		if sev < 4 { sev = 4 }
	case evt.ResponseStatus != nil && evt.ResponseStatus.Code >= 403:
		tags = append(tags, "k8s:unauthorized")
		if sev < 2 { sev = 2 }
	case verb == "create" && resource == "pods":
		tags = append(tags, "k8s:pod-create")
	case verb == "delete":
		tags = append(tags, "k8s:delete")
	}

	return &Event{
		Timestamp: time.Now().UTC(),
		Source:    "decoder:k8s_audit",
		Raw:       string(raw),
		Fields:    fields,
		Tags:      tags,
		Severity:  sev,
	}, nil
}

func levelToK8sSeverity(level string) int {
	switch level {
	case "RequestResponse":
		return 2
	case "Request":
		return 1
	case "Metadata":
		return 0
	default:
		return 1
	}
}

var _ Decoder = (*K8sAuditDecoder)(nil)
