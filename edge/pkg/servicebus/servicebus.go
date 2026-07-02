package servicebus

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"

	"github.com/kubeedge/api/apis/componentconfig/edgecore/v1alpha2"
	"github.com/kubeedge/beehive/pkg/core"
	beehiveContext "github.com/kubeedge/beehive/pkg/core/context"
	beehiveModel "github.com/kubeedge/beehive/pkg/core/model"
	commonType "github.com/kubeedge/kubeedge/common/types"
	"github.com/kubeedge/kubeedge/edge/pkg/common/message"
	"github.com/kubeedge/kubeedge/edge/pkg/common/modules"
	"github.com/kubeedge/kubeedge/edge/pkg/metamanager/dao/dbclient"
	servicebusConfig "github.com/kubeedge/kubeedge/edge/pkg/servicebus/config"
	"github.com/kubeedge/kubeedge/edge/pkg/servicebus/util"
	"github.com/kubeedge/kubeedge/pkg/features"
)

var (
	inited int32
	c      = make(chan struct{})
)

const (
	sourceType  = "router_servicebus"
	maxBodySize = 5 * 1e6
)

// TLSOptions carries the ServiceBus-specific TLS certificate material.
// It is passed explicitly through Register so that the server() function
// never has to read global command-line options.
//
//   - If TLSEnabled is false, the server starts plain HTTP (backward-compatible
//     default).
//   - If TLSEnabled is true and the cert or key path is empty or invalid,
//     Register returns an error and the server is NOT started in plain HTTP.
//     A missing or bad TLS configuration must never silently downgrade to
//     plaintext when the operator explicitly requested TLS.
//   - ClientAuth is intentionally omitted: local applications that talk to
//     ServiceBus are not provisioned with client certificates, so this
//     implementation provides server-only TLS.  A follow-up can add
//     configurable mTLS once a client-certificate provisioning workflow exists.
//
// NOTE: The certificate supplied here must have ExtKeyUsageServerAuth and
// IP/DNS SANs that match ServiceBus.Server (e.g. 127.0.0.1).  The EdgeHub
// client certificate CANNOT be reused because it carries ExtKeyUsageClientAuth
// and no ServiceBus SANs.
type TLSOptions struct {
	// TLSEnabled controls whether the ServiceBus HTTP server starts with TLS.
	// Default: false (plain HTTP, backward compatible).
	TLSEnabled bool

	// CertFile is the path to the PEM-encoded server certificate.
	// Required when TLSEnabled is true.
	CertFile string

	// KeyFile is the path to the PEM-encoded private key.
	// Required when TLSEnabled is true.
	KeyFile string
}

// servicebus struct
type servicebus struct {
	enable bool
	// default 127.0.0.1
	server  string
	port    int
	timeout int
	sbs     *dbclient.ServiceBusService
	tlsOpts TLSOptions
}

type serverRequest struct {
	Method    string      `json:"method"`
	TargetURL string      `json:"targetURL"`
	Payload   interface{} `json:"payload"`
}

type serverResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Body string `json:"body"`
}

var htc = new(http.Client)
var uc = new(util.URLClient)

func newServicebus(enable bool, server string, port, timeout int, tlsOpts TLSOptions) *servicebus {
	return &servicebus{
		enable:  enable,
		server:  server,
		port:    port,
		timeout: timeout,
		sbs:     dbclient.NewServiceBusService(),
		tlsOpts: tlsOpts,
	}
}

// Register registers the servicebus module.  tlsOpts controls whether the
// embedded HTTP server uses TLS.  Pass a zero-value TLSOptions{} for plain
// HTTP (backward-compatible default).
func Register(s *v1alpha2.ServiceBus, tlsOpts TLSOptions) {
	servicebusConfig.InitConfigure(s)
	core.Register(newServicebus(s.Enable, s.Server, s.Port, s.Timeout, tlsOpts))
}

func (*servicebus) Name() string {
	return modules.ServiceBusModuleName
}

func (*servicebus) Group() string {
	return modules.BusGroup
}

func (sb *servicebus) Enable() bool {
	return sb.enable
}

func (sb *servicebus) RestartPolicy() *core.ModuleRestartPolicy {
	if !features.DefaultFeatureGate.Enabled(features.ModuleRestart) {
		return nil
	}
	return &core.ModuleRestartPolicy{
		RestartType:            core.RestartTypeOnFailure,
		IntervalTimeGrowthRate: 2.0,
	}
}

func (sb *servicebus) Start() {
	// no need to call TopicInit now, we have fixed topic
	htc.Timeout = time.Second * 10
	uc.Client = htc
	if !sb.sbs.IsTableEmpty() {
		if atomic.CompareAndSwapInt32(&inited, 0, 1) {
			go server(c, sb.tlsOpts)
		}
	}
	//Get message from channel
	for {
		select {
		case <-beehiveContext.Done():
			klog.Warning("servicebus stop")
			return
		default:
		}
		msg, err := beehiveContext.Receive(modules.ServiceBusModuleName)
		if err != nil {
			klog.Warningf("servicebus receive msg error %v", err)
			continue
		}

		// build new message with required field & send message to servicebus
		klog.V(4).Info("servicebus receive msg")
		go processMessage(&msg)
	}
}

func processMessage(msg *beehiveModel.Message) {
	source := msg.GetSource()
	if source != sourceType {
		return
	}
	resource := msg.GetResource()
	dbc := dbclient.NewServiceBusService()
	switch msg.GetOperation() {
	case message.OperationStart:
		if err := dbc.InsertUrls(resource); err != nil {
			// TODO: handle err
			klog.Error(err)
		}
		if atomic.CompareAndSwapInt32(&inited, 0, 1) {
			go server(c, TLSOptions{}) // TLS not applicable for dynamic start
		}
	case message.OperationStop:
		if err := dbc.DeleteUrlsByKey(resource); err != nil {
			// TODO: handle err
			klog.Error(err)
		}

		if dbc.IsTableEmpty() {
			c <- struct{}{}
		}
	default:
		r := strings.Split(resource, ":")
		if len(r) != 2 {
			m := "the format of resource " + resource + " is incorrect"
			klog.Warning(m)
			code := http.StatusBadRequest
			if response, err := buildErrorResponse(msg.GetID(), m, code); err == nil {
				beehiveContext.SendToGroup(modules.HubGroup, response)
			}
			return
		}
		content, err := msg.GetContentData()
		if err != nil {
			klog.Errorf("marshall message content failed %v", err)
			m := "error to marshal request msg content"
			code := http.StatusBadRequest
			if response, err := buildErrorResponse(msg.GetID(), m, code); err == nil {
				beehiveContext.SendToGroup(modules.HubGroup, response)
			}
			return
		}

		var httpRequest commonType.HTTPRequest
		if err := json.Unmarshal(content, &httpRequest); err != nil {
			m := "error to parse http request"
			code := http.StatusBadRequest
			klog.Errorf(m, err)
			if response, err := buildErrorResponse(msg.GetID(), m, code); err == nil {
				beehiveContext.SendToGroup(modules.HubGroup, response)
			}
			return
		}

		//send message with resource to the edge part
		operation := httpRequest.Method
		targetURL := "http://127.0.0.1:" + r[0] + r[1]
		resp, err := uc.HTTPDo(operation, targetURL, httpRequest.Header, httpRequest.Body)
		if err != nil {
			m := "error to call service"
			code := http.StatusNotFound
			klog.Errorf(m, err)
			if response, err := buildErrorResponse(msg.GetID(), m, code); err == nil {
				beehiveContext.SendToGroup(modules.HubGroup, response)
			}
			return
		}
		defer resp.Body.Close()
		resBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		if err != nil {
			if err.Error() == "http: request body too large" {
				err = fmt.Errorf("response body too large")
			}
			m := "error to receive response, err: " + err.Error()
			code := http.StatusInternalServerError
			klog.Errorf(m, err)
			if response, err := buildErrorResponse(msg.GetID(), m, code); err == nil {
				beehiveContext.SendToGroup(modules.HubGroup, response)
			}
			return
		}

		response := commonType.HTTPResponse{Header: resp.Header, StatusCode: resp.StatusCode, Body: resBody}
		responseMsg := beehiveModel.NewMessage(msg.GetID()).SetRoute(modules.ServiceBusModuleName, modules.UserGroup).
			SetResourceOperation("", beehiveModel.UploadOperation).FillBody(response)
		beehiveContext.SendToGroup(modules.HubGroup, *responseMsg)
	}
}

// buildTLSConfig constructs a *tls.Config for server-only TLS from the given
// certificate and key files.
//
// Design decisions:
//
//   - Returns (nil, nil) only when opts.TLSEnabled is false — the caller is
//     responsible for checking TLSEnabled before calling this function.
//
//   - Returns a non-nil error when opts.TLSEnabled is true but the cert or
//     key path is empty or the key pair cannot be loaded.  The caller MUST
//     treat this as a fatal configuration error and NOT fall back to plain
//     HTTP.  Silently downgrading an explicitly enabled TLS endpoint removes
//     transport security without notifying the operator.
//
//   - GetCertificate is used instead of a static Certificates slice so that
//     certificate rotation takes effect on the next TLS handshake without an
//     EdgeCore restart.
//
//   - This function provides server-only TLS (ClientAuth: NoClientCert).
//     Local applications that talk to ServiceBus are not provisioned with
//     client certificates.  mTLS is intentionally out of scope until a
//     client-certificate provisioning workflow is defined.
//
//   - The certificate must have ExtKeyUsageServerAuth and IP/DNS SANs
//     matching the ServiceBus listen address (e.g. 127.0.0.1).
func buildTLSConfig(opts TLSOptions) (*tls.Config, error) {
	if !opts.TLSEnabled {
		return nil, nil
	}
	if opts.CertFile == "" || opts.KeyFile == "" {
		return nil, fmt.Errorf("[servicebus] TLS is enabled but CertFile or KeyFile is empty")
	}

	// Validate the key pair is loadable at startup so we fail fast with a
	// clear error instead of crashing silently on the first TLS handshake.
	if _, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile); err != nil {
		return nil, fmt.Errorf("[servicebus] failed to load TLS key pair: %w", err)
	}

	certFile := opts.CertFile
	keyFile := opts.KeyFile

	// Use GetCertificate so the cert is re-read from disk on every new TLS
	// handshake, enabling transparent certificate rotation.
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Server-only TLS: local applications are not expected to present
		// client certs.  Set explicitly so the policy is visible and auditable.
		ClientAuth: tls.NoClientCert,
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("[servicebus] certificate rotation: failed to reload key pair: %w", err)
			}
			return &c, nil
		},
	}

	return tlsCfg, nil
}

func server(stopChan <-chan struct{}, tlsOpts TLSOptions) {
	var (
		timeout time.Duration
		err     error
	)
	if timeout, err = time.ParseDuration(fmt.Sprintf("%vs", servicebusConfig.Config.Timeout)); err != nil {
		klog.Errorf("can't format timeout and the default value will be set")
		timeout, _ = time.ParseDuration("10s")
	}

	h := buildBasicHandler(timeout)
	s := http.Server{
		Addr:    fmt.Sprintf("%s:%d", servicebusConfig.Config.Server, servicebusConfig.Config.Port),
		Handler: h,
	}

	if tlsOpts.TLSEnabled {
		// TLS was explicitly requested.  A configuration error must be fatal:
		// do NOT fall back to plain HTTP when the operator enabled TLS.
		tlsCfg, err := buildTLSConfig(tlsOpts)
		if err != nil {
			klog.Errorf("[servicebus] TLS configuration failed, not starting server: %v", err)
			return
		}
		s.TLSConfig = tlsCfg
	}

	go func() {
		<-stopChan
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			klog.Errorf("Server shutdown failed: %s", err)
		}
		atomic.StoreInt32(&inited, 0)
	}()

	if s.TLSConfig != nil {
		klog.Infof("[servicebus] starting HTTPS server at %v", s.Addr)
		// cert and key are already loaded via GetCertificate; pass empty strings.
		utilruntime.HandleError(s.ListenAndServeTLS("", ""))
	} else {
		klog.Infof("[servicebus] starting HTTP server at %v (TLS disabled)", s.Addr)
		utilruntime.HandleError(s.ListenAndServe())
	}
}

func buildBasicHandler(timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sReq := &serverRequest{}
		sResp := &serverResponse{}
		req.Body = http.MaxBytesReader(w, req.Body, maxBodySize)
		byteData, err := io.ReadAll(req.Body)
		if err != nil {
			sResp.Code = http.StatusBadRequest
			sResp.Msg = "can't read data from body of the http's request"
			if _, err := w.Write(marshalResult(sResp)); err != nil {
				// TODO: handle err
				klog.Error(err)
			}
			return
		}
		if err = json.Unmarshal(byteData, sReq); err != nil {
			sResp.Code = http.StatusBadRequest
			sResp.Msg = "invalid params"
			if _, err := w.Write(marshalResult(sResp)); err != nil {
				// TODO: handle err
				klog.Error(err)
			}
			return
		}
		if targetURL, _ := dbclient.NewServiceBusService().GetUrlsByKey(sReq.TargetURL); targetURL == nil {
			sResp.Code = http.StatusBadRequest
			sResp.Msg = fmt.Sprintf("url %s is not allowed and please make a rule for this url in the cloud", sReq.TargetURL)
			if _, err := w.Write(marshalResult(sResp)); err != nil {
				// TODO: handle err
				klog.Error(err)
			}
			return
		}
		msg := beehiveModel.NewMessage("").BuildRouter(modules.ServiceBusModuleName, modules.UserGroup,
			sReq.TargetURL, beehiveModel.UploadOperation).FillBody(byteData)
		responseMessage, err := beehiveContext.SendSync(modules.EdgeHubModuleName, *msg, timeout)
		if err != nil {
			sResp.Code = http.StatusBadRequest
			sResp.Msg = err.Error()
			if _, err := w.Write(marshalResult(sResp)); err != nil {
				// TODO: handle err
				klog.Error(err)
			}
			return
		}
		resp, err := responseMessage.GetContentData()
		if err != nil {
			sResp.Code = http.StatusInternalServerError
			sResp.Msg = err.Error()
			if _, err := w.Write(marshalResult(sResp)); err != nil {
				// TODO: handle err
				klog.Error(err)
			}
			return
		}

		sResp.Code = http.StatusOK
		sResp.Msg = "receive response from cloud successfully"
		sResp.Body = string(resp)
		if _, err := w.Write(marshalResult(sResp)); err != nil {
			// TODO: handle err
			klog.Error(err)
		}
	})
}

func buildErrorResponse(parentID string, content string, statusCode int) (beehiveModel.Message, error) {
	h := http.Header{}
	h.Add("Server", "kubeedge-edgecore")
	c := commonType.HTTPResponse{Header: h, StatusCode: statusCode, Body: []byte(content)}
	message := beehiveModel.NewMessage(parentID).
		SetRoute(modules.ServiceBusModuleName, modules.UserGroup).FillBody(c)
	return *message, nil
}

func marshalResult(sResp *serverResponse) (resp []byte) {
	resp, _ = json.Marshal(sResp)
	return
}
