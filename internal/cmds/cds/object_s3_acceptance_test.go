package cds

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
)

func objectLiveStore(
	t *testing.T,
	cfg config,
	provider aws.CredentialsProvider,
) objectstate.Store {
	t.Helper()
	o := cfg.measured.ObjectState
	store, err := objectstate.NewS3(
		objectstate.S3Config{
			Bucket:        o.Bucket,
			Key:           o.Key,
			Region:        o.Region,
			ExpectedOwner: o.ExpectedBucketOwner,
			MaxBytes:      o.MaxBytes,
			Timeout:       10 * time.Second,
		},
		provider,
	)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newLiveObjectFixture(t *testing.T) (*objectAcceptance, objectProcessInput) {
	t.Helper()
	for _, name := range []string{
		"C8S_OBJECT_S3_BUCKET",
		"C8S_OBJECT_S3_PREFIX",
		"C8S_OBJECT_S3_OWNER",
		"C8S_OBJECT_S3_WRITER_ROLE",
		"AWS_REGION",
	} {
		if os.Getenv(name) == "" {
			t.Fatalf(
				"live test requires %s",
				name,
			)
		}
	}
	prefix := os.Getenv("C8S_OBJECT_S3_PREFIX")
	if len(prefix) > 512 || strings.Trim(
		prefix,
		"/",
	) == "" || strings.Contains(
		prefix,
		"..",
	) || strings.ContainsAny(
		prefix,
		"*?",
	) || strings.Contains(
		prefix,
		"${",
	) {
		t.Fatal("test prefix must identify a dedicated bounded object namespace")
	}
	random := make(
		[]byte,
		16,
	)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	id := "object-acceptance-" + hex.EncodeToString(random)
	h := newObjectAcceptanceForCluster(
		t,
		id,
	)
	h.stop()
	var wire map[string]any
	if err := yaml.Unmarshal(
		h.cfg.measuredFile,
		&wire,
	); err != nil {
		t.Fatal(err)
	}
	settings := wire["objectState"].(map[string]any)
	settings["bucket"], settings["region"] = os.Getenv("C8S_OBJECT_S3_BUCKET"), os.Getenv("AWS_REGION")
	settings["key"] = strings.TrimSuffix(
		prefix,
		"/",
	) + "/" + id + "/current"
	settings["expectedBucketOwner"] = os.Getenv("C8S_OBJECT_S3_OWNER")
	var err error
	h.cfg.measuredFile, err = yaml.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.measured, err = cdsconfig.Parse(h.cfg.measuredFile)
	if err != nil {
		t.Fatal(err)
	}
	o := h.cfg.measured.ObjectState
	ctx, cancel := context.WithTimeout(
		t.Context(),
		30*time.Second,
	)
	defer cancel()
	awsCfg, err := awsconfig.LoadDefaultConfig(
		ctx,
		awsconfig.WithRegion(o.Region),
		awsconfig.WithHTTPClient(&http.Client{Timeout: 10 * time.Second}),
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanupClient := s3.New(s3.Options{
		Region:      o.Region,
		Credentials: awsCfg.Credentials,
		Retryer:     aws.NopRetryer{},
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
	})
	versioning, err := cleanupClient.GetBucketVersioning(
		ctx,
		&s3.GetBucketVersioningInput{
			Bucket:              aws.String(o.Bucket),
			ExpectedBucketOwner: aws.String(o.ExpectedBucketOwner),
		},
	)
	if err != nil {
		t.Fatalf(
			"versioning preflight: %v",
			err,
		)
	}
	if versioning.MFADelete == "Enabled" {
		t.Fatal("live fixture refuses MFA Delete because cleanup requires unavailable interactive authorization")
	}

	lock, err := cleanupClient.GetObjectLockConfiguration(
		ctx,
		&s3.GetObjectLockConfigurationInput{
			Bucket:              aws.String(o.Bucket),
			ExpectedBucketOwner: aws.String(o.ExpectedBucketOwner),
		},
	)
	var apiError smithy.APIError
	if err != nil && !(errors.As(
		err,
		&apiError,
	) && apiError.ErrorCode() == "ObjectLockConfigurationNotFoundError") {
		t.Fatalf(
			"object lock preflight: %v",
			err,
		)
	}
	if lock != nil && lock.ObjectLockConfiguration != nil && lock.ObjectLockConfiguration.ObjectLockEnabled != "" {
		t.Fatal("live fixture refuses object-lock buckets because cleanup may be impossible")
	}
	rolePolicy, err := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{
				"Effect": "Allow",
				"Action": []string{
					"s3:GetObject",
					"s3:PutObject",
				},
				"Resource": "arn:aws:s3:::" + o.Bucket + "/" + o.Key,
			},
			map[string]any{
				"Effect":   "Allow",
				"Action":   "s3:ListBucket",
				"Resource": "arn:aws:s3:::" + o.Bucket,
				"Condition": map[string]any{
					"StringEquals": map[string]string{"s3:prefix": o.Key},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := sts.New(sts.Options{
		Region:      o.Region,
		Credentials: awsCfg.Credentials,
		Retryer:     aws.NopRetryer{},
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
	}).AssumeRole(
		ctx,
		&sts.AssumeRoleInput{
			RoleArn:         aws.String(os.Getenv("C8S_OBJECT_S3_WRITER_ROLE")),
			RoleSessionName: aws.String(id),
			DurationSeconds: aws.Int32(900),
			Policy:          aws.String(string(rolePolicy)),
		},
	)
	if err != nil {
		t.Fatalf(
			"scoped writer session: %v",
			err,
		)
	}
	if session.Credentials == nil {
		t.Fatal("writer session returned no credentials")
	}
	writer := aws.Credentials{
		AccessKeyID:     aws.ToString(session.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(session.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(session.Credentials.SessionToken),
	}
	store := objectLiveStore(
		t,
		h.cfg,
		credentials.NewStaticCredentialsProvider(
			writer.AccessKeyID,
			writer.SecretAccessKey,
			writer.SessionToken,
		),
	)
	if _, err := store.Load(ctx); !errors.Is(
		err,
		objectstate.ErrNotFound,
	) {
		t.Fatalf(
			"fresh object key preflight: wanted missing state, got %v",
			err,
		)
	}
	key := make(
		[]byte,
		32,
	)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key) })
	h.cipher, err = objectCipher(
		h.cfg,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := initialObjectView(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Stop()
	h.root = view.ca.CA.Cert
	view.state.StartedMS = time.Now().Add(-time.Hour).UnixMilli()
	plain, err := view.encode()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	sealed, err := h.cipher.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	h.store = &acceptanceObjectStore{
		data:    sealed,
		version: 1,
	}
	h.prepareSecret(t)
	object, err := h.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// The random key belongs exclusively to this run; cleanup removes only its exact versions.
	t.Logf(
		"live fixture object: s3://%s/%s",
		o.Bucket,
		o.Key,
	)
	_, err = store.Create(
		t.Context(),
		object.Data,
	)
	if !errors.Is(
		err,
		objectstate.ErrConflict,
	) {
		t.Cleanup(func() {
			cleanupLiveObject(
				t,
				cleanupClient,
				o,
			)
		})
	}
	if err != nil {
		t.Fatalf(
			"initialize isolated object: %v",
			err,
		)
	}
	h.store = store
	input := processInput(
		t,
		h,
		key,
	)
	input.Credentials = writer
	return h, input
}

func cleanupLiveObject(
	t *testing.T,
	client *s3.Client,
	o *cdsconfig.ObjectState,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(
		context.Background(),
		90*time.Second,
	)
	defer cancel()
	input := &s3.ListObjectVersionsInput{
		Bucket:              aws.String(o.Bucket),
		Prefix:              aws.String(o.Key),
		ExpectedBucketOwner: aws.String(o.ExpectedBucketOwner),
	}
	var versions []*string
	for page := 0; page < 100; page++ {
		output, err := client.ListObjectVersions(
			ctx,
			input,
		)
		if err != nil {
			t.Errorf(
				"cleanup list for owned key %s failed: %v",
				o.Key,
				err,
			)
			return
		}
		for _, version := range output.Versions {
			if aws.ToString(version.Key) == o.Key {
				versions = append(
					versions,
					version.VersionId,
				)
			}
		}
		for _, marker := range output.DeleteMarkers {
			if aws.ToString(marker.Key) == o.Key {
				versions = append(
					versions,
					marker.VersionId,
				)
			}
		}
		if !aws.ToBool(output.IsTruncated) {
			break
		}
		if page == 99 {
			t.Errorf(
				"cleanup exceeded version-list bound for owned key %s",
				o.Key,
			)
			return
		}
		input.KeyMarker, input.VersionIdMarker = output.NextKeyMarker, output.NextVersionIdMarker
	}
	for _, version := range versions {
		if _, err := client.DeleteObject(
			ctx,
			&s3.DeleteObjectInput{
				Bucket:              aws.String(o.Bucket),
				Key:                 aws.String(o.Key),
				VersionId:           version,
				ExpectedBucketOwner: aws.String(o.ExpectedBucketOwner),
			},
		); err != nil {
			t.Errorf(
				"cleanup delete for owned key %s failed: %v",
				o.Key,
				err,
			)
			return
		}
	}
	remaining, err := client.ListObjectVersions(
		ctx,
		&s3.ListObjectVersionsInput{
			Bucket:              aws.String(o.Bucket),
			Prefix:              aws.String(o.Key),
			ExpectedBucketOwner: aws.String(o.ExpectedBucketOwner),
		},
	)
	if err != nil {
		t.Errorf(
			"cleanup verification failed: %v",
			err,
		)
		return
	}
	for _, version := range remaining.Versions {
		if aws.ToString(version.Key) == o.Key {
			t.Errorf(
				"owned object version remained after cleanup: %s",
				o.Key,
			)
		}
	}
	for _, marker := range remaining.DeleteMarkers {
		if aws.ToString(marker.Key) == o.Key {
			t.Errorf(
				"owned object delete marker remained after cleanup: %s",
				o.Key,
			)
		}
	}
	t.Logf(
		"cleanup removed %d versions of the exact owned key",
		len(versions),
	)
}

func TestObjectS3Acceptance(t *testing.T) {
	if os.Getenv("C8S_OBJECT_S3_RUN") != "1" {
		t.Skip("set C8S_OBJECT_S3_RUN=1 and explicit bucket/prefix/owner/region to use live S3")
	}
	started := time.Now()
	h, input := newLiveObjectFixture(t)
	certificate := &tls.Certificate{
		Certificate: [][]byte{h.leaf.Raw},
		PrivateKey:  h.leafKey,
	}
	var replicas []*objectProcess
	restart := func() {
		for _, replica := range replicas {
			replica.kill()
		}
		replicas = nil
		for range 3 {
			replicas = append(
				replicas,
				startObjectProcess(
					t,
					input,
					certificate,
				),
			)
		}
	}
	restart()
	before := objectCall(
		replicas[0],
		http.MethodGet,
		"/ca",
		nil,
		"",
	)
	objectProcessWantStatus(
		t,
		before,
		http.StatusOK,
	)
	policyResponse := objectCall(
		replicas[1],
		http.MethodGet,
		"/allowlist",
		nil,
		"",
	)
	objectProcessWantStatus(
		t,
		policyResponse,
		http.StatusOK,
	)
	allowedPolicy := policyResponse.Body.Bytes()
	t.Run(
		"concurrent_register",
		func(t *testing.T) {
			objectLiveRegister(
				t,
				h,
				replicas,
			)
		},
	)
	if t.Failed() {
		return
	}
	objectProcessWantStatus(
		t,
		objectCall(
			replicas[0],
			http.MethodPut,
			"/allowlist",
			allowedPolicy,
			h.token(
				t,
				http.MethodPut,
				"/allowlist",
				allowedPolicy,
			),
		),
		http.StatusNoContent,
	)
	positiveNonce := mintChallenge(
		t,
		replicas[1],
		"/secrets",
	)
	positive := httptest.NewRecorder()
	replicas[2].ServeHTTP(
		positive,
		h.secretRequest(
			t,
			positiveNonce,
		),
	)
	objectProcessWantStatus(
		t,
		positive,
		http.StatusOK,
	)
	secret := base64.StdEncoding.EncodeToString([]byte("object-acceptance-secret"))
	if !strings.Contains(
		positive.Body.String(),
		secret,
	) {
		t.Fatal("positive secret-release control returned no secret")
	}
	lostChallengeStarted := time.Now()
	lostNonce := mintChallenge(
		t,
		replicas[1],
		"/secrets",
	)
	commits := objectProcessCommits(
		t,
		replicas[0],
	)
	objectControl(
		t,
		replicas[0],
		"lose-ack",
	)
	lost := httptest.NewRecorder()
	replicas[0].ServeHTTP(
		lost,
		h.secretRequest(
			t,
			lostNonce,
		),
	)
	objectProcessWantStatus(
		t,
		lost,
		http.StatusServiceUnavailable,
	)
	if lost.Header().Get("X-C8s-Commit-Outcome") != "unknown" || strings.Contains(
		lost.Body.String(),
		secret,
	) || strings.Contains(
		lost.Body.String(),
		"object-acceptance-secret",
	) {
		t.Fatal("lost commit acknowledgment did not suppress the successful secret response")
	}
	if objectProcessCommits(
		t,
		replicas[0],
	) != commits+1 {
		t.Fatal("lost acknowledgment was not exactly one successful storage mutation")
	}
	t.Log("lost successful CAS acknowledgment released no secret and made exactly one mutation")
	pausedNonce := mintChallenge(
		t,
		replicas[2],
		"/secrets",
	)
	objectControl(
		t,
		replicas[0],
		"pause",
	)
	stale := httptest.NewRecorder()
	done := make(chan struct{})
	pausedRequest := h.secretRequest(
		t,
		pausedNonce,
	)
	go func() {
		replicas[0].ServeHTTP(
			stale,
			pausedRequest,
		)
		close(done)
	}()
	objectProcessWantStatus(
		t,
		objectCall(
			replicas[0],
			http.MethodGet,
			"/_acceptance/entered",
			nil,
			"",
		),
		http.StatusNoContent,
	)
	revoked := objectDocument(
		t,
		"revoked",
	)
	spent := h.token(
		t,
		http.MethodPut,
		"/allowlist",
		revoked,
	)
	objectProcessWantStatus(
		t,
		objectCall(
			replicas[1],
			http.MethodPut,
			"/allowlist",
			revoked,
			spent,
		),
		http.StatusNoContent,
	)
	objectControl(
		t,
		replicas[0],
		"resume",
	)
	select {
	case <-done:
	case <-time.After(45 * time.Second):
		t.Fatal("paused request failed to finish")
	}
	objectProcessWantStatus(
		t,
		stale,
		http.StatusConflict,
	)
	if stale.Header().Get("X-C8s-Commit-Outcome") != "not-committed" || strings.Contains(
		stale.Body.String(),
		secret,
	) || strings.Contains(
		stale.Body.String(),
		"object-acceptance-secret",
	) {
		t.Fatal("revocation failed to fence buffered secret release")
	}
	t.Log("concurrent policy revocation fenced a paused secret release")
	unused := h.token(
		t,
		http.MethodPut,
		"/allowlist",
		allowedPolicy,
	)
	restart()
	after := objectCall(
		replicas[2],
		http.MethodGet,
		"/ca",
		nil,
		"",
	)
	objectProcessWantStatus(
		t,
		after,
		http.StatusOK,
	)
	if !bytes.Equal(
		before.Body.Bytes(),
		after.Body.Bytes(),
	) {
		t.Fatal("total process loss changed the CA")
	}
	objectProcessWantStatus(
		t,
		objectCall(
			replicas[0],
			http.MethodPut,
			"/allowlist",
			revoked,
			spent,
		),
		http.StatusConflict,
	)
	objectProcessWantStatus(
		t,
		objectCall(
			replicas[1],
			http.MethodPut,
			"/allowlist",
			revoked,
			objectTokenTwin(
				t,
				spent,
			),
		),
		http.StatusConflict,
	)
	denied := httptest.NewRecorder()
	replicas[1].ServeHTTP(
		denied,
		h.secretRequest(
			t,
			pausedNonce,
		),
	)
	objectProcessWantStatus(
		t,
		denied,
		http.StatusForbidden,
	)
	if strings.Contains(
		denied.Body.String(),
		secret,
	) || strings.Contains(
		denied.Body.String(),
		"object-acceptance-secret",
	) {
		t.Fatal("recovered replica disclosed a revoked secret")
	}
	replay := httptest.NewRecorder()
	replicas[2].ServeHTTP(
		replay,
		h.secretRequest(
			t,
			lostNonce,
		),
	)
	if time.Since(lostChallengeStarted) >= h.cfg.challengeTTL {
		t.Fatal("recovery exceeded challenge lifetime; replay rejection would be inconclusive")
	}
	objectProcessWantStatus(
		t,
		replay,
		http.StatusBadRequest,
	)

	if strings.TrimSpace(replay.Body.String()) != "invalid or expired challenge" {
		t.Fatal("recovered replica did not reject the consumed nonce")
	}
	objectProcessWantStatus(
		t,
		objectCall(
			replicas[0],
			http.MethodPut,
			"/allowlist",
			allowedPolicy,
			unused,
		),
		http.StatusNoContent,
	)
	fresh := mintChallenge(
		t,
		replicas[1],
		"/secrets",
	)
	recovered := httptest.NewRecorder()
	replicas[2].ServeHTTP(
		recovered,
		h.secretRequest(
			t,
			fresh,
		),
	)
	objectProcessWantStatus(
		t,
		recovered,
		http.StatusOK,
	)
	if !strings.Contains(
		recovered.Body.String(),
		secret,
	) {
		t.Fatal("recovered replica lost the acknowledged secret or valid authorization")
	}
	t.Logf(
		"all three processes killed and reaped; replacements preserved CA, replay rejection and revocation; elapsed=%s",
		time.Since(started).Round(time.Millisecond),
	)
}

func objectControl(
	t *testing.T,
	process *objectProcess,
	action string,
) {
	t.Helper()
	objectProcessWantStatus(
		t,
		objectCall(
			process,
			http.MethodPost,
			"/_acceptance/"+action,
			nil,
			"",
		),
		http.StatusNoContent,
	)
}

func objectProcessCommits(
	t *testing.T,
	process *objectProcess,
) uint64 {
	t.Helper()
	response := objectCall(
		process,
		http.MethodGet,
		"/_acceptance/commits",
		nil,
		"",
	)
	objectProcessWantStatus(
		t,
		response,
		http.StatusOK,
	)
	var count uint64
	if err := json.Unmarshal(
		response.Body.Bytes(),
		&count,
	); err != nil {
		t.Fatal(err)
	}
	return count
}

func objectLiveRegister(
	t *testing.T,
	h *objectAcceptance,
	replicas []*objectProcess,
) {
	t.Helper()
	initialResponse := objectCall(
		replicas[0],
		http.MethodGet,
		"/allowlist",
		nil,
		"",
	)
	objectProcessWantStatus(
		t,
		initialResponse,
		http.StatusOK,
	)
	initial := initialResponse.Body.String()
	var clock atomic.Int64
	var successes, reads atomic.Int64
	var clients sync.WaitGroup
	operations := make(
		chan porcupine.Operation,
		64,
	)
	for client := range 3 {
		clients.Add(1)
		go func() {
			defer clients.Done()
			for step := range 8 {
				body := objectDocument(
					t,
					fmt.Sprintf(
						"client-%d-write-%d",
						client,
						step,
					),
				)
				token := h.token(
					t,
					http.MethodPut,
					"/allowlist",
					body,
				)
				call := clock.Add(1)
				response := objectCall(
					replicas[(client+step)%3],
					http.MethodPut,
					"/allowlist",
					body,
					token,
				)
				end := clock.Add(1)
				if response.Code != http.StatusNoContent && (response.Code != http.StatusConflict || response.Header().Get("X-C8s-Commit-Outcome") != "not-committed") {
					t.Errorf(
						"unexpected concurrency write outcome: status=%d outcome=%q storage=%s",
						response.Code,
						response.Header().Get("X-C8s-Commit-Outcome"),
						objectProcessFailure(
							t,
							replicas[(client+step)%3],
						),
					)
					return
				}
				applied := response.Code == http.StatusNoContent
				if applied {
					successes.Add(1)
				}
				operations <- porcupine.Operation{
					ClientId: client,
					Call:     call,
					Return:   end,
					Input: objectRegisterInput{
						Write: true,
						Value: string(body),
					},
					Output: objectRegisterOutput{Applied: applied},
				}
				call = clock.Add(1)
				response = objectCall(
					replicas[(client+step+1)%3],
					http.MethodGet,
					"/allowlist",
					nil,
					"",
				)
				end = clock.Add(1)
				if response.Code != http.StatusOK {
					t.Errorf(
						"unexpected concurrency read outcome: status=%d storage=%s",
						response.Code,
						objectProcessFailure(
							t,
							replicas[(client+step+1)%3],
						),
					)
					return
				}
				reads.Add(1)
				operations <- porcupine.Operation{
					ClientId: client,
					Call:     call,
					Return:   end,
					Input:    objectRegisterInput{},
					Output:   objectRegisterOutput{Value: response.Body.String()},
				}
			}
		}()
	}
	clients.Wait()
	close(operations)
	if t.Failed() {
		return
	}
	var history []porcupine.Operation
	for operation := range operations {
		history = append(
			history,
			operation,
		)
	}
	for i, replica := range replicas {
		call := clock.Add(1)
		response := objectCall(
			replica,
			http.MethodGet,
			"/allowlist",
			nil,
			"",
		)
		end := clock.Add(1)
		objectProcessWantStatus(
			t,
			response,
			http.StatusOK,
		)
		history = append(
			history,
			porcupine.Operation{
				ClientId: i,
				Call:     call,
				Return:   end,
				Input:    objectRegisterInput{},
				Output:   objectRegisterOutput{Value: response.Body.String()},
			},
		)
	}
	model := porcupine.Model{
		Init: func() any { return initial },
		Step: func(state, input, output any) (bool, any) {
			in, out := input.(objectRegisterInput), output.(objectRegisterOutput)
			if in.Write {
				if out.Applied {
					return true, in.Value
				}
				return true, state
			}
			return out.Value == state.(string), state
		},
	}
	if len(history) != 51 || successes.Load() == 0 || reads.Load() != 24 {
		t.Fatalf(
			"incomplete history: operations=%d, writes=%d, reads=%d",
			len(history),
			successes.Load(),
			reads.Load(),
		)
	}
	if result := porcupine.CheckOperationsTimeout(
		model,
		history,
		15*time.Second,
	); result != porcupine.Ok {
		t.Fatalf(
			"live policy history was %s",
			result,
		)
	}
	t.Logf(
		"Porcupine accepted %d operations: %d successful writes, %d conflicting writes, 27 reads",
		len(history),
		successes.Load(),
		24-successes.Load(),
	)
}

func objectProcessFailure(
	t *testing.T,
	process *objectProcess,
) string {
	t.Helper()
	response := objectCall(
		process,
		http.MethodGet,
		"/_acceptance/error",
		nil,
		"",
	)
	if response.Code != http.StatusOK {
		return "unavailable"
	}
	var failure *objectStoreFailure
	if err := json.Unmarshal(
		response.Body.Bytes(),
		&failure,
	); err != nil {
		return "invalid diagnostic"
	}
	encoded, err := json.Marshal(failure)
	if err != nil {
		return "invalid diagnostic"
	}
	return string(encoded)
}
