package cdsdirect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/directstate"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func textResult(code int, text string) cdsha.OperatorResult {
	return cdsha.OperatorResult{Code: code, Body: []byte(text)}
}
func jsonResult(code int, value any) cdsha.OperatorResult {
	body, _ := json.Marshal(value)
	return cdsha.OperatorResult{Code: code, Body: append(body, '\n'), JSON: true, NoStore: true}
}

func spentKey(token string) string {
	// ECDSA (r,n-s) and base64 signature variants must share the same spend.
	i := strings.LastIndexByte(token, '.')
	if i >= 0 {
		token = token[:i]
	}
	h := sha256.Sum256([]byte(token))
	return "spent:" + hex.EncodeToString(h[:])
}

func (s *State) WriteOperator(ctx context.Context, c cdsha.OperatorCommand) (cdsha.OperatorResult, error) {
	if c.AtMS <= 0 || (c.Path != "/allowlist" && c.Path != routes.Path && !strings.HasPrefix(c.Path, "/secrets/")) {
		return cdsha.OperatorResult{}, errors.New("direct state: invalid operator command")
	}
	rawPath := c.Path
	if c.EscapedPath != "" {
		decoded, err := url.PathUnescape(c.EscapedPath)
		if err != nil || decoded != c.Path {
			return cdsha.OperatorResult{}, errors.New("direct state: signed path mismatch")
		}
		rawPath = c.EscapedPath
	}
	if err := operatorauth.VerifyStored(s.launch.OperatorKeys, c.Token, http.MethodPut, c.Path, c.Body); err != nil {
		return cdsha.OperatorResult{}, err
	}
	if _, valid := allowlist.OperatorVersion(c.IfMatch); c.Path == "/allowlist" && !valid {
		return textResult(http.StatusPreconditionFailed, allowlist.InvalidOperatorVersion), nil
	}
	tokenKey := spentKey(c.Token)
	keys := []string{coreKey, policyKey, tokenKey}
	lane := policyKey
	var cmd secrets.Command
	var parseError error
	var parseStatus int
	secretWrite := strings.HasPrefix(c.Path, "/secrets/")
	if secretWrite {
		cmd, parseStatus, parseError = secrets.PrepareOperatorWrite(rawPath, c.Body)
		defer clear(cmd.Value)
		if parseError == nil {
			lane = secretKey(cmd.Path)
			keys = append(keys, lane)
		}
	}
	answer, err := s.store.Update(ctx, lane, keys, func(v *directstate.View) (map[string][]byte, any, error) {
		_, _, err := s.core(v)
		if err != nil {
			return nil, nil, err
		}
		if _, spent := v.Get(tokenKey); spent {
			return nil, textResult(http.StatusConflict, operatorauth.ErrTokenReused.Error()), nil
		}
		writes := map[string][]byte{}
		var result cdsha.OperatorResult
		if secretWrite {
			if parseError != nil {
				result = textResult(parseStatus, parseError.Error())
			} else {
				var r secrets.Result
				writes, r, err = s.secretChange(v, cmd)
				defer clear(r.Current)
				if err != nil {
					return nil, nil, err
				}
				if writes == nil {
					writes = map[string][]byte{}
				}
				switch {
				case errors.Is(r.Refusal(), secrets.ErrStoreFull):
					result = jsonResult(http.StatusInsufficientStorage, types.ErrorResponse{Error: types.ErrorCodeSecretStoreFull, Message: "secret storage limit reached"})
				case r.Refusal() != nil:
					result = textResult(http.StatusInternalServerError, "secret write failed")
				default:
					response := secrets.PutResponse{Path: cmd.Path, Existing: r.HeldOrigin}
					code := http.StatusOK
					if !r.HeldExists {
						code, response.Created = http.StatusCreated, true
					} else if cmd.Op == secrets.OpPutIfAbsent {
						code = http.StatusConflict
					}
					result = jsonResult(code, response)
				}
			}
		} else {
			f, al, _, err := s.machine(v)
			if err != nil {
				return nil, nil, err
			}
			defer al.Close()
			body, _ := json.Marshal(cdsha.Entry{Kind: cdsha.KindOperator, Operator: &c})
			defer clear(body)
			r := f.Apply(1, body)
			if r.Stop != nil {
				return nil, nil, r.Stop
			}
			if r.Operator == nil {
				return nil, nil, errors.New("direct state: missing operator decision")
			}
			result = *r.Operator
			p, err := policyBytes(al)
			if err != nil {
				return nil, nil, err
			}
			writes[policyKey] = p
		}
		// The receipt is current replay state. Refused authorized requests spend
		// it too. It contains only the public response, never an existing secret.
		writes[tokenKey], err = json.Marshal(result)
		return writes, result, err
	})
	if err != nil {
		return cdsha.OperatorResult{}, err
	}
	return answer.(cdsha.OperatorResult), nil
}
