package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/frain-dev/convoy/api/handlers"

	"github.com/frain-dev/convoy/pkg/msgpack"
	"gopkg.in/guregu/null.v4"

	"github.com/frain-dev/convoy/internal/pkg/dedup"
	"github.com/go-chi/chi/v5"
	"github.com/oklog/ulid/v2"

	"github.com/frain-dev/convoy"
	"github.com/frain-dev/convoy/config"
	"github.com/frain-dev/convoy/database/postgres"
	"github.com/frain-dev/convoy/datastore"
	"github.com/frain-dev/convoy/internal/pkg/crc"
	"github.com/frain-dev/convoy/pkg/httpheader"
	"github.com/frain-dev/convoy/pkg/verifier"
	"github.com/frain-dev/convoy/queue"
	"github.com/frain-dev/convoy/util"
	"github.com/frain-dev/convoy/worker/task"
	"github.com/go-chi/render"
)

func (a *ApplicationHandler) IngestEvent(w http.ResponseWriter, r *http.Request) {
	// s.AppService.CountProjectApplications()
	// 1. Retrieve mask ID
	maskID := chi.URLParam(r, "maskID")

	// 2. Retrieve source using mask ID.
	source, err := postgres.NewSourceRepo(a.A.DB).FindSourceByMaskID(r.Context(), maskID)
	if err != nil {
		if errors.Is(err, datastore.ErrSourceNotFound) {
			_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusNotFound))
			return
		}
		_ = render.Render(w, r, util.NewErrorResponse("error retrieving source", http.StatusBadRequest))
		return
	}

	// 2. Retrieve source using mask ID.
	projectRepo := postgres.NewProjectRepo(a.A.DB)
	project, err := projectRepo.FetchProjectByID(r.Context(), source.ProjectID)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	if !a.A.Licenser.ProjectEnabled(project.UID) {
		_ = render.Render(w, r, util.NewErrorResponse(handlers.ErrProjectDisabled.Error(), http.StatusBadRequest))
		return
	}

	if source.Type != datastore.HTTPSource {
		_ = render.Render(w, r, util.NewErrorResponse("Source type needs to be HTTP",
			http.StatusBadRequest))
		return
	}

	// 3. Select verifier based of source config.
	// TODO(subomi): Can verifier be nil?
	var v verifier.Verifier
	verifierConfig := source.Verifier

	if !util.IsStringEmpty(string(source.Provider)) {
		switch source.Provider {
		case datastore.GithubSourceProvider:
			v = verifier.NewGithubVerifier(verifierConfig.HMac.Secret)
		case datastore.TwitterSourceProvider:
			v = verifier.NewTwitterVerifier(verifierConfig.HMac.Secret)
		case datastore.ShopifySourceProvider:
			v = verifier.NewShopifyVerifier(verifierConfig.HMac.Secret)
		default:
			_ = render.Render(w, r, util.NewErrorResponse("Provider type undefined",
				http.StatusBadRequest))
			return
		}
	} else {
		switch verifierConfig.Type {
		case datastore.HMacVerifier:
			opts := &verifier.HmacOptions{
				Header:   verifierConfig.HMac.Header,
				Hash:     verifierConfig.HMac.Hash,
				Secret:   verifierConfig.HMac.Secret,
				Encoding: string(verifierConfig.HMac.Encoding),
			}
			v = verifier.NewHmacVerifier(opts)

		case datastore.BasicAuthVerifier:
			v = verifier.NewBasicAuthVerifier(
				verifierConfig.BasicAuth.UserName,
				verifierConfig.BasicAuth.Password,
			)
		case datastore.APIKeyVerifier:
			v = verifier.NewAPIKeyVerifier(
				verifierConfig.ApiKey.HeaderValue,
				verifierConfig.ApiKey.HeaderName,
			)
		default:
			v = &verifier.NoopVerifier{}
		}
	}

	var maxIngestSize uint64
	if project.Config != nil && project.Config.MaxIngestSize != 0 {
		maxIngestSize = project.Config.MaxIngestSize
	}

	if maxIngestSize == 0 {
		cfg, err := config.Get()
		if err != nil {
			a.A.Logger.WithError(err).Error("failed to load config")
			_ = render.Render(w, r, util.NewErrorResponse("failed to load config", http.StatusBadRequest))
			return
		}

		maxIngestSize = cfg.MaxResponseSize
	}

	// The Content-Length header indicates the size of the message body, in bytes, sent to the recipient.
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Length
	// We use this to check the size of the request content, this is to ensure that we return the appropriate
	// status code when the size of a request payload exceeds the configured MaxResponseSize.
	if r.ContentLength > int64(maxIngestSize) {
		_ = render.Render(w, r, util.NewErrorResponse("request body too large", http.StatusRequestEntityTooLarge))
		return
	}

	var checksum string
	var isDuplicate bool
	if len(source.IdempotencyKeys) > 0 {
		duper := dedup.NewDeDuper(r.Context(), r, postgres.NewEventRepo(a.A.DB))
		exists, err := duper.Exists(source.Name, source.ProjectID, source.IdempotencyKeys)
		if err != nil {
			_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
			return
		}

		isDuplicate = exists

		checksum, err = duper.GenerateChecksum(source.Name, source.IdempotencyKeys)
		if err != nil {
			_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
			return
		}
	}

	// 3.1 On Failure
	// Return 400 Bad Request.
	payload, err := extractPayloadFromIngestEventReq(r, maxIngestSize)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	if err = v.VerifyRequest(r, payload); err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	if len(payload) == 0 {
		payload = []byte("{}")
	}

	// 3.2 On success
	// Attach Source to Event.
	// Write Event to the Ingestion Queue.
	event := &datastore.Event{
		UID:              ulid.Make().String(),
		EventType:        datastore.EventType(maskID),
		SourceID:         source.UID,
		ProjectID:        source.ProjectID,
		Raw:              string(payload),
		Data:             payload,
		IsDuplicateEvent: isDuplicate,
		URLQueryParams:   r.URL.RawQuery,
		IdempotencyKey:   checksum,
		Headers:          httpheader.HTTPHeader(r.Header),
		AcknowledgedAt:   null.TimeFrom(time.Now()),
	}

	event.Headers["X-Convoy-Source-Id"] = []string{source.MaskID}

	createEvent := task.CreateEvent{
		Event: event,
	}

	eventByte, err := msgpack.EncodeMsgPack(createEvent)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	jobId := fmt.Sprintf("single:%s:%s", event.ProjectID, event.UID)
	job := &queue.Job{
		ID:      jobId,
		Payload: eventByte,
		Delay:   0,
	}

	err = a.A.Queue.Write(convoy.CreateEventProcessor, convoy.CreateEventQueue, job)
	if err != nil {
		a.A.Logger.WithError(err).Error("Error occurred sending new event to the queue")
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	// 4. Return 200
	if !util.IsStringEmpty(source.CustomResponse.Body) {
		// send back custom response
		if !util.IsStringEmpty(source.CustomResponse.ContentType) {
			w.Header().Set("Content-Type", source.CustomResponse.ContentType)
			w.WriteHeader(http.StatusOK)

			customResp, err := extractCustomBody(r, source.CustomResponse.ContentType, source.CustomResponse.Body)
			if err != nil {
				_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
				return
			}

			_, _ = w.Write(customResp)
			return
		}

		render.Status(r, http.StatusOK)
		render.PlainText(w, r, source.CustomResponse.Body)
		return

	}

	if event.IsDuplicateEvent {
		_ = render.Render(w, r, util.NewServerResponse("Duplicate event received, but will not be sent", len(payload), http.StatusOK))
	} else {
		_ = render.Render(w, r, util.NewServerResponse("Event received", len(payload), http.StatusOK))
	}
}

// extractValueFromNestedMap retrieves a value from a nested map based on a dot-separated key.
func extractValueFromNestedMap(data map[string]interface{}, key string) (string, bool) {
	parts := strings.Split(key, ".")
	current := data

	for i, part := range parts {
		if value, exists := current[part]; exists {
			if i == len(parts)-1 {
				if str, ok := value.(string); ok {
					return str, true
				}
				return fmt.Sprintf("%v", value), true
			}
			if nestedMap, ok := value.(map[string]interface{}); ok {
				current = nestedMap
			} else {
				return "", false
			}
		} else {
			return "", false
		}
	}

	return "", false
}

// extractCustomBody processes the custom response body and returns a byte slice.
func extractCustomBody(r *http.Request, customResponseContentType, customResponseContentBody string) ([]byte, error) {
	switch customResponseContentType {
	case "application/json":
		// Parse the JSON template
		var responseMap map[string]interface{}
		if err := json.Unmarshal([]byte(customResponseContentBody), &responseMap); err != nil {
			return nil, fmt.Errorf("invalid JSON response template: %v", err)
		}

		// Replace req.Headers.{field} placeholders
		for key, values := range r.Header {
			placeholder := fmt.Sprintf("req.Headers.%s", key)
			replacePlaceholdersInMap(responseMap, placeholder, strings.Join(values, ","))
		}

		// Parse JSON body of the request
		var bodyMap map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&bodyMap); err == nil {
			placeholders := extractPlaceholders(customResponseContentBody, "req.Body")
			for _, placeholder := range placeholders {
				field := strings.TrimPrefix(placeholder, "req.Body.")
				if value, exists := extractValueFromNestedMap(bodyMap, field); exists {
					replacePlaceholdersInMap(responseMap, placeholder, value)
				}
			}
		} else if err.Error() != "EOF" {
			return nil, err
		}

		// Encode the modified map to JSON
		return json.Marshal(responseMap)

	case "text/plain":
		// Replace req.Headers.{field} placeholders
		for key, values := range r.Header {
			placeholder := fmt.Sprintf("req.Headers.%s", key)
			customResponseContentBody = strings.ReplaceAll(customResponseContentBody, placeholder, strings.Join(values, ","))
		}

		// Parse JSON body of the request for req.Body.{field} placeholders
		var bodyMap map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&bodyMap); err == nil {
			placeholders := extractPlaceholders(customResponseContentBody, "req.Body")
			for _, placeholder := range placeholders {
				field := strings.TrimPrefix(placeholder, "req.Body.")
				if value, exists := extractValueFromNestedMap(bodyMap, field); exists {
					customResponseContentBody = strings.ReplaceAll(customResponseContentBody, placeholder, value)
				}
			}
		} else if err.Error() != "EOF" {
			return nil, err
		}

		// Return the plain text response as bytes
		return []byte(customResponseContentBody), nil

	default:
		return nil, errors.New("unsupported Content-Type")
	}
}

// replacePlaceholdersInMap replaces placeholders in a map recursively.
func replacePlaceholdersInMap(data map[string]interface{}, placeholder, value string) {
	for key, v := range data {
		switch typedValue := v.(type) {
		case string:
			if typedValue == placeholder {
				data[key] = value
			}
		case map[string]interface{}:
			replacePlaceholdersInMap(typedValue, placeholder, value)
		}
	}
}

// extractPlaceholders identifies placeholders with a specific prefix in the input text.
func extractPlaceholders(text, prefix string) []string {
	var placeholders []string
	start := 0
	for {
		start = strings.Index(text[start:], prefix)
		if start == -1 {
			break
		}
		start += len(prefix)
		end := start
		for end < len(text) && (text[end] == '.' || text[end] == '_' || text[end] == '-' || (text[end] >= 'a' && text[end] <= 'z') || (text[end] >= 'A' && text[end] <= 'Z') || (text[end] >= '0' && text[end] <= '9')) {
			end++
		}
		placeholders = append(placeholders, text[start-len(prefix):end])
		start = end
	}
	return placeholders
}

const (
	applicationJsonContentType   = "application/json"
	multipartFormDataContentType = "multipart/form-data"
	urlEncodedContentType        = "application/x-www-form-urlencoded"
)

func extractPayloadFromIngestEventReq(r *http.Request, maxIngestSize uint64) ([]byte, error) {
	var contentType string
	rawContentType := strings.ToLower(
		strings.TrimSpace(
			r.Header.Get("Content-Type"),
		),
	)

	// We split the rawContentType using the first semicolon as the delimiter because go-chi has a weird way
	// of handling the form-data content type. It adds a semicolon after the boundary and we need to remove it.
	// Example: multipart/form-data; boundary=--------------------------879783787191406952783600
	if contentTypeSlice := strings.SplitN(rawContentType, ";", 2); len(contentTypeSlice) == 0 {
		// always default to json if no content type is specified
		contentType = applicationJsonContentType
	} else {
		contentType = strings.TrimSpace(contentTypeSlice[0])
	}

	switch contentType {
	case multipartFormDataContentType:
		if err := r.ParseMultipartForm(int64(maxIngestSize)); err != nil {
			return nil, err
		}
		return convertRequestFormToJSON(r)
	case urlEncodedContentType:
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		return convertRequestFormToJSON(r)
	default:
		// To avoid introducing a breaking change, we are keeping the old behaviour of assuming
		// the content type is JSON if the content type is not specified/unsupported.
		return io.ReadAll(io.LimitReader(r.Body, int64(maxIngestSize)))
	}
}

func convertRequestFormToJSON(r *http.Request) ([]byte, error) {
	data := make(map[string]string)
	for k, v := range r.Form {
		// Golang handles the form data and returns it as a map[string][]string.
		// we only need the first value in the slice, so we take the first element in the slice.
		// We also skip empty values.
		if len(v) > 0 {
			data[k] = v[0]
		}
	}
	return json.Marshal(data)
}

func (a *ApplicationHandler) HandleCrcCheck(w http.ResponseWriter, r *http.Request) {
	maskId := chi.URLParam(r, "maskID")
	source, err := postgres.NewSourceRepo(a.A.DB).FindSourceByMaskID(r.Context(), maskId)
	if err != nil {
		if errors.Is(err, datastore.ErrSourceNotFound) {
			_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusNotFound))
			return
		}
		_ = render.Render(w, r, util.NewErrorResponse("error retrieving source", http.StatusBadRequest))
		return
	}

	if source.Type != datastore.HTTPSource {
		_ = render.Render(w, r, util.NewErrorResponse("Source type needs to be HTTP", http.StatusBadRequest))
		return
	}

	if util.IsStringEmpty(string(source.Provider)) {
		_ = render.Render(w, r, util.NewErrorResponse("Provider type undefined", http.StatusBadRequest))
		return
	}

	var c crc.Crc

	switch source.Provider {
	case datastore.TwitterSourceProvider:
		c = crc.NewTwitterCrc(source.Verifier.HMac.Secret)
	default:
		_ = render.Render(w, r, util.NewErrorResponse("Provider type is not supported", http.StatusBadRequest))
		return
	}

	sourceRepo := postgres.NewSourceRepo(a.A.DB)
	err = c.HandleRequest(w, r, source, sourceRepo)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}
}
