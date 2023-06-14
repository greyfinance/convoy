package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/frain-dev/convoy/pkg/log"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	"github.com/frain-dev/convoy/api/models"
	"github.com/frain-dev/convoy/config"
	"github.com/frain-dev/convoy/database/postgres"
	"github.com/frain-dev/convoy/datastore"
	m "github.com/frain-dev/convoy/internal/pkg/middleware"
	"github.com/frain-dev/convoy/services"
	"github.com/frain-dev/convoy/util"
)

func createEventService(a *DashboardHandler) (*services.EventService, error) {
	sourceRepo := postgres.NewSourceRepo(a.A.DB)
	endpointRepo := postgres.NewEndpointRepo(a.A.DB)
	subRepo := postgres.NewSubscriptionRepo(a.A.DB)
	eventRepo := postgres.NewEventRepo(a.A.DB)
	eventDeliveryRepo := postgres.NewEventDeliveryRepo(a.A.DB)
	deviceRepo := postgres.NewDeviceRepo(a.A.DB)

	eventService, err := services.NewEventService(
		endpointRepo, eventRepo, eventDeliveryRepo,
		a.A.Queue, a.A.Cache, subRepo, sourceRepo, deviceRepo,
	)

	if err != nil {
		return nil, err
	}

	return eventService, nil
}

func (a *DashboardHandler) CreateEndpointEvent(w http.ResponseWriter, r *http.Request) {
	var newMessage models.CreateEvent
	err := util.ReadJSON(r, &newMessage)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	err = newMessage.Validate()
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	project, err := a.retrieveProject(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	eventService, err := createEventService(a)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	event, err := eventService.CreateEvent(r.Context(), &newMessage, project)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	resp := &models.EventResponse{Event: event}
	_ = render.Render(w, r, util.NewServerResponse("Endpoint event created successfully", resp, http.StatusCreated))
}

func (a *DashboardHandler) ReplayEndpointEvent(w http.ResponseWriter, r *http.Request) {
	project, err := a.retrieveProject(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	event, err := a.retrieveEvent(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	eventService, err := createEventService(a)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	err = eventService.ReplayEvent(r.Context(), event, project)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	resp := &models.EventResponse{Event: event}
	_ = render.Render(w, r, util.NewServerResponse("Endpoint event replayed successfully", resp, http.StatusOK))
}

func (a *DashboardHandler) BatchReplayEvents(w http.ResponseWriter, r *http.Request) {
	var q *models.QueryBatchReplayEvent
	p, err := a.retrieveProject(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	eventService, err := createEventService(a)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	data, err := q.Transform(r)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	successes, failures, err := eventService.BatchReplayEvents(r.Context(), p, data.Filter)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	_ = render.Render(w, r, util.NewServerResponse(fmt.Sprintf("%d successful, %d failed", successes, failures), nil, http.StatusOK))
}

func (a *DashboardHandler) CountAffectedEvents(w http.ResponseWriter, r *http.Request) {
	var q *models.QueryCountAffectedEvents
	p, err := a.retrieveProject(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	data, err := q.Transform(r)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	count, err := postgres.NewEventRepo(a.A.DB).CountEvents(r.Context(), p.UID, data.Filter)
	if err != nil {
		log.FromContext(r.Context()).WithError(err).Error("an error occurred while fetching event")
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	_ = render.Render(w, r, util.NewServerResponse("events count successful", map[string]interface{}{"num": count}, http.StatusOK))
}

func (a *DashboardHandler) GetEndpointEvent(w http.ResponseWriter, r *http.Request) {
	event, err := a.retrieveEvent(r)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusNotFound))
		return
	}

	resp := &models.EventResponse{Event: event}
	_ = render.Render(w, r, util.NewServerResponse("Endpoint event fetched successfully", resp, http.StatusOK))
}

func (a *DashboardHandler) GetEventDelivery(w http.ResponseWriter, r *http.Request) {
	eventDelivery, err := a.retrieveEventDelivery(r)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusNotFound))
		return
	}

	resp := &models.EventDeliveryResponse{EventDelivery: eventDelivery}
	_ = render.Render(w, r, util.NewServerResponse("Event Delivery fetched successfully", resp, http.StatusOK))
}

func (a *DashboardHandler) ResendEventDelivery(w http.ResponseWriter, r *http.Request) {
	project, err := a.retrieveProject(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	eventDelivery, err := a.retrieveEventDelivery(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	eventService, err := createEventService(a)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	err = eventService.ResendEventDelivery(r.Context(), eventDelivery, project)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	resp := &models.EventDeliveryResponse{EventDelivery: eventDelivery}
	_ = render.Render(w, r, util.NewServerResponse("App event processed for retry successfully",
		resp, http.StatusOK))
}

func (a *DashboardHandler) BatchRetryEventDelivery(w http.ResponseWriter, r *http.Request) {
	var q *models.QueryBatchRetryEventDelivery

	data, err := q.Transform(r)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	project, err := a.retrieveProject(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	eventService, err := createEventService(a)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	successes, failures, err := eventService.BatchRetryEventDelivery(r.Context(), project, data.Filter)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	_ = render.Render(w, r, util.NewServerResponse(fmt.Sprintf("%d successful, %d failed", successes, failures), nil, http.StatusOK))
}

func (a *DashboardHandler) CountAffectedEventDeliveries(w http.ResponseWriter, r *http.Request) {
	var q *models.QueryCountAffectedEventDeliveries

	data, err := q.Transform(r)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	project, err := a.retrieveProject(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	f := data.Filter
	count, err := postgres.NewEventDeliveryRepo(a.A.DB).CountEventDeliveries(r.Context(), project.UID, f.EndpointIDs, f.EventID, f.Status, f.SearchParams)
	if err != nil {
		log.FromContext(r.Context()).WithError(err).Error("an error occurred while fetching event deliveries")
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	_ = render.Render(w, r, util.NewServerResponse("event deliveries count successful", map[string]interface{}{"num": count}, http.StatusOK))
}

func (a *DashboardHandler) ForceResendEventDeliveries(w http.ResponseWriter, r *http.Request) {
	eventDeliveryIDs := models.IDs{}

	err := json.NewDecoder(r.Body).Decode(&eventDeliveryIDs)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse("Request is invalid", http.StatusBadRequest))
		return
	}

	project, err := a.retrieveProject(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	eventService, err := createEventService(a)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	successes, failures, err := eventService.ForceResendEventDeliveries(r.Context(), eventDeliveryIDs.IDs, project)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	_ = render.Render(w, r, util.NewServerResponse(fmt.Sprintf("%d successful, %d failed", successes, failures), nil, http.StatusOK))
}

func (a *DashboardHandler) GetEventsPaged(w http.ResponseWriter, r *http.Request) {
	var q *models.QueryListEvent
	cfg, err := config.Get()
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	data, err := q.Transform(r)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	project, err := a.retrieveProject(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	eventService, err := createEventService(a)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	if cfg.Search.Type == config.TypesenseSearchProvider && !util.IsStringEmpty(data.Filter.Query) {
		m, paginationData, err := eventService.Search(r.Context(), project, data.Filter)
		if err != nil {
			_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
			return
		}

		resp := models.NewListResponse(m, func(event datastore.Event) models.EventResponse {
			return models.EventResponse{Event: &event}
		})
		_ = render.Render(w, r, util.NewServerResponse("Endpoint events fetched successfully",
			pagedResponse{Content: resp, Pagination: &paginationData}, http.StatusOK))

		return
	}

	m, paginationData, err := postgres.NewEventRepo(a.A.DB).LoadEventsPaged(r.Context(), project.UID, data.Filter)
	if err != nil {
		log.FromContext(r.Context()).WithError(err).Error("failed to fetch events")
		_ = render.Render(w, r, util.NewErrorResponse("an error occurred while fetching app events", http.StatusInternalServerError))
		return
	}

	resp := models.NewListResponse(m, func(event datastore.Event) models.EventResponse {
		return models.EventResponse{Event: &event}
	})
	_ = render.Render(w, r, util.NewServerResponse("App events fetched successfully",
		pagedResponse{Content: resp, Pagination: &paginationData}, http.StatusOK))
}

func (a *DashboardHandler) GetEventDeliveriesPaged(w http.ResponseWriter, r *http.Request) {
	var q *models.QueryListEventDelivery

	project, err := a.retrieveProject(r)
	if err != nil {
		_ = render.Render(w, r, util.NewServiceErrResponse(err))
		return
	}

	data, err := q.Transform(r)
	if err != nil {
		_ = render.Render(w, r, util.NewErrorResponse(err.Error(), http.StatusBadRequest))
		return
	}

	f := data.Filter
	ed, paginationData, err := postgres.NewEventDeliveryRepo(a.A.DB).LoadEventDeliveriesPaged(r.Context(), project.UID, f.EndpointIDs, f.EventID, f.Status, f.SearchParams, f.Pageable)
	if err != nil {
		log.FromContext(r.Context()).WithError(err).Error("failed to fetch event deliveries")
		_ = render.Render(w, r, util.NewErrorResponse("an error occurred while fetching event deliveries", http.StatusInternalServerError))
		return
	}

	resp := models.NewListResponse(ed, func(ed datastore.EventDelivery) models.EventDeliveryResponse {
		return models.EventDeliveryResponse{EventDelivery: &ed}
	})
	_ = render.Render(w, r, util.NewServerResponse("Event deliveries fetched successfully",
		pagedResponse{Content: resp, Pagination: &paginationData}, http.StatusOK))
}

func (a *DashboardHandler) retrieveEvent(r *http.Request) (*datastore.Event, error) {
	project, err := a.retrieveProject(r)
	if err != nil {
		return &datastore.Event{}, err
	}

	eventID := chi.URLParam(r, "eventID")
	eventRepo := postgres.NewEventRepo(a.A.DB)
	return eventRepo.FindEventByID(r.Context(), project.UID, eventID)
}

func (a *DashboardHandler) retrieveEventDelivery(r *http.Request) (*datastore.EventDelivery, error) {
	project, err := a.retrieveProject(r)
	if err != nil {
		return &datastore.EventDelivery{}, err
	}

	eventDeliveryID := chi.URLParam(r, "eventDeliveryID")
	eventDeliveryRepo := postgres.NewEventDeliveryRepo(a.A.DB)
	return eventDeliveryRepo.FindEventDeliveryByID(r.Context(), project.UID, eventDeliveryID)
}

func getSearchParams(r *http.Request) (datastore.SearchParams, error) {
	var searchParams datastore.SearchParams
	format := "2006-01-02T15:04:05"
	startDate := r.URL.Query().Get("startDate")
	endDate := r.URL.Query().Get("endDate")

	var err error

	var startT time.Time
	if len(startDate) == 0 {
		startT = time.Unix(0, 0)
	} else {
		startT, err = time.Parse(format, startDate)
		if err != nil {
			return searchParams, errors.New("please specify a startDate in the format " + format)
		}
	}
	var endT time.Time
	if len(endDate) == 0 {
		now := time.Now()
		endT = time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, now.Location())
	} else {
		endT, err = time.Parse(format, endDate)
		if err != nil {
			return searchParams, errors.New("please specify a correct endDate in the format " + format + " or none at all")
		}
	}

	if err := m.EnsurePeriod(startT, endT); err != nil {
		return searchParams, err
	}

	searchParams = datastore.SearchParams{
		CreatedAtStart: startT.Unix(),
		CreatedAtEnd:   endT.Unix(),
	}

	return searchParams, nil
}

func getEndpointIDs(r *http.Request) []string {
	var endpoints []string

	for _, id := range r.URL.Query()["endpointId"] {
		if !util.IsStringEmpty(id) {
			endpoints = append(endpoints, id)
		}
	}

	return endpoints
}
