package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"geektrust/client"
	"geektrust/internal/config"
	"geektrust/internal/idsauth"
	"geektrust/internal/session"
)

// Command wiring owns paths and terminal interaction; the library sees neither.
func commandClient(cfg *config.Config, logger *slog.Logger) (*client.Client, error) {
	return client.New(client.Options{
		ControllerURL: cfg.BaseURL, DeviceID: cfg.DeviceID, Platform: cfg.Platform,
		LoginDomain: cfg.LoginDomain, ClientMode: cfg.ClientType == "client",
		Logger: logger, PromptSMS: smsPrompt,
		SessionStore: commandSessionStore{session.NewStore(cfg.StateFile)},
		Authenticator: client.AuthenticatorFunc(func(ctx context.Context, h *http.Client) (string, error) {
			k, err := idsauth.LoadKeystore(cfg.Keystore)
			if err != nil {
				return "", errors.New("cannot load credential")
			}
			if err = idsauth.NewClient(k, h).Login(ctx); err != nil {
				return "", err
			}
			return k.Username(), nil
		}),
	})
}

type commandSessionStore struct{ store *session.Store }

func (s commandSessionStore) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state, err := s.store.Load(ctx)
	if err != nil || state == nil {
		return nil, err
	}
	return json.Marshal(state)
}
func (s commandSessionStore) Save(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var state session.State
	if err := json.Unmarshal(data, &state); err != nil {
		return errors.New("invalid session state")
	}
	return s.store.Save(ctx, &state)
}
