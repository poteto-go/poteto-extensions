package middleware

import (
	"testing"

	"github.com/getsentry/sentry-go"
	"github.com/poteto-go/poteto"
	"github.com/stretchr/testify/assert"
)

func TestSentry(t *testing.T) {
	// Arrange
	hub := &sentry.Hub{}
	middlewareFunc := Sentry(hub)
	next := func(ctx poteto.Context) error {
		retrievedHub := GetHubFromContext(ctx)
		assert.Equal(t, hub, retrievedHub)
		return nil
	}
	ctx := poteto.NewContext(nil, nil)

	// Act
	handler := middlewareFunc(next)
	err := handler(ctx)

	// Assert
	assert.Nil(t, err)

}

func TestGetHubFromContext(t *testing.T) {
	t.Run("can get hub from context", func(t *testing.T) {
		// Arrange
		ctx := poteto.NewContext(nil, nil)
		hub := &sentry.Hub{}
		ctx.Set(SentryHubKey, hub)

		// Act
		retrievedHub := GetHubFromContext(ctx)

		// Assert
		assert.Equal(t, hub, retrievedHub)
	})

	t.Run("cannot get hub (nil)", func(t *testing.T) {
		// Arrange
		ctx := poteto.NewContext(nil, nil)

		// Act
		retrievedHub := GetHubFromContext(ctx)

		// Assert
		assert.Nil(t, retrievedHub)
	})
}

func TestSetHubOnContext(t *testing.T) {
	// Arrange
	ctx := poteto.NewContext(nil, nil)
	hub := &sentry.Hub{}

	// Act
	SetHubOnContext(ctx, hub)
	retrievedHub := GetHubFromContext(ctx)

	// Assert
	assert.Equal(t, hub, retrievedHub)
}
