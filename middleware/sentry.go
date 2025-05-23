package middleware

import (
	"github.com/getsentry/sentry-go"
	"github.com/poteto-go/poteto"
)

const SentryHubKey = "sentry-hub"

//	func main() {
//	  sentry.Init(sentry.ClientOptions{
//	    Dsn: "<dsn>"
//	  })
//
//	  p := poteto.New()
//
//	  p.Register(middleware.Sentry(sentry.CurrentHub()))
//
//	  p.GET("/", func(ctx poteto.Context) error {
//	    hub := middleware.GetHubFromContext()
//	    /*....*/
//	    return nil
//	  })
//	}
func Sentry(hub *sentry.Hub) poteto.MiddlewareFunc {
	return func(next poteto.HandlerFunc) poteto.HandlerFunc {
		return func(ctx poteto.Context) error {
			SetHubOnContext(ctx, hub)

			return next(ctx)
		}
	}
}

func GetHubFromContext(ctx poteto.Context) *sentry.Hub {
	if hub, ok := ctx.Get(SentryHubKey); ok {
		return hub.(*sentry.Hub)
	}

	return nil
}

func SetHubOnContext(ctx poteto.Context, hub *sentry.Hub) {
	ctx.Set(SentryHubKey, hub)
}
