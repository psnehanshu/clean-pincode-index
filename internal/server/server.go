package server

import (
	"context"
	"embed"
	"net/http"
	"text/template"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	pgStorage "github.com/gofiber/storage/postgres/v3"
	"github.com/gofiber/template/html/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/psnehanshu/cleanpincode.in/internal/queries"
	"go.uber.org/zap"
)

type Server struct {
	logger       *zap.SugaredLogger
	db           *pgxpool.Pool
	queries      *queries.Queries
	sessionStore *session.Store
	close        func() error
}

func New(dbConnStr string) (*Server, error) {
	// Initialize logger
	z, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	logger := z.Sugar()

	// Initialize database
	dbPool, err := pgxpool.New(context.Background(), dbConnStr)
	if err != nil {
		return nil, err
	}

	// Initialize queries
	q := queries.New(dbPool)

	// Function supposed to be deferred
	close := func() error {
		dbPool.Close()
		return z.Sync()
	}

	// Initialize session store with Postgres
	sessionStore := session.New(session.Config{
		Storage: pgStorage.New(pgStorage.Config{DB: dbPool, Table: "__session_store"}),
	})

	// Return instance
	return &Server{logger, dbPool, q, sessionStore, close}, nil
}

//go:embed views
var viewsfs embed.FS

// Start the web server
func (s *Server) Start(addr string) error {
	engine := html.NewFileSystem(http.FS(viewsfs), ".html")

	engine.AddFuncMap(template.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
		"rank_top_3": func(rank int) bool {
			return rank >= 0 && rank <= 2
		},
	})

	app := fiber.New(fiber.Config{
		Views:             engine,
		ViewsLayout:       "views/layouts/root",
		PassLocalsToViews: true,
		ErrorHandler:      s.handleErrors,
	})

	app.Use(func(c *fiber.Ctx) error {
		if err := s.populateRequestUser(c); err != nil {
			return err
		}

		return c.Next()
	})

	// Mount routes
	s.mountRoutes(app)

	// Start!
	return app.Listen(addr)
}

func (s *Server) Close() error {
	if s.close == nil {
		panic("server.clear shouldn't be nil")
	}
	return s.close()
}
