package server

import (
	"context"
	"embed"
	"net/http"
	"net/url"
	"os"
	"text/template"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	pgStorage "github.com/gofiber/storage/postgres/v3"
	"github.com/gofiber/template/html/v2"
	"github.com/hako/durafmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/psnehanshu/cleanpincode.in/internal/queries"
	"go.uber.org/zap"
)

type Server struct {
	logger       *zap.SugaredLogger
	db           *pgxpool.Pool
	queries      *queries.Queries
	sessionStore *session.Store
	s3           *minio.Client
	bucketName   string
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

	// Initialize minio client object.
	minioClient, err := minio.New(os.Getenv("S3_ENDPOINT"), &minio.Options{
		Creds:  credentials.NewStaticV4(os.Getenv("S3_ACCESS_KEY_ID"), os.Getenv("S3_SECRET_ACCESS_KEY"), ""),
		Secure: false,
	})
	if err != nil {
		return nil, err
	}

	// Return instance
	return &Server{logger, dbPool, q, sessionStore, minioClient, os.Getenv("S3_BUCKET_NAME"), close}, nil
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
		"urlencode": func(v string) string {
			return url.QueryEscape(v)
		},
		"time_passed": func(t time.Time, limit int) string {
			duration := time.Since(t)
			return durafmt.Parse(duration).LimitFirstN(limit).String()
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
