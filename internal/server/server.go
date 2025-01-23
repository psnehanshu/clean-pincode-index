package server

import (
	"embed"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

type Server struct {
	Logger *zap.SugaredLogger
	DB     *pgx.Conn
}

//go:embed views
var viewsfs embed.FS

// Start the web server
func (s *Server) Start(addr string) error {
	engine := html.NewFileSystem(http.FS(viewsfs), ".html")
	app := fiber.New(fiber.Config{
		Views:             engine,
		ViewsLayout:       "views/layouts/root",
		PassLocalsToViews: true,
	})

	// Mount routes
	s.mountRoutes(app)

	// Start!
	return app.Listen(addr)
}

// Mount routes
func (s *Server) mountRoutes(app *fiber.App) {
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("views/index", fiber.Map{})
	})
}
