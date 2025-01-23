package server

import (
	"embed"
	"net/http"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/psnehanshu/cleanpincode.in/internal/queries"
	"go.uber.org/zap"
)

type Server struct {
	Logger  *zap.SugaredLogger
	DB      *pgx.Conn
	Queries *queries.Queries
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
		// Fetch pincodes
		pincodes, err := s.Queries.GetPincodes(c.Context(), queries.GetPincodesParams{
			Limit: 10, Offset: 0,
		})
		if err != nil {
			s.Logger.Errorw("failed to get pincodes", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get pincodes")
		}

		return c.Render("views/index", fiber.Map{"Pincodes": pincodes})
	})

	app.Get("/pincode/:pincode", func(c *fiber.Ctx) error {
		var pincode pgtype.Int4
		if pint, err := strconv.ParseInt(c.Params("pincode"), 10, 32); err != nil {
			return c.SendStatus(http.StatusBadRequest)
		} else {
			pincode.Int32 = int32(pint)
			pincode.Valid = true
		}

		pincodeResult, err := s.Queries.GetByPincode(c.Context(), pincode)
		if err != nil {
			s.Logger.Errorw("failed to get pincode", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get pincode")
		}

		if len(pincodeResult) == 0 {
			return c.Status(http.StatusNotFound).SendString("pincode not found")
		}

		return c.Render("views/pincode", fiber.Map{
			"PostOffices": pincodeResult,
			"Pincode":     pincode,
		})
	})
}
