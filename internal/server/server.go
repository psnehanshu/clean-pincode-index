package server

import (
	"embed"
	"net/http"
	"strconv"
	"strings"

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

	app.Get("/pincodes", func(c *fiber.Ctx) error {
		page, limit := c.QueryInt("page", 1), c.QueryInt("limit", 20)
		if page < 1 {
			page = 1
		}
		if limit < 1 {
			limit = 1
		}
		offset := (page - 1) * limit

		pincodes, err := s.Queries.GetPincodes(c.Context(), queries.GetPincodesParams{
			Limit: int32(limit), Offset: int32(offset),
		})
		if err != nil {
			s.Logger.Errorw("failed to get pincodes", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get pincodes")
		}

		return c.Render("views/pincodes", fiber.Map{
			"Pincodes": pincodes, "Limit": limit, "Page": page, "NextPage": page + 1, "PrevPage": page - 1,
		})
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

		// Find all unique states, in 99.99% cases, there will be only one state
		statesMap := make(map[string]bool)
		states := make([]string, 0, len(pincodeResult))
		for _, p := range pincodeResult {
			if statesMap[p.Statename.String] {
				continue
			}
			statesMap[p.Statename.String] = true
			states = append(states, p.Statename.String)
		}

		return c.Render("views/pincode", fiber.Map{
			"PostOffices": pincodeResult,
			"Pincode":     pincode,
			"State":       strings.Join(states, ", "),
		})
	})
}
